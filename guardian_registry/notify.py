"""Alerts: a transactional outbox plus a dispatcher.

Every event that someone must hear about (a payment waiting for approval, a held
rule change, the kill switch) writes notification rows IN THE SAME TRANSACTION as
the event, so an alert is never lost or sent for something that rolled back.

The dispatcher then delivers pending rows:
  * inapp   - nothing to send; the row is the in-app feed entry (status 'sent' at once)
  * sms     - urgent alerts to a person, through an SmsSender
  * whatsapp - urgent alerts instead of SMS, for people who chose WhatsApp (falls back to
              SMS if no WhatsApp provider is configured)
  * push    - urgent alerts to every app install the person registered. Push goes to the
              app, not the phone number, so unlike SMS and WhatsApp it keeps flowing during
              a SIM-swap window
  * webhook - signed POST to a bank/app's registered URL when a check changes state,
              so banks don't have to poll

Failures retry with exponential backoff, up to MAX_ATTEMPTS, then become 'failed'.
"""

from __future__ import annotations

import json
import logging
import os
import sqlite3
from dataclasses import dataclass, field
from datetime import timedelta

import httpx

from . import messages
from .clock import Clock, iso
from .db import Database
from .security import decrypt_mobile, decrypt_text, mask_mobile, new_id, sign_webhook

log = logging.getLogger("guardian_registry.notify")

MAX_ATTEMPTS = 6
LEASE_SECONDS = 60
BACKOFF_SECONDS = [30, 120, 600, 1800, 3600]

# Alert kinds that go out by SMS as well as in-app. Everything else is in-app only.
URGENT_KINDS = {
    "approval_needed",      # a guardian must approve a payment
    "payment_held",         # a cooling-off payment a guardian may want to cancel
    "change_proposed",      # protection is being loosened
    "kill_switch_on",
    "kill_switch_off",
    "guardian_invited",
    "guardian_removal_proposed",
    "recovery_requested",   # someone is recovering a contact's account
    "recovery_held",
    "sim_changed",          # a guardian's ward (or the guardian) had a SIM change / lost phone
    "data_breach_notice",   # DPDP Act: affected people are told without delay
}


# ----------------------------------------------------------------- senders
class SmsSender:
    def send(self, to: str, text: str) -> None:  # pragma: no cover - interface
        raise NotImplementedError

    def send_otp(self, to: str, code: str, minutes: int, language: str = "en") -> None:
        """Template-based providers (DLT in India) override this to send a template id."""
        self.send(to, messages.alert(f"Guardian Registry code: {code}. Valid {minutes} min. Never share it with "
                                     "anyone, not even a guardian or a bank.", language))

    def send_alert_in(self, to: str, title: str, body: str, language: str) -> None:
        self.send_alert(to, title, body)

    def send_alert(self, to: str, title: str, body: str) -> None:
        self.send(to, f"{title}: {body}")


@dataclass
class LogSmsSender(SmsSender):
    """Development sender: logs a masked number and keeps messages in memory for tests."""
    sent: list[tuple[str, str]] = field(default_factory=list)

    def send(self, to: str, text: str) -> None:
        self.sent.append((to, text))
        log.info("SMS to %s: %s", mask_mobile(to), text)


class HttpSmsSender(SmsSender):
    """Provider-neutral SMS gateway: POST {"to", "text"} to GR_SMS_URL with a bearer token.
    Point it at a thin adapter for MSG91, Gupshup, Twilio, etc."""

    def __init__(self, url: str, token: str, client: httpx.Client | None = None):
        self.url, self.token = url, token
        self.client = client or httpx.Client(timeout=10)

    def send(self, to: str, text: str) -> None:
        r = self.client.post(self.url, json={"to": to, "text": text},
                             headers={"Authorization": f"Bearer {self.token}"})
        r.raise_for_status()


class WhatsAppSender:
    def send(self, to: str, title: str, body: str) -> None:  # pragma: no cover - interface
        raise NotImplementedError

    def send_in(self, to: str, title: str, body: str, language: str) -> None:
        self.send(to, title, body)


@dataclass
class LogWhatsAppSender(WhatsAppSender):
    sent: list[tuple[str, str, str]] = field(default_factory=list)

    def send(self, to: str, title: str, body: str) -> None:
        self.sent.append((to, title, body))
        log.info("WhatsApp to %s: %s", mask_mobile(to), title)


class HttpWhatsAppSender(WhatsAppSender):
    """POST {"to", "template", "params": [title, body]} to GR_WHATSAPP_URL. WhatsApp only
    allows pre-approved templates for messages a business starts, so put an adapter in front
    of the Cloud API (or Gupshup, Twilio...) that maps 'guardian_alert' to your template."""

    def __init__(self, url: str, token: str, client: httpx.Client | None = None):
        self.url, self.token = url, token
        self.client = client or httpx.Client(timeout=10)

    def send(self, to: str, title: str, body: str) -> None:
        r = self.client.post(self.url, json={"to": to, "template": "guardian_alert", "params": [title, body]},
                             headers={"Authorization": f"Bearer {self.token}"})
        r.raise_for_status()


class PushSender:
    def send(self, token: str, platform: str, title: str, body: str, data: dict) -> None:  # pragma: no cover
        raise NotImplementedError


@dataclass
class LogPushSender(PushSender):
    sent: list[tuple[str, str, str]] = field(default_factory=list)

    def send(self, token: str, platform: str, title: str, body: str, data: dict) -> None:
        self.sent.append((token, platform, title))
        log.info("push to %s device: %s", platform, title)


class HttpPushSender(PushSender):
    """POST {"token", "platform", "title", "body", "data"} to GR_PUSH_URL: an adapter for
    Firebase Cloud Messaging / APNs."""

    def __init__(self, url: str, token: str, client: httpx.Client | None = None):
        self.url, self.token = url, token
        self.client = client or httpx.Client(timeout=10)

    def send(self, token: str, platform: str, title: str, body: str, data: dict) -> None:
        r = self.client.post(self.url, json={"token": token, "platform": platform, "title": title,
                                             "body": body, "data": data},
                             headers={"Authorization": f"Bearer {self.token}"})
        r.raise_for_status()


def whatsapp_sender_from_env() -> WhatsAppSender | None:
    from .providers import whatsapp_from_env
    direct = whatsapp_from_env()
    if direct:
        return direct
    url = os.environ.get("GR_WHATSAPP_URL")
    return HttpWhatsAppSender(url, os.environ.get("GR_WHATSAPP_TOKEN", "")) if url else None


def push_sender_from_env() -> PushSender | None:
    from .providers import push_from_env
    direct = push_from_env()
    if direct:
        return direct
    url = os.environ.get("GR_PUSH_URL")
    return HttpPushSender(url, os.environ.get("GR_PUSH_TOKEN", "")) if url else None


def sms_sender_from_env() -> SmsSender:
    from .providers import sms_from_env
    direct = sms_from_env()
    if direct:
        return direct
    url = os.environ.get("GR_SMS_URL")
    if url:
        return HttpSmsSender(url, os.environ.get("GR_SMS_TOKEN", ""))
    return LogSmsSender()


# ------------------------------------------------------------------ outbox
def enqueue_user(c: sqlite3.Connection, now: str, user_id: str, kind: str, title: str, body: str,
                 principal_id: str | None = None, payload: dict | None = None) -> None:
    """Queue an in-app entry; for urgent kinds also SMS or WhatsApp (the person's choice) and push.
    The text is written in the recipient's language (messages.py)."""
    data = json.dumps(payload or {}, ensure_ascii=False)
    lang = user_language(c, user_id)
    if lang != "en":
        title, body = messages.alert(title, lang), messages.alert(body, lang)
    c.execute(
        "INSERT INTO notifications (id, recipient_type, recipient_id, principal_id, kind, channel, title, body, "
        "payload, status, next_attempt_at, created_at, sent_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (new_id("ntf"), "user", user_id, principal_id, kind, "inapp", title, body, data, "sent", now, now, now))
    if kind in URGENT_KINDS:
        c.execute(
            "INSERT INTO notifications (id, recipient_type, recipient_id, principal_id, kind, channel, title, body, "
            "payload, status, next_attempt_at, created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (new_id("ntf"), "user", user_id, principal_id, kind, _urgent_channel(c, user_id), title, body, data,
             "pending", now, now))
        if c.execute("SELECT 1 FROM push_tokens WHERE user_id=? LIMIT 1", (user_id,)).fetchone():
            c.execute(
                "INSERT INTO notifications (id, recipient_type, recipient_id, principal_id, kind, channel, title, "
                "body, payload, status, next_attempt_at, created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                (new_id("ntf"), "user", user_id, principal_id, kind, "push", title, body, data, "pending", now, now))


def user_language(c, user_id: str) -> str:
    r = c.execute("SELECT language FROM users WHERE id=?", (user_id,)).fetchone()
    return (r["language"] if r and r["language"] in messages.enabled_languages() else "en")


def _urgent_channel(c: sqlite3.Connection, user_id: str) -> str:
    r = c.execute("SELECT urgent_channel FROM users WHERE id=?", (user_id,)).fetchone()
    return r["urgent_channel"] if r and r["urgent_channel"] in ("sms", "whatsapp") else "sms"


def enqueue_participant(c: sqlite3.Connection, now: str, participant_id: str, kind: str,
                        payload: dict, principal_id: str | None = None) -> None:
    has_hook = c.execute("SELECT webhook_url FROM participants WHERE id=?", (participant_id,)).fetchone()
    if not has_hook or not has_hook["webhook_url"]:
        return  # bank polls instead
    c.execute(
        "INSERT INTO notifications (id, recipient_type, recipient_id, principal_id, kind, channel, title, body, "
        "payload, status, next_attempt_at, created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
        (new_id("ntf"), "participant", participant_id, principal_id, kind, "webhook", kind, "",
         json.dumps(payload, ensure_ascii=False), "pending", now, now))


# --------------------------------------------------------------- dispatcher
@dataclass
class DispatchStats:
    sent: int = 0
    retried: int = 0
    failed: int = 0
    skipped: int = 0


class Dispatcher:
    def __init__(self, db: Database, clock: Clock, sms: SmsSender | None = None,
                 http: httpx.Client | None = None, whatsapp: WhatsAppSender | None = None,
                 push: PushSender | None = None):
        self.db, self.clock = db, clock
        self.sms = sms or sms_sender_from_env()
        self.whatsapp = whatsapp if whatsapp is not None else whatsapp_sender_from_env()
        self.push = push if push is not None else push_sender_from_env()
        self._http = http

    @property
    def http(self) -> httpx.Client:
        if self._http is None:  # created lazily: building a TLS context is slow
            self._http = httpx.Client(timeout=10)
        return self._http

    def run_once(self, limit: int = 100) -> DispatchStats:
        stats = DispatchStats()
        now = iso(self.clock.now())
        due = self.db.all(
            "SELECT * FROM notifications WHERE status='pending' AND next_attempt_at<=? "
            "ORDER BY created_at LIMIT ?", (now, limit))
        lease = iso(self.clock.now() + timedelta(seconds=LEASE_SECONDS))
        for n in due:
            # claim the row first, so two nodes' dispatchers never send the same alert twice;
            # if this node dies mid-send the lease runs out and another node retries it
            with self.db.tx(shared=True) as c:  # row-level claim: no person's state involved
                claimed = c.execute("UPDATE notifications SET next_attempt_at=? WHERE id=? AND status='pending' "
                                    "AND next_attempt_at=?", (lease, n["id"], n["next_attempt_at"])).rowcount
            if not claimed:
                continue
            try:
                delivered = self._deliver(n)
            except Exception as e:  # noqa: BLE001 - any delivery error is retried
                self._retry(n, str(e)[:500], stats)
                continue
            with self.db.tx(shared=True) as c:
                c.execute("UPDATE notifications SET status=?, attempts=attempts+1, sent_at=?, last_error=NULL WHERE id=?",
                          ("sent" if delivered else "skipped", iso(self.clock.now()), n["id"]))
            if delivered:
                stats.sent += 1
            else:
                stats.skipped += 1
        return stats

    def _deliver(self, n: sqlite3.Row) -> bool:
        if n["channel"] == "push":
            if self.push is None:
                return False
            from .providers import DeadToken
            tokens = self.db.all("SELECT token_hash, token_enc, platform FROM push_tokens WHERE user_id=?",
                                 (n["recipient_id"],))
            delivered, errors = 0, []
            for t in tokens:  # one install failing must not re-send to the others on retry
                try:
                    self.push.send(decrypt_text(t["token_enc"]), t["platform"], n["title"], n["body"],
                                   {"kind": n["kind"], "id": n["id"]})
                    delivered += 1
                except DeadToken:
                    with self.db.tx(n["recipient_id"]) as c:  # uninstalled: never try it again
                        c.execute("DELETE FROM push_tokens WHERE user_id=? AND token_hash=?",
                                  (n["recipient_id"], t["token_hash"]))
                except Exception as e:  # noqa: BLE001
                    errors.append(str(e))
            if errors and not delivered:
                raise RuntimeError("; ".join(errors)[:500])
            return bool(delivered)
        if n["channel"] in ("sms", "whatsapp"):
            u = self.db.one("SELECT mobile_enc, language FROM users WHERE id=?", (n["recipient_id"],))
            lang = u["language"] if u and u["language"] in messages.enabled_languages() else "en"
            if not u or not u["mobile_enc"]:
                return False  # no number on file (enrolled before v2): in-app only
            swapped = self.db.one("SELECT 1 FROM sim_events WHERE user_id=? AND cleared_at IS NULL "
                                  "AND window_ends_at>?", (n["recipient_id"], iso(self.clock.now())))
            if swapped:
                return False  # the number may be in an attacker's hands: in-app only until cleared
            to = decrypt_mobile(u["mobile_enc"])
            if n["channel"] == "whatsapp" and self.whatsapp is not None:
                send_in = getattr(self.whatsapp, "send_in", None)
                if send_in:
                    send_in(to, n["title"], n["body"], lang)
                else:
                    self.whatsapp.send(to, n["title"], n["body"])
            else:  # SMS, or WhatsApp chosen but no provider configured
                send_alert_in = getattr(self.sms, "send_alert_in", None)
                send_alert = getattr(self.sms, "send_alert", None)
                if send_alert_in:
                    send_alert_in(to, n["title"], n["body"], lang)
                elif send_alert:
                    send_alert(to, n["title"], n["body"])
                else:
                    self.sms.send(to, f"{n['title']}: {n['body']}")
            return True
        if n["channel"] == "webhook":
            p = self.db.one("SELECT webhook_url, webhook_secret FROM participants WHERE id=?", (n["recipient_id"],))
            if not p or not p["webhook_url"]:
                return False
            body = json.dumps({"id": n["id"], "event": n["kind"], "created_at": n["created_at"],
                               "data": json.loads(n["payload"])}, ensure_ascii=False).encode()
            r = self.http.post(p["webhook_url"], content=body, headers={
                "Content-Type": "application/json",
                "X-GR-Event": n["kind"],
                "X-GR-Delivery": n["id"],
                "X-GR-Signature": sign_webhook(p["webhook_secret"], body),
            })
            if r.status_code >= 300:
                raise RuntimeError(f"webhook returned HTTP {r.status_code}")
            return True
        return False

    def _retry(self, n: sqlite3.Row, error: str, stats: DispatchStats) -> None:
        attempts = n["attempts"] + 1
        with self.db.tx(shared=True) as c:
            if attempts >= MAX_ATTEMPTS:
                c.execute("UPDATE notifications SET status='failed', attempts=?, last_error=? WHERE id=?",
                          (attempts, error, n["id"]))
                stats.failed += 1
                log.warning("notification %s failed permanently: %s", n["id"], error)
            else:
                wait = BACKOFF_SECONDS[min(attempts - 1, len(BACKOFF_SECONDS) - 1)]
                c.execute("UPDATE notifications SET attempts=?, last_error=?, next_attempt_at=? WHERE id=?",
                          (attempts, error, iso(self.clock.now() + timedelta(seconds=wait)), n["id"]))
                stats.retried += 1
