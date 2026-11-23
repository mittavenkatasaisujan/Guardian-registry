"""Alerts: a transactional outbox plus a dispatcher.

Every event that someone must hear about (a payment waiting for approval, a held
rule change, the kill switch) writes notification rows IN THE SAME TRANSACTION as
the event, so an alert is never lost or sent for something that rolled back.

The dispatcher then delivers pending rows:
  * inapp   - nothing to send; the row is the in-app feed entry (status 'sent' at once)
  * sms     - urgent alerts to a person, through an SmsSender
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

from .clock import Clock, iso
from .db import Database
from .security import decrypt_mobile, mask_mobile, new_id, sign_webhook

log = logging.getLogger("guardian_registry.notify")

MAX_ATTEMPTS = 6
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
}


# ----------------------------------------------------------------- senders
class SmsSender:
    def send(self, to: str, text: str) -> None:  # pragma: no cover - interface
        raise NotImplementedError


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


def sms_sender_from_env() -> SmsSender:
    url = os.environ.get("GR_SMS_URL")
    if url:
        return HttpSmsSender(url, os.environ.get("GR_SMS_TOKEN", ""))
    return LogSmsSender()


# ------------------------------------------------------------------ outbox
def enqueue_user(c: sqlite3.Connection, now: str, user_id: str, kind: str, title: str, body: str,
                 principal_id: str | None = None, payload: dict | None = None) -> None:
    """Queue an in-app entry, plus an SMS for urgent kinds."""
    data = json.dumps(payload or {}, ensure_ascii=False)
    c.execute(
        "INSERT INTO notifications (id, recipient_type, recipient_id, principal_id, kind, channel, title, body, "
        "payload, status, next_attempt_at, created_at, sent_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (new_id("ntf"), "user", user_id, principal_id, kind, "inapp", title, body, data, "sent", now, now, now))
    if kind in URGENT_KINDS:
        c.execute(
            "INSERT INTO notifications (id, recipient_type, recipient_id, principal_id, kind, channel, title, body, "
            "payload, status, next_attempt_at, created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (new_id("ntf"), "user", user_id, principal_id, kind, "sms", title, body, data, "pending", now, now))


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
                 http: httpx.Client | None = None):
        self.db, self.clock = db, clock
        self.sms = sms or sms_sender_from_env()
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
        for n in due:
            try:
                delivered = self._deliver(n)
            except Exception as e:  # noqa: BLE001 - any delivery error is retried
                self._retry(n, str(e)[:500], stats)
                continue
            with self.db.tx() as c:
                c.execute("UPDATE notifications SET status=?, attempts=attempts+1, sent_at=?, last_error=NULL WHERE id=?",
                          ("sent" if delivered else "skipped", iso(self.clock.now()), n["id"]))
            if delivered:
                stats.sent += 1
            else:
                stats.skipped += 1
        return stats

    def _deliver(self, n: sqlite3.Row) -> bool:
        if n["channel"] == "sms":
            u = self.db.one("SELECT mobile_enc FROM users WHERE id=?", (n["recipient_id"],))
            if not u or not u["mobile_enc"]:
                return False  # no number on file (enrolled before v2): in-app only
            swapped = self.db.one("SELECT 1 FROM sim_events WHERE user_id=? AND cleared_at IS NULL "
                                  "AND window_ends_at>?", (n["recipient_id"], iso(self.clock.now())))
            if swapped:
                return False  # the number may be in an attacker's hands: in-app only until cleared
            self.sms.send(decrypt_mobile(u["mobile_enc"]), f"{n['title']}: {n['body']}")
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
        with self.db.tx() as c:
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
