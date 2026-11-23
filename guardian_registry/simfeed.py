"""Mobile-operator SIM feed: hear about SIM swaps from the source, not second-hand.

Until v0.6 the registry learned about a SIM change only if a bank reported it. Mobile
operators know first, so they now feed the registry directly, two ways:

  1. Push. An operator joins as a participant of kind `telecom` and sends batches of
     events to POST /v1/signals/operator-events:
       * sim_swap      the number moved to a new SIM            (capability sim_signals)
       * port_out      the number moved to another operator     (capability sim_signals)
       * disconnected  the number was disconnected; it will     (capability number_lifecycle)
                       later be given to someone else
     Each event is processed once (idempotent on the operator's event_id). Nothing is kept
     about numbers that aren't enrolled, beyond the event id and outcome.

  2. Live lookup. Before trusting a sign-in or a high-trust action (approve a payment,
     accept a guardian role, loosen rules...), the registry asks the operator's SIM-swap
     API when the SIM last changed (shape of the CAMARA / GSMA Open Gateway "SIM Swap"
     retrieve-date call). Answers are cached for LOOKUP_CACHE_MINUTES, failures for
     LOOKUP_FAILURE_CACHE_MINUTES. A recent change opens the usual 72 h risk window, so
     the session asking becomes restricted at once (see simswap.py).
     If the lookup is down the default is to carry on (fail open), since bank reports and
     the push feed still apply. GR_SIM_LOOKUP_FAIL=closed blocks high-trust actions instead.

Disconnected numbers (the problem behind DoT's Mobile Number Revocation List). Indian
operators recycle numbers. Without this, whoever gets Ravi's old number could sign in by
SMS code AS RAVI and approve payments for his mother. So a disconnection detaches the
number from the account at once:
  * the next person to sign in with that number gets a brand-new, empty account;
  * the original owner keeps any phone already signed in, and can add a new number from
    it (the usual held number change, guardians can veto);
  * bank KYC claims end (they vouched for the old number) and SMS stop;
  * guardians, and the people this person guards, are told.
A disconnection dated before the person linked the number (an old event for a number that
was already recycled to them) is ignored.
"""

from __future__ import annotations

import logging
import os
import sqlite3
from datetime import datetime, timedelta

import httpx

from .clock import iso
from .errors import Forbidden, Invalid
from .security import decrypt_mobile, mask_mobile, normalize_mobile

log = logging.getLogger("guardian_registry.simfeed")

OPERATOR_EVENT_TYPES = {"sim_swap": "sim_signals", "port_out": "sim_signals", "disconnected": "number_lifecycle"}
MAX_EVENTS_PER_BATCH = 500
LOOKUP_CACHE_MINUTES = 10
LOOKUP_FAILURE_CACHE_MINUTES = 1
SAME_CHANGE_TOLERANCE = timedelta(minutes=10)  # two reports this close describe one SIM change


class SimLookupError(Exception):
    pass


class SimLookup:
    """Ask an operator when a number's SIM last changed."""

    def latest_sim_change(self, mobile: str) -> datetime | None:  # pragma: no cover - interface
        raise NotImplementedError


class HttpSimLookup(SimLookup):
    """POST {"phoneNumber": "+91..."} -> {"latestSimChange": "<ISO 8601>" | null}.

    This is the CAMARA SIM Swap retrieve-date shape. Put an adapter in front of a single
    operator or an aggregator that routes to the right one."""

    def __init__(self, url: str, token: str | None = None, timeout: float = 3.0, client: httpx.Client | None = None):
        self.url, self.token, self.timeout = url, token, timeout
        self._client = client

    @property
    def client(self) -> httpx.Client:
        if self._client is None:
            self._client = httpx.Client(timeout=self.timeout)
        return self._client

    def latest_sim_change(self, mobile: str) -> datetime | None:
        headers = {"Authorization": f"Bearer {self.token}"} if self.token else {}
        try:
            r = self.client.post(self.url, json={"phoneNumber": normalize_mobile(mobile)}, headers=headers)
        except httpx.HTTPError as e:
            raise SimLookupError(f"lookup failed: {type(e).__name__}") from None
        if r.status_code == 404:
            return None  # operator doesn't know the number
        if r.status_code != 200:
            raise SimLookupError(f"lookup returned HTTP {r.status_code}")
        try:
            value = r.json().get("latestSimChange")
            if value is None:
                return None
            when = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except (ValueError, AttributeError) as e:
            raise SimLookupError(f"bad lookup response: {e}") from None
        if when.tzinfo is None:
            raise SimLookupError("bad lookup response: latestSimChange has no timezone")
        return when


def sim_lookup_from_env() -> SimLookup | None:
    url = os.environ.get("GR_SIM_LOOKUP_URL")
    return HttpSimLookup(url, os.environ.get("GR_SIM_LOOKUP_TOKEN")) if url else None


def lookup_fails_closed() -> bool:
    return os.environ.get("GR_SIM_LOOKUP_FAIL", "open").lower() == "closed"


def _parse_when(value, now: datetime) -> datetime:
    if not isinstance(value, str):
        raise Invalid("occurred_at is required")
    try:
        when = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise Invalid("occurred_at must be an ISO 8601 timestamp") from None
    if when.tzinfo is None:
        raise Invalid("occurred_at must include a timezone")
    if when > now + timedelta(minutes=5):
        raise Invalid("occurred_at cannot be in the future")
    return when


class SimFeedMixin:
    """Mixed into Registry. Needs self.sim_lookup (SimLookup or None)."""

    sim_lookup: SimLookup | None = None

    # ------------------------------------------------------------- shared
    def _known_sim_change(self, uid: str, when: datetime) -> bool:
        """Is this SIM change already on record (open OR already confirmed)? Stops a confirmed
        change from being re-opened by the next lookup, and duplicates across sources."""
        return bool(self.db.one(
            "SELECT 1 FROM sim_events WHERE user_id=? AND source NOT IN ('self','guardian') "
            "AND changed_at BETWEEN ? AND ?",
            (uid, iso(when - SAME_CHANGE_TOLERANCE), iso(when + SAME_CHANGE_TOLERANCE))))

    def _mobile_since(self, uid: str) -> str:
        u = self._user(uid)
        return u["mobile_since"] or u["created_at"]

    # ------------------------------------------------------------- push feed
    def ingest_operator_events(self, participant_id: str, events: list[dict]) -> dict:
        self._require_participant(participant_id)
        if not isinstance(events, list) or not events:
            raise Invalid("events must be a non-empty list")
        if len(events) > MAX_EVENTS_PER_BATCH:
            raise Invalid(f"at most {MAX_EVENTS_PER_BATCH} events per batch")
        caps = self._caps(self._participant_row(participant_id))
        results, counts = [], {}
        for ev in events:
            res = self._ingest_one(participant_id, caps, ev if isinstance(ev, dict) else {})
            results.append(res)
            counts[res["result"]] = counts.get(res["result"], 0) + 1
        return {"received": len(events), "counts": counts, "results": results}

    def _ingest_one(self, pid: str, caps: set[str], ev: dict) -> dict:
        event_id = str(ev.get("event_id") or "").strip()
        out = {"event_id": event_id}
        if not event_id or len(event_id) > 100:
            return {**out, "result": "invalid", "detail": "event_id is required (max 100 characters)"}
        prior = self.db.one("SELECT outcome FROM operator_events WHERE participant_id=? AND event_id=?",
                            (pid, event_id))
        if prior:
            return {**out, "result": "duplicate", "original_result": prior["outcome"]}
        etype = ev.get("type")
        if etype not in OPERATOR_EVENT_TYPES:
            return {**out, "result": "invalid", "detail": f"type must be one of {list(OPERATOR_EVENT_TYPES)}"}
        if OPERATOR_EVENT_TYPES[etype] not in caps:
            return {**out, "result": "forbidden",
                    "detail": f"participant is not permitted to use '{OPERATOR_EVENT_TYPES[etype]}'"}
        now = self.clock.now()
        try:
            mobile = normalize_mobile(str(ev.get("mobile") or ""))
            when = _parse_when(ev.get("occurred_at"), now)
        except ValueError as e:
            return {**out, "result": "invalid", "detail": str(e)}
        except Invalid as e:
            return {**out, "result": "invalid", "detail": str(e)}

        with self.db.tx() as c:
            uid = self.user_by_mobile(mobile)
            if not uid:
                result = "not_enrolled"
            elif etype == "disconnected":
                if iso(when) < self._mobile_since(uid):
                    result = "predates_enrolment"
                else:
                    self._detach_number(c, uid, pid, when)
                    result = "number_detached"
            elif when + timedelta(hours=self._window_hours()) <= now:
                result = "stale"
            elif self._known_sim_change(uid, when):
                result = "already_known"
            else:
                what = ("moved their number to another mobile operator" if etype == "port_out"
                        else "had their SIM card changed (reported by their mobile operator)")
                self._open_window(c, uid, "operator", pid, when, what=what)
                result = "window_opened"
            c.execute("INSERT INTO operator_events (participant_id, event_id, type, occurred_at, received_at, outcome) "
                      "VALUES (?,?,?,?,?,?)", (pid, event_id, etype, iso(when), iso(now), result))
            if uid:
                self._audit(c, pid, f"operator.{etype}", uid, event_id=event_id, result=result)
        return {**out, "result": result}

    @staticmethod
    def _window_hours() -> int:
        from .simswap import SIM_SWAP_WINDOW_HOURS
        return SIM_SWAP_WINDOW_HOURS

    def _detach_number(self, c: sqlite3.Connection, uid: str, pid: str, when: datetime) -> None:
        u = c.execute("SELECT mobile_enc, display_name FROM users WHERE id=?", (uid,)).fetchone()
        masked = mask_mobile(decrypt_mobile(u["mobile_enc"])) if u["mobile_enc"] else "their number"
        now = self._now()
        c.execute("UPDATE users SET mobile_hash=?, mobile_enc=NULL, number_status='disconnected', "
                  "number_detached_at=? WHERE id=?", (f"detached:{uid}:{now}", now, uid))
        ended = c.execute("UPDATE kyc_attestations SET status='expired', decided_at=?, ended_by='number_disconnected' "
                          "WHERE user_id=? AND status IN ('pending_consent','active')", (now, uid)).rowcount
        c.execute("DELETE FROM sim_lookups WHERE user_id=?", (uid,))
        self._audit(c, pid, "mobile.disconnected", uid, mobile=masked, disconnected_at=iso(when), kyc_ended=ended)
        name = u["display_name"]
        self._alert(c, [uid], "number_disconnected", "Your number was disconnected",
                    f"Your mobile operator says {masked} was disconnected. It is no longer linked to your account, so "
                    "sign-in codes can't reach you. From this app, add your new number under Change number.", uid)
        self._alert_guardians(c, uid, "number_disconnected", "Number disconnected",
                              f"{name}'s mobile number {masked} was disconnected by the operator and removed from "
                              f"their account. Their protection still applies. Help {name} add their new number.")
        for w in c.execute("SELECT principal_id FROM guardianships WHERE guardian_id=? AND status='active'",
                           (uid,)).fetchall():
            self._alert(c, [w["principal_id"]], "guardian_number_disconnected", "Your guardian's number changed",
                        f"{name}'s mobile number was disconnected. They can still act from the phone they are signed "
                        "in on, but can't sign in anywhere new until they add a new number.", w["principal_id"])

    # ------------------------------------------------------------- live lookup
    def refresh_sim_status(self, uid: str, *, force: bool = False) -> dict:
        """Ask the operator about this user's SIM if we haven't recently.

        Returns {"checked": bool, "opened": bool, "unavailable": bool}."""
        out = {"checked": False, "opened": False, "unavailable": False}
        if self.sim_lookup is None:
            return out
        u = self._user(uid)
        if not u["mobile_enc"]:
            return out
        now = self.clock.now()
        cached = self.db.one("SELECT * FROM sim_lookups WHERE user_id=?", (uid,))
        if cached and not force:
            ttl = LOOKUP_CACHE_MINUTES if cached["ok"] else LOOKUP_FAILURE_CACHE_MINUTES
            if cached["checked_at"] > iso(now - timedelta(minutes=ttl)):
                out["unavailable"] = not cached["ok"]
                return out
        out["checked"] = True
        try:
            latest = self.sim_lookup.latest_sim_change(decrypt_mobile(u["mobile_enc"]))
            ok, error = 1, None
        except Exception as e:  # noqa: BLE001 - any lookup failure is handled the same way
            latest, ok, error = None, 0, str(e)[:200]
            log.warning("SIM lookup failed for %s: %s", uid, error)
        with self.db.tx() as c:
            c.execute("INSERT INTO sim_lookups (user_id, checked_at, ok, latest_change, error) VALUES (?,?,?,?,?) "
                      "ON CONFLICT(user_id) DO UPDATE SET checked_at=excluded.checked_at, ok=excluded.ok, "
                      "latest_change=excluded.latest_change, error=excluded.error",
                      (uid, iso(now), ok, iso(latest) if latest else None, error))
            if not ok:
                out["unavailable"] = True
            elif latest and latest + timedelta(hours=self._window_hours()) > now \
                    and latest <= now + timedelta(minutes=5) and not self._known_sim_change(uid, latest):
                self._open_window(c, uid, "operator_lookup", "operator_lookup", latest,
                                  what="had their SIM card changed (found when we checked with their operator)")
                out["opened"] = True
        return out

    def lookup_blocks_trust(self, uid: str) -> bool:
        """For the API: refresh, and say whether a fail-closed outage should block this action."""
        res = self.refresh_sim_status(uid)
        return res["unavailable"] and lookup_fails_closed()
