"""SIM-swap and account-takeover protection.

The attack: a fraudster gets the victim's number moved to a new SIM (a fake "lost SIM"
request, or an insider at a shop). From then on THEY receive the SMS codes. With this
registry that would let them sign in as the victim (to loosen protection) or as a
GUARDIAN (to approve scam payments for someone else).

Defences:
  1. Signals open a risk window of SIM_SWAP_WINDOW_HOURS:
       * a participant bank reports a SIM change (banks get these from mobile operators), or
       * the person, or one of their guardians, reports a lost or stolen phone. That also
         signs the person out everywhere.
  2. Restricted sign-ins. A session is RESTRICTED if it started after the SIM changed
     (during an open window), or on a device this person hasn't used before (probation
     for NEW_DEVICE_PROBATION_HOURS). A restricted session can read, deny, cancel, veto
     and switch the kill switch ON. It cannot approve payments, accept a guardian role,
     invite guardians, loosen rules, confirm the SIM change or change the number. The API
     enforces this list (see api.TrustedUser).
  3. Payment holds. While the window is open, the rules engine holds payments to new
     payees and larger payments (policy.py, rule `sim_swap_hold`).
  4. No SMS to a number that may be in the wrong hands. Alerts to that person go in-app
     only, and their guardians are told by SMS.
  5. Closing the window early. "Yes, I changed my SIM" counts only from a trusted session:
     the person's old, already-signed-in device, or one of their guardians.

A genuine number change is also handled here: the new number is proven by OTP, then the
move is held for 24 h (guardians can veto or approve early). It ends existing bank KYC
claims, since those vouched for the old number.
"""

from __future__ import annotations

import hashlib
import hmac
import sqlite3
from datetime import datetime, timedelta

from .clock import iso
from .errors import Conflict, Invalid
from .models import ChangeKind, Rules
from .security import encrypt_mobile, mask_mobile, new_id, normalize_mobile, pepper, secret_hash

SIM_SWAP_WINDOW_HOURS = 72
NEW_DEVICE_PROBATION_HOURS = 24
CLOCK_SKEW = timedelta(minutes=5)


class SimSwapMixin:
    """Mixed into Registry."""

    # ------------------------------------------------------------- devices
    @staticmethod
    def _device_hash(uid: str, device_id: str) -> str:
        return hmac.new(pepper(), f"device:{uid}:{device_id}".encode(), hashlib.sha256).hexdigest()

    def _register_device(self, c: sqlite3.Connection, uid: str, device_id: str | None) -> tuple[str | None, str | None]:
        """Record the device. Returns (device_hash, probation_until or None).

        The first device ever is trusted at once. A later new device (or a sign-in that
        sends no device id) is on probation. A device becomes trusted only when its
        probation ends, so signing in twice doesn't skip it."""
        now = self.clock.now()
        first_ever = not c.execute("SELECT 1 FROM devices WHERE user_id=?", (uid,)).fetchone() and \
            not c.execute("SELECT 1 FROM sessions WHERE user_id=?", (uid,)).fetchone()
        if not device_id:
            return None, (None if first_ever else iso(now + timedelta(hours=NEW_DEVICE_PROBATION_HOURS)))
        dh = self._device_hash(uid, device_id.strip())
        row = c.execute("SELECT * FROM devices WHERE user_id=? AND device_hash=?", (uid, dh)).fetchone()
        if row:
            c.execute("UPDATE devices SET last_seen=? WHERE user_id=? AND device_hash=?", (iso(now), uid, dh))
            return dh, (None if row["trusted_at"] <= iso(now) else row["trusted_at"])
        probation = None if first_ever else iso(now + timedelta(hours=NEW_DEVICE_PROBATION_HOURS))
        c.execute("INSERT INTO devices VALUES (?,?,?,?,?)", (uid, dh, iso(now), iso(now), probation or iso(now)))
        return dh, probation

    # ------------------------------------------------------------- windows
    def _open_sim_events(self, uid: str) -> list[sqlite3.Row]:
        return self.db.all("SELECT * FROM sim_events WHERE user_id=? AND cleared_at IS NULL AND window_ends_at>? "
                           "ORDER BY changed_at", (uid, self._now()))

    def sim_swap_active(self, uid: str) -> bool:
        return bool(self._open_sim_events(uid))

    def session_info(self, token: str) -> dict | None:
        r = self.db.one("SELECT * FROM sessions WHERE token_hash=? AND revoked_at IS NULL AND expires_at>?",
                        (secret_hash(token), self._now()))
        if not r:
            return None
        reasons = []
        if r["probation_until"] and r["probation_until"] > self._now():
            reasons.append(f"new device: restricted until {r['probation_until']}")
        for ev in self._open_sim_events(r["user_id"]):
            if r["created_at"] >= ev["changed_at"]:
                reasons.append(f"signed in after a SIM change: restricted until {ev['window_ends_at']} "
                               "or until confirmed from a trusted device or by a guardian")
                break
        return {"user_id": r["user_id"], "restricted": bool(reasons), "reasons": reasons,
                "created_at": r["created_at"]}

    def _open_window(self, c: sqlite3.Connection, uid: str, source: str, reported_by: str,
                     changed_at: datetime) -> str:
        eid = new_id("sim")
        ends = changed_at + timedelta(hours=SIM_SWAP_WINDOW_HOURS)
        c.execute("INSERT INTO sim_events (id, user_id, source, reported_by, changed_at, created_at, window_ends_at) "
                  "VALUES (?,?,?,?,?,?,?)", (eid, uid, source, reported_by, iso(changed_at), self._now(), iso(ends)))
        self._audit(c, reported_by, "sim.window_opened", uid, event_id=eid, source=source, changed_at=iso(changed_at))
        who = self._name(uid)
        what = "had their SIM card changed" if source == "participant" else "reported a lost or stolen phone"
        self._alert_guardians(c, uid, "sim_changed", "SIM change alert",
                              f"{who} {what}. For {SIM_SWAP_WINDOW_HOURS} h, new sign-ins can't approve or loosen "
                              f"anything and larger payments are held. Call {who} on another number. If it wasn't "
                              "them, switch on the kill switch.", event_id=eid)
        # people this user GUARDS: their guardian's approvals from new sign-ins are paused
        for w in c.execute("SELECT principal_id FROM guardianships WHERE guardian_id=? AND status='active'",
                           (uid,)).fetchall():
            self._alert(c, [w["principal_id"]], "guardian_sim_changed", "Your guardian's SIM changed",
                        f"{who}'s SIM card changed. Approvals from their new sign-ins are paused for "
                        f"{SIM_SWAP_WINDOW_HOURS} h.", w["principal_id"], event_id=eid)
        self._alert(c, [uid], "sim_changed_self", "SIM change detected",
                    "We were told your SIM card changed. If you did this, confirm it from your old phone or ask a "
                    "guardian to confirm. If you didn't, contact your mobile operator now.", uid, event_id=eid)
        return eid

    # ------------------------------------------------------------- signals
    def report_sim_change(self, participant_id: str, mobile: str, changed_at: str | None = None) -> dict:
        """A bank reports that the customer's SIM changed (from its operator data)."""
        try:
            normalize_mobile(mobile)
        except ValueError as e:
            raise Invalid(str(e)) from None
        now = self.clock.now()
        when = now
        if changed_at:
            try:
                when = datetime.fromisoformat(changed_at)
            except ValueError:
                raise Invalid("changed_at must be an ISO 8601 timestamp") from None
            if when.tzinfo is None:
                raise Invalid("changed_at must include a timezone, e.g. 2026-11-23T09:15:00+05:30")
            if when > now + CLOCK_SKEW:
                raise Invalid("changed_at cannot be in the future")
        uid = self.user_by_mobile(mobile)
        if not uid:
            return {"enrolled": False}
        if when + timedelta(hours=SIM_SWAP_WINDOW_HOURS) <= now:
            with self.db.tx() as c:
                self._audit(c, participant_id, "sim.reported_stale", uid, changed_at=iso(when))
            return {"enrolled": True, "window_open": False, "note": "SIM change is older than the risk window"}
        with self.db.tx() as c:
            eid = self._open_window(c, uid, "participant", participant_id, when)
        return {"enrolled": True, "window_open": True, "event_id": eid,
                "window_ends_at": iso(when + timedelta(hours=SIM_SWAP_WINDOW_HOURS))}

    def report_lost_phone(self, actor_id: str, user_id: str) -> dict:
        """The person or a guardian says the phone is lost or stolen: sign the person out
        everywhere and open the risk window."""
        role = self._require_principal_or_guardian(user_id, actor_id)
        with self.db.tx() as c:
            n = c.execute("UPDATE sessions SET revoked_at=? WHERE user_id=? AND revoked_at IS NULL",
                          (self._now(), user_id)).rowcount
            c.execute("UPDATE devices SET trusted_at=? WHERE user_id=?",  # every device must re-earn trust
                      (iso(self.clock.now() + timedelta(hours=NEW_DEVICE_PROBATION_HOURS)), user_id))
            self._audit(c, actor_id, "sim.lost_phone", user_id, by=role, sessions_revoked=n)
            eid = self._open_window(c, user_id, "self" if role == "principal" else "guardian", actor_id,
                                    self.clock.now())
        return {"event_id": eid, "sessions_revoked": n,
                "window_ends_at": iso(self.clock.now() + timedelta(hours=SIM_SWAP_WINDOW_HOURS))}

    def confirm_sim_change(self, actor_id: str, user_id: str) -> dict:
        """'Yes, the SIM change was me.' The API only allows this from a trusted session."""
        role = self._require_principal_or_guardian(user_id, actor_id)
        events = self._open_sim_events(user_id)
        if not events:
            raise Conflict("no open SIM-change window")
        with self.db.tx() as c:
            for ev in events:
                c.execute("UPDATE sim_events SET cleared_at=?, cleared_by=? WHERE id=?", (self._now(), actor_id, ev["id"]))
            self._audit(c, actor_id, "sim.window_cleared", user_id, by=role, events=[e["id"] for e in events])
            self._alert(c, [user_id, *self._active_guardian_ids(user_id)], "sim_change_confirmed",
                        "SIM change confirmed", f"{self._name(actor_id)} confirmed the SIM change for "
                        f"{self._name(user_id)}. Normal protection applies again.", user_id)
        return {"cleared": len(events)}

    def security_status(self, actor_id: str, user_id: str) -> dict:
        self._require_principal_or_guardian(user_id, actor_id)
        events = self._open_sim_events(user_id)
        devices = self.db.all("SELECT trusted_at FROM devices WHERE user_id=?", (user_id,))
        now = self._now()
        return {
            "sim_swap_window_open": bool(events),
            "window_ends_at": max((e["window_ends_at"] for e in events), default=None),
            "reported_by": [e["source"] for e in events],
            "trusted_devices": sum(1 for d in devices if d["trusted_at"] <= now),
            "devices_on_probation": sum(1 for d in devices if d["trusted_at"] > now),
            "sim_swap_hold_rule": self._rules_raw(user_id).sim_swap_hold,
        }

    # ------------------------------------------------------------- loosening test for restricted sessions
    def would_loosen(self, user_id: str, changes: dict) -> bool:
        current = self.get_rules(user_id)
        try:
            proposed = Rules.from_dict({**current.to_dict(), **changes})
        except TypeError:
            return True
        return current.is_loosening(proposed)

    # ------------------------------------------------------------- number change
    def request_mobile_change(self, user_id: str, new_mobile: str, sms) -> str:
        if self.user_by_mobile(new_mobile):
            raise Conflict("that number is already enrolled")
        return self.request_otp(new_mobile, sms)

    def confirm_mobile_change(self, user_id: str, new_mobile: str, code: str) -> dict:
        mh = self._check_otp(new_mobile, code)
        if self.user_by_mobile(new_mobile):
            raise Conflict("that number is already enrolled")
        self._consume_otp(mh)
        payload = {"new_mobile_hash": mh, "new_mobile_enc": encrypt_mobile(new_mobile),
                   "new_mobile_masked": mask_mobile(new_mobile)}
        return self._propose_change(user_id, ChangeKind.CHANGE_MOBILE, payload)

    def _apply_mobile_change(self, c: sqlite3.Connection, uid: str, payload: dict) -> None:
        taken = c.execute("SELECT id FROM users WHERE mobile_hash=? AND id<>?", (payload["new_mobile_hash"], uid)).fetchone()
        if taken:
            raise Conflict("the new number was enrolled by someone else in the meantime")
        c.execute("UPDATE users SET mobile_hash=?, mobile_enc=? WHERE id=?",
                  (payload["new_mobile_hash"], payload["new_mobile_enc"], uid))
        ended = c.execute("UPDATE kyc_attestations SET status='expired', decided_at=?, ended_by='number_changed' "
                          "WHERE user_id=? AND status IN ('pending_consent','active')", (self._now(), uid)).rowcount
        self._audit(c, uid, "mobile.changed", uid, new_mobile=payload["new_mobile_masked"], kyc_ended=ended)
        if ended:
            self._alert(c, [uid], "kyc_expired", "Bank verification ended",
                        "Your number changed, so your bank needs to confirm your identity again.", uid)

