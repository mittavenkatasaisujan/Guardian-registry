"""The registry: who protects whom, under which rules, and what each bank check decided.

Design rules that matter for fraud:
  * A guardian link exists only after BOTH sides consent (principal invites, guardian accepts).
  * Tightening protection applies at once. Loosening it (raising limits, switching the kill
    switch off, removing a guardian) is held for LOOSENING_DELAY_HOURS, during which any
    other active guardian can veto it or approve it early. This blunts the "scammer on the
    phone tells grandpa to turn off the protection" attack.
  * Guardians cannot loosen a principal's rules; they can only protect (kill switch on,
    approve/deny, cancel a held payment, vouch for a payee, veto a loosening).
  * Every state change writes a hash-chained audit entry in the same transaction.
  * Everyone who must react to an event gets an alert queued in that same transaction
    (see notify.py); urgent ones also go out by SMS.
"""

from __future__ import annotations

import hmac
import json
import sqlite3
from datetime import datetime, timedelta

from . import audit, notify
from .clock import Clock, iso, ist_day
from .db import Database
from .errors import Conflict, Forbidden, Invalid, NotFound, TooMany, Unauthorized
from .models import (
    CHANNELS, ChangeKind, ChangeStatus, CheckStatus, GuardianStatus, Outcome, Rules, Transaction,
)
from .policy import _rupees as rupees, evaluate
from .presets import PRESETS
from .security import (
    encrypt_mobile, is_production, mobile_hash, new_id, new_otp, new_secret, normalize_mobile,
    otp_hash, secret_hash,
)

LOOSENING_DELAY_HOURS = 24
MAX_GUARDIANS = 3
SESSION_DAYS = 30
KEY_ROTATION_GRACE_HOURS = 24
OTP_TTL_MINUTES = 5
OTP_MAX_ATTEMPTS = 5
OTP_RESEND_SECONDS = 30
OTP_MAX_SENDS_PER_WINDOW = 3
OTP_WINDOW_MINUTES = 15

_OUTCOME_TO_STATUS = {
    Outcome.ALLOW: CheckStatus.ALLOWED,
    Outcome.DELAY: CheckStatus.COOLING_OFF,
    Outcome.NEEDS_APPROVAL: CheckStatus.PENDING_APPROVAL,
    Outcome.BLOCK: CheckStatus.BLOCKED,
}


class Registry:
    def __init__(self, db: Database | None = None, clock: Clock | None = None):
        self.db = db or Database()
        self.clock = clock or Clock()

    # ------------------------------------------------------------------ helpers
    def _now(self) -> str:
        return iso(self.clock.now())

    def _audit(self, c: sqlite3.Connection, actor: str, action: str,
               principal_id: str | None, **data) -> None:
        audit.append(c, self._now(), actor, action, principal_id, data)

    def _user(self, user_id: str) -> sqlite3.Row:
        row = self.db.one("SELECT * FROM users WHERE id=?", (user_id,))
        if not row:
            raise NotFound("user not found")
        return row

    def _active_guardianship(self, principal_id: str, guardian_id: str) -> sqlite3.Row | None:
        return self.db.one(
            "SELECT * FROM guardianships WHERE principal_id=? AND guardian_id=? AND status=?",
            (principal_id, guardian_id, GuardianStatus.ACTIVE.value),
        )

    def _require_guardian(self, principal_id: str, guardian_id: str) -> None:
        if not self._active_guardianship(principal_id, guardian_id):
            raise Forbidden("you are not an active guardian of this person")

    def _require_principal_or_guardian(self, principal_id: str, actor_id: str) -> str:
        if actor_id == principal_id:
            return "principal"
        self._require_guardian(principal_id, actor_id)
        return "guardian"

    def _active_guardian_ids(self, principal_id: str) -> list[str]:
        return [r["guardian_id"] for r in self.db.all(
            "SELECT guardian_id FROM guardianships WHERE principal_id=? AND status=?",
            (principal_id, GuardianStatus.ACTIVE.value))]

    def _name(self, user_id: str) -> str:
        return self._user(user_id)["display_name"]

    def _alert(self, c: sqlite3.Connection, user_ids, kind: str, title: str, body: str,
               principal_id: str | None, **payload) -> None:
        for uid in dict.fromkeys(user_ids):  # de-duplicate, keep order
            notify.enqueue_user(c, self._now(), uid, kind, title, body, principal_id, payload)

    def _alert_guardians(self, c: sqlite3.Connection, principal_id: str, kind: str, title: str, body: str,
                         exclude: tuple = (), **payload) -> None:
        ids = [g for g in self._active_guardian_ids(principal_id) if g not in exclude]
        self._alert(c, ids, kind, title, body, principal_id, **payload)

    def _webhook_check(self, c: sqlite3.Connection, cid: str) -> None:
        r = c.execute("SELECT participant_id, principal_id FROM checks WHERE id=?", (cid,)).fetchone()
        notify.enqueue_participant(c, self._now(), r["participant_id"], "check.updated",
                                   {"check": self._check_view(cid, for_participant=True)}, r["principal_id"])

    # ------------------------------------------------------------- participants
    def register_participant(self, name: str) -> tuple[str, str]:
        """A bank or payment app. Returns (participant_id, api_key); the key is shown once."""
        name = name.strip()
        if not name:
            raise Invalid("name is required")
        if self.db.one("SELECT 1 FROM participants WHERE name=?", (name,)):
            raise Conflict("participant already registered")
        pid, key = new_id("prt"), new_secret("grk")
        with self.db.tx() as c:
            c.execute("INSERT INTO participants (id, name, key_hash, created_at) VALUES (?,?,?,?)",
                      (pid, name, secret_hash(key), self._now()))
            self._audit(c, "admin", "participant.registered", None, participant_id=pid, name=name)
        return pid, key

    def participant_by_key(self, key: str) -> str | None:
        h = secret_hash(key)
        row = self.db.one("SELECT id FROM participants WHERE key_hash=?", (h,))
        if row:
            return row["id"]
        row = self.db.one("SELECT id FROM participants WHERE prev_key_hash=? AND prev_key_expires_at>?",
                          (h, self._now()))
        return row["id"] if row else None

    def rotate_participant_key(self, participant_id: str) -> dict:
        """Issue a new API key. The old one keeps working for KEY_ROTATION_GRACE_HOURS so the
        bank can roll it out without downtime."""
        key = new_secret("grk")
        grace = iso(self.clock.now() + timedelta(hours=KEY_ROTATION_GRACE_HOURS))
        with self.db.tx() as c:
            c.execute("UPDATE participants SET prev_key_hash=key_hash, prev_key_expires_at=?, key_hash=? WHERE id=?",
                      (grace, secret_hash(key), participant_id))
            self._audit(c, participant_id, "participant.key_rotated", None, participant_id=participant_id)
        return {"api_key": key, "previous_key_valid_until": grace}

    def set_webhook(self, participant_id: str, url: str | None) -> dict:
        """Register (or clear) the URL that receives signed check.updated events."""
        if url:
            url = url.strip()
            local = url.startswith(("http://localhost", "http://127.0.0.1"))
            if not (url.startswith("https://") or (local and not is_production())):
                raise Invalid("webhook url must be https:// (http://localhost allowed outside production)")
        secret = new_secret("whs") if url else None
        with self.db.tx() as c:
            c.execute("UPDATE participants SET webhook_url=?, webhook_secret=? WHERE id=?", (url, secret, participant_id))
            self._audit(c, participant_id, "participant.webhook_set", None, participant_id=participant_id, url=url)
        return {"webhook_url": url, "webhook_secret": secret}

    # -------------------------------------------------------------------- users
    def register_user(self, mobile: str, display_name: str) -> tuple[str, str]:
        """Enrol a person and open a session. The API only reaches this after the number is
        proven by OTP (see verify_otp); it is public here for tests and back-office tools."""
        try:
            mh = mobile_hash(mobile)
        except ValueError as e:
            raise Invalid(str(e)) from None
        display_name = display_name.strip()
        if not display_name:
            raise Invalid("display_name is required")
        if self.db.one("SELECT 1 FROM users WHERE mobile_hash=?", (mh,)):
            raise Conflict("this mobile number is already enrolled")
        uid, token = new_id("usr"), new_secret("gut")
        with self.db.tx() as c:
            c.execute("INSERT INTO users (id, mobile_hash, mobile_enc, display_name, created_at) VALUES (?,?,?,?,?)",
                      (uid, mh, encrypt_mobile(mobile), display_name, self._now()))
            c.execute("INSERT INTO rules VALUES (?,?,?)", (uid, json.dumps(Rules().to_dict()), self._now()))
            self._insert_session(c, uid, token)
            self._audit(c, uid, "user.enrolled", uid)
        return uid, token

    # ----------------------------------------------------------------- sessions
    def _insert_session(self, c: sqlite3.Connection, uid: str, token: str) -> None:
        c.execute("INSERT INTO sessions (token_hash, user_id, created_at, expires_at) VALUES (?,?,?,?)",
                  (secret_hash(token), uid, self._now(), iso(self.clock.now() + timedelta(days=SESSION_DAYS))))

    def user_by_token(self, token: str) -> str | None:
        row = self.db.one("SELECT user_id FROM sessions WHERE token_hash=? AND revoked_at IS NULL AND expires_at>?",
                          (secret_hash(token), self._now()))
        return row["user_id"] if row else None

    def logout(self, token: str, everywhere: bool = False) -> None:
        uid = self.user_by_token(token)
        if not uid:
            return
        with self.db.tx() as c:
            if everywhere:
                c.execute("UPDATE sessions SET revoked_at=? WHERE user_id=? AND revoked_at IS NULL", (self._now(), uid))
            else:
                c.execute("UPDATE sessions SET revoked_at=? WHERE token_hash=?", (self._now(), secret_hash(token)))
            self._audit(c, uid, "session.revoked", uid, everywhere=everywhere)

    # ---------------------------------------------------------------------- OTP
    def request_otp(self, mobile: str, sms: "notify.SmsSender") -> str:
        """Send a one-time code to prove the person holds this number. Behaves the same whether
        or not the number is enrolled, so it can't be used to probe who is registered.
        Returns the code (the API echoes it only when GR_OTP_DEV_ECHO=1 outside production)."""
        try:
            mh = mobile_hash(mobile)
        except ValueError as e:
            raise Invalid(str(e)) from None
        now = self.clock.now()
        row = self.db.one("SELECT * FROM otps WHERE mobile_hash=?", (mh,))
        window_start, sends = iso(now), 0
        if row:
            last = datetime.fromisoformat(row["last_sent_at"])
            if (now - last).total_seconds() < OTP_RESEND_SECONDS:
                raise TooMany(f"wait {OTP_RESEND_SECONDS} seconds before asking for another code")
            if now - datetime.fromisoformat(row["window_start"]) < timedelta(minutes=OTP_WINDOW_MINUTES):
                window_start, sends = row["window_start"], row["sends"]
                if sends >= OTP_MAX_SENDS_PER_WINDOW:
                    raise TooMany(f"too many codes requested; try again in {OTP_WINDOW_MINUTES} minutes")
        code = new_otp()
        with self.db.tx() as c:
            c.execute("INSERT OR REPLACE INTO otps (mobile_hash, code_hash, expires_at, attempts, window_start, sends, "
                      "last_sent_at) VALUES (?,?,?,0,?,?,?)",
                      (mh, otp_hash(mh, code), iso(now + timedelta(minutes=OTP_TTL_MINUTES)),
                       window_start, sends + 1, iso(now)))
        sms.send(normalize_mobile(mobile),
                 f"Guardian Registry code: {code}. Valid {OTP_TTL_MINUTES} min. Never share it with anyone, "
                 "not even a guardian or a bank.")
        return code

    def verify_otp(self, mobile: str, code: str, display_name: str | None = None) -> dict:
        """Check the code. Enrolled number -> new session. New number -> enrol (needs display_name)."""
        try:
            mh = mobile_hash(mobile)
        except ValueError as e:
            raise Invalid(str(e)) from None
        row = self.db.one("SELECT * FROM otps WHERE mobile_hash=?", (mh,))
        if not row or row["expires_at"] <= self._now():
            raise Unauthorized("code expired or not requested")
        if row["attempts"] >= OTP_MAX_ATTEMPTS:
            raise Unauthorized("too many wrong codes; request a new one")
        if not hmac.compare_digest(row["code_hash"], otp_hash(mh, (code or "").strip())):
            with self.db.tx() as c:
                c.execute("UPDATE otps SET attempts=attempts+1 WHERE mobile_hash=?", (mh,))
            raise Unauthorized("wrong code")
        uid = self.user_by_mobile(mobile)
        if not uid and not (display_name or "").strip():
            raise Invalid("this number is not enrolled yet: send display_name to enrol")
        with self.db.tx() as c:
            c.execute("DELETE FROM otps WHERE mobile_hash=?", (mh,))  # single use
        if uid:
            token = new_secret("gut")
            with self.db.tx() as c:
                self._insert_session(c, uid, token)
                self._audit(c, uid, "session.created", uid, via="otp")
            return {"user_id": uid, "token": token, "new_user": False}
        uid, token = self.register_user(mobile, display_name)
        return {"user_id": uid, "token": token, "new_user": True}

    def user_by_mobile(self, mobile: str) -> str | None:
        try:
            mh = mobile_hash(mobile)
        except ValueError:
            return None
        row = self.db.one("SELECT id FROM users WHERE mobile_hash=?", (mh,))
        return row["id"] if row else None

    def profile(self, user_id: str) -> dict:
        u = self._user(user_id)
        return {"id": u["id"], "display_name": u["display_name"], "enrolled_at": u["created_at"]}

    # ---------------------------------------------------------------- guardians
    def invite_guardian(self, principal_id: str, guardian_mobile: str) -> dict:
        guardian_id = self.user_by_mobile(guardian_mobile)
        if not guardian_id:
            raise NotFound("that person must enrol before they can be invited as a guardian")
        if guardian_id == principal_id:
            raise Invalid("you cannot be your own guardian")
        live = self.db.all(
            "SELECT guardian_id FROM guardianships WHERE principal_id=? AND status IN (?,?)",
            (principal_id, GuardianStatus.INVITED.value, GuardianStatus.ACTIVE.value))
        if any(r["guardian_id"] == guardian_id for r in live):
            raise Conflict("this person is already invited or active as your guardian")
        if len(live) >= MAX_GUARDIANS:
            raise Conflict(f"at most {MAX_GUARDIANS} guardians (invited + active)")
        gid = new_id("gdn")
        with self.db.tx() as c:
            c.execute("INSERT INTO guardianships (id, principal_id, guardian_id, status, invited_at) VALUES (?,?,?,?,?)",
                      (gid, principal_id, guardian_id, GuardianStatus.INVITED.value, self._now()))
            self._audit(c, principal_id, "guardian.invited", principal_id, guardianship_id=gid, guardian_id=guardian_id)
            self._alert(c, [guardian_id], "guardian_invited", "Guardian request",
                        f"{self._name(principal_id)} asked you to be their payment guardian. Accept or decline in the app.",
                        principal_id, guardianship_id=gid)
        return self.guardianship(gid)

    def guardianship(self, gid: str) -> dict:
        r = self.db.one("SELECT * FROM guardianships WHERE id=?", (gid,))
        if not r:
            raise NotFound("guardianship not found")
        return {
            "id": r["id"], "principal_id": r["principal_id"],
            "principal_name": self._user(r["principal_id"])["display_name"],
            "guardian_id": r["guardian_id"],
            "guardian_name": self._user(r["guardian_id"])["display_name"],
            "status": r["status"], "invited_at": r["invited_at"],
            "accepted_at": r["accepted_at"], "ended_at": r["ended_at"],
        }

    def respond_to_invite(self, guardian_id: str, gid: str, accept: bool) -> dict:
        r = self.db.one("SELECT * FROM guardianships WHERE id=?", (gid,))
        if not r or r["guardian_id"] != guardian_id:
            raise NotFound("invitation not found")
        if r["status"] != GuardianStatus.INVITED.value:
            raise Conflict(f"invitation is already {r['status']}")
        with self.db.tx() as c:
            if accept:
                c.execute("UPDATE guardianships SET status=?, accepted_at=? WHERE id=?",
                          (GuardianStatus.ACTIVE.value, self._now(), gid))
            else:
                c.execute("UPDATE guardianships SET status=?, ended_at=? WHERE id=?",
                          (GuardianStatus.DECLINED.value, self._now(), gid))
            self._audit(c, guardian_id, "guardian.accepted" if accept else "guardian.declined",
                        r["principal_id"], guardianship_id=gid)
            self._alert(c, [r["principal_id"]], "guardian_accepted" if accept else "guardian_declined",
                        "Guardian " + ("accepted" if accept else "declined"),
                        f"{self._name(guardian_id)} {'is now your guardian' if accept else 'declined your request'}.",
                        r["principal_id"], guardianship_id=gid)
        return self.guardianship(gid)

    def resign(self, guardian_id: str, gid: str) -> dict:
        """A guardian can always step down at once: consent can be withdrawn."""
        r = self.db.one("SELECT * FROM guardianships WHERE id=?", (gid,))
        if not r or r["guardian_id"] != guardian_id:
            raise NotFound("guardianship not found")
        if r["status"] != GuardianStatus.ACTIVE.value:
            raise Conflict("guardianship is not active")
        with self.db.tx() as c:
            c.execute("UPDATE guardianships SET status=?, ended_at=? WHERE id=?",
                      (GuardianStatus.ENDED.value, self._now(), gid))
            self._audit(c, guardian_id, "guardian.resigned", r["principal_id"], guardianship_id=gid)
            self._alert(c, [r["principal_id"]], "guardian_resigned", "Guardian stepped down",
                        f"{self._name(guardian_id)} is no longer your guardian.", r["principal_id"], guardianship_id=gid)
        return self.guardianship(gid)

    def remove_guardian(self, principal_id: str, gid: str) -> dict:
        """Cancelling an unaccepted invite is immediate; removing an active guardian is a
        loosening and is held (see module docstring)."""
        r = self.db.one("SELECT * FROM guardianships WHERE id=?", (gid,))
        if not r or r["principal_id"] != principal_id:
            raise NotFound("guardianship not found")
        if r["status"] == GuardianStatus.INVITED.value:
            with self.db.tx() as c:
                c.execute("UPDATE guardianships SET status=?, ended_at=? WHERE id=?",
                          (GuardianStatus.ENDED.value, self._now(), gid))
                self._audit(c, principal_id, "guardian.invite_cancelled", principal_id, guardianship_id=gid)
            return {"applied": True, "guardianship": self.guardianship(gid)}
        if r["status"] != GuardianStatus.ACTIVE.value:
            raise Conflict("guardianship is not active")
        return self._propose_change(principal_id, ChangeKind.REMOVE_GUARDIAN, {"guardianship_id": gid})

    def guardians_of(self, principal_id: str) -> list[dict]:
        rows = self.db.all("SELECT id FROM guardianships WHERE principal_id=? ORDER BY invited_at", (principal_id,))
        return [self.guardianship(r["id"]) for r in rows]

    def wards_of(self, guardian_id: str) -> list[dict]:
        rows = self.db.all("SELECT id FROM guardianships WHERE guardian_id=? ORDER BY invited_at", (guardian_id,))
        return [self.guardianship(r["id"]) for r in rows]

    # -------------------------------------------------------------------- rules
    def get_rules(self, principal_id: str) -> Rules:
        self._apply_due_changes(principal_id)
        return self._rules_raw(principal_id)

    def _rules_raw(self, principal_id: str) -> Rules:
        row = self.db.one("SELECT body FROM rules WHERE principal_id=?", (principal_id,))
        if not row:
            raise NotFound("user not found")
        return Rules.from_dict(json.loads(row["body"]))

    def _write_rules(self, c: sqlite3.Connection, principal_id: str, rules: Rules) -> None:
        c.execute("UPDATE rules SET body=?, updated_at=? WHERE principal_id=?",
                  (json.dumps(rules.to_dict()), self._now(), principal_id))

    @staticmethod
    def _validate_rules(rules: Rules) -> None:
        for f in ("per_txn_limit", "daily_limit", "approval_threshold", "new_payee_delay_threshold"):
            v = getattr(rules, f)
            if v is not None and (not isinstance(v, int) or isinstance(v, bool) or v <= 0):
                raise Invalid(f"{f} must be a positive whole number of paise or null")
        if not 0 <= rules.cooling_off_minutes <= 7 * 24 * 60:
            raise Invalid("cooling_off_minutes must be between 0 and 10080")
        if not 1 <= rules.approval_timeout_minutes <= 24 * 60:
            raise Invalid("approval_timeout_minutes must be between 1 and 1440")
        bad = set(rules.blocked_channels) - set(CHANNELS)
        if bad:
            raise Invalid(f"unknown channels: {sorted(bad)}")

    def update_rules(self, principal_id: str, changes: dict) -> dict:
        """Principal changes their own rules. `changes` holds only the fields to change.
        Tightening applies now; loosening fields are split off into a held change."""
        if "kill_switch" in changes:
            raise Invalid("use the kill-switch endpoints to turn payments on or off")
        current = self.get_rules(principal_id)
        unknown = set(changes) - set(Rules.__dataclass_fields__)
        if unknown:
            raise Invalid(f"unknown rule fields: {sorted(unknown)}")
        proposed = Rules.from_dict({**current.to_dict(), **changes})
        self._validate_rules(proposed)

        tighten, loosen = {}, {}
        for k, v in changes.items():
            single = Rules.from_dict({**current.to_dict(), k: v})
            (loosen if current.is_loosening(single) else tighten)[k] = v

        result: dict = {"applied": {}, "held": None}
        if tighten:
            with self.db.tx() as c:
                self._write_rules(c, principal_id, Rules.from_dict({**current.to_dict(), **tighten}))
                self._audit(c, principal_id, "rules.tightened", principal_id, changes=tighten)
            result["applied"] = tighten
        if loosen:
            result["held"] = self._propose_change(principal_id, ChangeKind.UPDATE_RULES, {"changes": loosen})
        result["rules"] = self.get_rules(principal_id).to_dict()
        return result

    def engage_kill_switch(self, principal_id: str, actor_id: str) -> Rules:
        role = self._require_principal_or_guardian(principal_id, actor_id)
        current = self.get_rules(principal_id)
        if not current.kill_switch:
            current.kill_switch = True
            with self.db.tx() as c:
                self._write_rules(c, principal_id, current)
                self._audit(c, actor_id, "kill_switch.on", principal_id, by=role)
                self._alert(c, [principal_id, *self._active_guardian_ids(principal_id)], "kill_switch_on",
                            "Payments paused",
                            f"{self._name(actor_id)} paused all outgoing payments for {self._name(principal_id)}.",
                            principal_id)
        return current

    def release_kill_switch(self, principal_id: str, actor_id: str) -> dict:
        """A guardian can switch payments back on at once. The principal's own request is held,
        because "switch it off for me" is exactly what a scammer would ask for."""
        role = self._require_principal_or_guardian(principal_id, actor_id)
        current = self.get_rules(principal_id)
        if not current.kill_switch:
            return {"applied": True, "rules": current.to_dict()}
        if role == "guardian":
            current.kill_switch = False
            with self.db.tx() as c:
                self._write_rules(c, principal_id, current)
                self._audit(c, actor_id, "kill_switch.off", principal_id, by=role)
                self._alert(c, [principal_id, *self._active_guardian_ids(principal_id)], "kill_switch_off",
                            "Payments resumed",
                            f"{self._name(actor_id)} switched payments back on for {self._name(principal_id)}.",
                            principal_id)
            return {"applied": True, "rules": current.to_dict()}
        return self._propose_change(principal_id, ChangeKind.KILL_SWITCH_OFF, {})

    # --------------------------------------------------------- held changes
    def _propose_change(self, principal_id: str, kind: ChangeKind, payload: dict) -> dict:
        cid = new_id("chg")
        effective = iso(self.clock.now() + timedelta(hours=LOOSENING_DELAY_HOURS))
        with self.db.tx() as c:
            c.execute("INSERT INTO pending_changes (id, principal_id, kind, payload, status, requested_by, created_at, effective_at) "
                      "VALUES (?,?,?,?,?,?,?,?)",
                      (cid, principal_id, kind.value, json.dumps(payload), ChangeStatus.PENDING.value,
                       principal_id, self._now(), effective))
            self._audit(c, principal_id, "change.proposed", principal_id, change_id=cid, kind=kind.value, payload=payload)
            who = self._name(principal_id)
            what = {
                ChangeKind.UPDATE_RULES: f"loosen their payment limits ({', '.join(payload.get('changes', {}))})",
                ChangeKind.KILL_SWITCH_OFF: "switch payments back on",
                ChangeKind.REMOVE_GUARDIAN: "remove a guardian",
            }[kind]
            excluded = ()
            if kind is ChangeKind.REMOVE_GUARDIAN:
                g = c.execute("SELECT guardian_id FROM guardianships WHERE id=?", (payload["guardianship_id"],)).fetchone()
                excluded = (g["guardian_id"],) if g else ()
                # the guardian being removed still hears about it, as an urgent alert
                self._alert(c, excluded, "guardian_removal_proposed", "You are being removed as guardian",
                            f"{who} asked to remove you as guardian. It takes effect in {LOOSENING_DELAY_HOURS} hours. "
                            "If this sounds like pressure from someone else, call them.", principal_id, change_id=cid)
            self._alert_guardians(c, principal_id, "change_proposed", "Protection change requested",
                                  f"{who} asked to {what}. It takes effect in {LOOSENING_DELAY_HOURS} hours unless you "
                                  "veto it. If they are on a call with a stranger, veto.", exclude=excluded, change_id=cid)
            self._alert(c, [principal_id], "change_held", "Change on hold",
                        f"For your safety this takes effect in {LOOSENING_DELAY_HOURS} hours. Your guardians have been told.",
                        principal_id, change_id=cid)
        return {"applied": False, "change": self.change(cid)}

    def change(self, cid: str) -> dict:
        r = self.db.one("SELECT * FROM pending_changes WHERE id=?", (cid,))
        if not r:
            raise NotFound("change not found")
        return {"id": r["id"], "principal_id": r["principal_id"], "kind": r["kind"],
                "payload": json.loads(r["payload"]), "status": r["status"],
                "created_at": r["created_at"], "effective_at": r["effective_at"],
                "decided_by": r["decided_by"], "decided_at": r["decided_at"]}

    def changes_for(self, principal_id: str, only_pending: bool = False) -> list[dict]:
        self._apply_due_changes(principal_id)
        sql = "SELECT id FROM pending_changes WHERE principal_id=?"
        args: tuple = (principal_id,)
        if only_pending:
            sql += " AND status=?"
            args += (ChangeStatus.PENDING.value,)
        return [self.change(r["id"]) for r in self.db.all(sql + " ORDER BY created_at", args)]

    def _apply_change(self, c: sqlite3.Connection, r: sqlite3.Row, actor: str) -> None:
        payload = json.loads(r["payload"])
        pid = r["principal_id"]
        kind = ChangeKind(r["kind"])
        if kind is ChangeKind.UPDATE_RULES:
            # apply over CURRENT rules, so tightening done in the meantime is not undone
            current = self._rules_raw(pid)
            self._write_rules(c, pid, Rules.from_dict({**current.to_dict(), **payload["changes"]}))
        elif kind is ChangeKind.KILL_SWITCH_OFF:
            current = self._rules_raw(pid)
            current.kill_switch = False
            self._write_rules(c, pid, current)
        elif kind is ChangeKind.REMOVE_GUARDIAN:
            c.execute("UPDATE guardianships SET status=?, ended_at=? WHERE id=? AND status=?",
                      (GuardianStatus.ENDED.value, self._now(), payload["guardianship_id"], GuardianStatus.ACTIVE.value))
        c.execute("UPDATE pending_changes SET status=?, decided_by=?, decided_at=? WHERE id=?",
                  (ChangeStatus.APPLIED.value, actor, self._now(), r["id"]))
        self._audit(c, actor, "change.applied", pid, change_id=r["id"], kind=kind.value)
        self._alert(c, [pid, *self._active_guardian_ids(pid)], "change_applied", "Protection change applied",
                    f"The requested change ({kind.value.replace('_', ' ')}) for {self._name(pid)} is now in effect.",
                    pid, change_id=r["id"])

    def _apply_due_changes(self, principal_id: str) -> None:
        due = self.db.all("SELECT * FROM pending_changes WHERE principal_id=? AND status=? AND effective_at<=?",
                          (principal_id, ChangeStatus.PENDING.value, self._now()))
        if due:
            with self.db.tx() as c:
                for r in due:
                    self._apply_change(c, r, "system:delay_elapsed")

    def _guardian_change(self, guardian_id: str, cid: str) -> sqlite3.Row:
        r = self.db.one("SELECT * FROM pending_changes WHERE id=?", (cid,))
        if not r:
            raise NotFound("change not found")
        self._require_guardian(r["principal_id"], guardian_id)
        self._apply_due_changes(r["principal_id"])
        r = self.db.one("SELECT * FROM pending_changes WHERE id=?", (cid,))
        if r["status"] != ChangeStatus.PENDING.value:
            raise Conflict(f"change is already {r['status']}")
        if r["kind"] == ChangeKind.REMOVE_GUARDIAN.value:
            target = self.db.one("SELECT guardian_id FROM guardianships WHERE id=?",
                                 (json.loads(r["payload"])["guardianship_id"],))
            if target and target["guardian_id"] == guardian_id:
                raise Forbidden("the guardian being removed cannot decide on their own removal")
        return r

    def approve_change(self, guardian_id: str, cid: str) -> dict:
        r = self._guardian_change(guardian_id, cid)
        with self.db.tx() as c:
            self._apply_change(c, r, guardian_id)
        return self.change(cid)

    def veto_change(self, guardian_id: str, cid: str) -> dict:
        r = self._guardian_change(guardian_id, cid)
        with self.db.tx() as c:
            c.execute("UPDATE pending_changes SET status=?, decided_by=?, decided_at=? WHERE id=?",
                      (ChangeStatus.VETOED.value, guardian_id, self._now(), cid))
            self._audit(c, guardian_id, "change.vetoed", r["principal_id"], change_id=cid)
            self._alert(c, [r["principal_id"]], "change_vetoed", "Change stopped",
                        f"{self._name(guardian_id)} stopped your requested change. Your protection stays as it was.",
                        r["principal_id"], change_id=cid)
        return self.change(cid)

    # ----------------------------------------------------------- trusted payees
    def vouch_payee(self, guardian_id: str, principal_id: str, payee: str) -> None:
        """Only a guardian can vouch for a payee (it skips the new-payee cooling-off)."""
        self._require_guardian(principal_id, guardian_id)
        payee = payee.strip().lower()
        if not payee:
            raise Invalid("payee is required")
        with self.db.tx() as c:
            c.execute("INSERT OR IGNORE INTO trusted_payees VALUES (?,?,?,?)",
                      (principal_id, payee, guardian_id, self._now()))
            self._audit(c, guardian_id, "payee.vouched", principal_id, payee=payee)

    def trusted_payees(self, principal_id: str) -> list[str]:
        return [r["payee"] for r in self.db.all(
            "SELECT payee FROM trusted_payees WHERE principal_id=? ORDER BY added_at", (principal_id,))]

    def _payee_known(self, principal_id: str, payee: str) -> bool:
        return bool(
            self.db.one("SELECT 1 FROM trusted_payees WHERE principal_id=? AND payee=?", (principal_id, payee))
            or self.db.one("SELECT 1 FROM checks WHERE principal_id=? AND payee=? AND completed_at IS NOT NULL",
                           (principal_id, payee))
        )

    # ------------------------------------------------------------------- checks
    def _refresh(self, c: sqlite3.Connection, r: sqlite3.Row) -> bool:
        now = self._now()
        if r["status"] == CheckStatus.COOLING_OFF.value and r["release_at"] <= now:
            c.execute("UPDATE checks SET status=?, decided_by=?, decided_at=? WHERE id=?",
                      (CheckStatus.RELEASED.value, "system:cooling_off_elapsed", r["release_at"], r["id"]))
            self._audit(c, "system", "check.released", r["principal_id"], check_id=r["id"])
            self._alert(c, [r["principal_id"]], "payment_released", "Payment can go ahead",
                        f"The waiting period for {rupees(r['amount'])} to {r['payee']} is over.", r["principal_id"],
                        check_id=r["id"])
            self._webhook_check(c, r["id"])
            return True
        if r["status"] == CheckStatus.PENDING_APPROVAL.value and r["expires_at"] <= now:
            c.execute("UPDATE checks SET status=?, decided_by=?, decided_at=? WHERE id=?",
                      (CheckStatus.EXPIRED.value, "system:approval_timeout", r["expires_at"], r["id"]))
            self._audit(c, "system", "check.expired", r["principal_id"], check_id=r["id"])
            self._alert(c, [r["principal_id"]], "payment_expired", "Payment not approved in time",
                        f"No guardian approved {rupees(r['amount'])} to {r['payee']}, so it was not sent.",
                        r["principal_id"], check_id=r["id"])
            self._webhook_check(c, r["id"])
            return True
        return False

    def _refresh_principal(self, c: sqlite3.Connection, principal_id: str) -> None:
        for r in c.execute("SELECT * FROM checks WHERE principal_id=? AND status IN (?,?)",
                           (principal_id, CheckStatus.COOLING_OFF.value, CheckStatus.PENDING_APPROVAL.value)).fetchall():
            self._refresh(c, r)

    def _check_view(self, cid: str, for_participant: bool = False) -> dict:
        r = self.db.one("SELECT * FROM checks WHERE id=?", (cid,))
        status = CheckStatus(r["status"])
        view = {
            "check_id": r["id"], "enrolled": True,
            "participant_txn_id": r["participant_txn_id"],
            "amount": r["amount"], "payee": r["payee"], "channel": r["channel"],
            "outcome": r["outcome"], "status": status.value,
            "may_execute": status.is_final_go and r["completed_at"] is None,
            "reasons": json.loads(r["reasons"]),
            "created_at": r["created_at"], "release_at": r["release_at"],
            "approval_expires_at": r["expires_at"],
            "decided_by": r["decided_by"], "decided_at": r["decided_at"],
            "completed_at": r["completed_at"],
        }
        if not for_participant:
            view["principal_id"] = r["principal_id"]
        return view

    def check(self, participant_id: str, mobile: str, participant_txn_id: str,
              amount: int, payee: str, channel: str = "upi") -> dict:
        """Called by a bank/app before moving money. Idempotent on (participant, participant_txn_id)."""
        if not participant_txn_id.strip():
            raise Invalid("participant_txn_id is required")
        if channel not in CHANNELS:
            raise Invalid(f"channel must be one of {list(CHANNELS)}")
        if not isinstance(amount, int) or isinstance(amount, bool):
            raise Invalid("amount must be a whole number of paise")
        payee = payee.strip().lower()
        if not payee:
            raise Invalid("payee is required")
        try:
            normalize_mobile(mobile)
        except ValueError as e:
            raise Invalid(str(e)) from None

        principal_id = self.user_by_mobile(mobile)
        if not principal_id:
            return {"enrolled": False, "outcome": Outcome.ALLOW.value, "may_execute": True,
                    "reasons": ["customer is not enrolled in the registry"]}

        existing = self.db.one("SELECT * FROM checks WHERE participant_id=? AND participant_txn_id=?",
                               (participant_id, participant_txn_id))
        if existing:
            if (existing["principal_id"], existing["amount"], existing["payee"], existing["channel"]) != \
                    (principal_id, amount, payee, channel):
                raise Conflict("participant_txn_id was already used for a different payment")
            return self.get_check(participant_id, existing["id"])

        self._apply_due_changes(principal_id)
        now = self.clock.now()
        day = ist_day(now)
        with self.db.tx() as c:
            self._refresh_principal(c, principal_id)
            spend_statuses = [s.value for s in CheckStatus if s.counts_as_spend]
            spent = c.execute(
                "SELECT COALESCE(SUM(amount),0) s FROM checks WHERE principal_id=? AND day=? AND status IN (%s)"
                % ",".join("?" * len(spend_statuses)),
                (principal_id, day, *spend_statuses),
            ).fetchone()["s"]
            rules = self._rules_raw(principal_id)
            decision = evaluate(
                rules, Transaction(amount=amount, payee=payee, channel=channel),
                spent_today=spent,
                payee_known=self._payee_known(principal_id, payee),
                has_active_guardian=bool(self._active_guardian_ids(principal_id)),
            )
            status = _OUTCOME_TO_STATUS[decision.outcome]
            release_at = iso(now + timedelta(minutes=decision.delay_minutes)) if decision.outcome is Outcome.DELAY else None
            expires_at = (iso(now + timedelta(minutes=decision.approval_timeout_minutes))
                          if decision.outcome is Outcome.NEEDS_APPROVAL else None)
            cid = new_id("chk")
            c.execute(
                "INSERT INTO checks (id, principal_id, participant_id, participant_txn_id, amount, payee, channel, "
                "outcome, status, reasons, day, created_at, release_at, expires_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (cid, principal_id, participant_id, participant_txn_id, amount, payee, channel,
                 decision.outcome.value, status.value, json.dumps(decision.reasons, ensure_ascii=False),
                 day, iso(now), release_at, expires_at),
            )
            self._audit(c, participant_id, "check.decided", principal_id, check_id=cid,
                        amount=amount, payee=payee, channel=channel, outcome=decision.outcome.value)
            who, amt = self._name(principal_id), rupees(amount)
            why = "; ".join(decision.reasons)
            if decision.outcome is Outcome.NEEDS_APPROVAL:
                self._alert_guardians(c, principal_id, "approval_needed", "Approve payment?",
                                      f"{who} wants to pay {amt} to {payee}. Approve or deny within "
                                      f"{decision.approval_timeout_minutes} min. Reason held: {why}.", check_id=cid)
                self._alert(c, [principal_id], "payment_waiting", "Waiting for your guardian",
                            f"{amt} to {payee} needs a guardian's approval. They have been alerted.", principal_id,
                            check_id=cid)
            elif decision.outcome is Outcome.DELAY:
                self._alert_guardians(c, principal_id, "payment_held", "Payment on hold",
                                      f"{who} is paying {amt} to {payee}. It goes through in {decision.delay_minutes} "
                                      f"min unless you or they cancel it. Reason: {why}.", check_id=cid)
                self._alert(c, [principal_id], "payment_waiting", "Payment on hold",
                            f"{amt} to {payee} will go through in {decision.delay_minutes} min. You can cancel it "
                            "until then.", principal_id, check_id=cid)
            elif decision.outcome is Outcome.BLOCK:
                self._alert(c, [principal_id], "payment_blocked", "Payment blocked",
                            f"{amt} to {payee} was blocked: {why}.", principal_id, check_id=cid)
        return self._check_view(cid, for_participant=True)

    def _load_check(self, cid: str) -> sqlite3.Row:
        r = self.db.one("SELECT * FROM checks WHERE id=?", (cid,))
        if not r:
            raise NotFound("check not found")
        with self.db.tx() as c:
            if self._refresh(c, r):
                r = c.execute("SELECT * FROM checks WHERE id=?", (cid,)).fetchone()
        return r

    def get_check(self, participant_id: str, cid: str) -> dict:
        r = self._load_check(cid)
        if r["participant_id"] != participant_id:
            raise NotFound("check not found")
        return self._check_view(cid, for_participant=True)

    def report_outcome(self, participant_id: str, cid: str, completed: bool) -> dict:
        """Bank tells the registry whether the money actually moved. A failed payment stops
        counting toward the daily limit; a completed one makes the payee 'known'."""
        r = self._load_check(cid)
        if r["participant_id"] != participant_id:
            raise NotFound("check not found")
        if r["completed_at"] is not None:
            raise Conflict("outcome already reported as completed")
        if not CheckStatus(r["status"]).is_final_go:
            raise Conflict(f"payment was not cleared to execute (status: {r['status']})")
        with self.db.tx() as c:
            if completed:
                c.execute("UPDATE checks SET completed_at=? WHERE id=?", (self._now(), cid))
            else:
                c.execute("UPDATE checks SET status=? WHERE id=?", (CheckStatus.FAILED.value, cid))
            self._audit(c, participant_id, "check.completed" if completed else "check.failed",
                        r["principal_id"], check_id=cid)
        return self._check_view(cid, for_participant=True)

    def _decide_check(self, actor_id: str, cid: str, new_status: CheckStatus,
                      allowed_from: set[CheckStatus], allow_principal: bool) -> dict:
        with self.db.tx() as c:  # read, refresh and write under one lock: no approve-vs-expiry race
            r = self._load_check(cid)
            pid = r["principal_id"]
            if not (allow_principal and actor_id == pid):
                self._require_guardian(pid, actor_id)
            if CheckStatus(r["status"]) not in allowed_from:
                raise Conflict(f"payment is {r['status']}; it can no longer be changed")
            c.execute("UPDATE checks SET status=?, decided_by=?, decided_at=? WHERE id=?",
                      (new_status.value, actor_id, self._now(), cid))
            self._audit(c, actor_id, f"check.{new_status.value}", pid, check_id=cid)
            verb = {CheckStatus.APPROVED: "approved", CheckStatus.DENIED: "denied",
                    CheckStatus.CANCELLED: "cancelled"}[new_status]
            self._alert(c, [pid, *self._active_guardian_ids(pid)], f"payment_{verb}", f"Payment {verb}",
                        f"{self._name(actor_id)} {verb} {rupees(r['amount'])} to {r['payee']}.", pid, check_id=cid)
            self._webhook_check(c, cid)
        return self._check_view(cid)

    def approve_check(self, guardian_id: str, cid: str) -> dict:
        return self._decide_check(guardian_id, cid, CheckStatus.APPROVED,
                                  {CheckStatus.PENDING_APPROVAL}, allow_principal=False)

    def deny_check(self, guardian_id: str, cid: str) -> dict:
        return self._decide_check(guardian_id, cid, CheckStatus.DENIED,
                                  {CheckStatus.PENDING_APPROVAL}, allow_principal=False)

    def cancel_check(self, actor_id: str, cid: str) -> dict:
        """The principal or a guardian can stop a payment that is still held."""
        return self._decide_check(actor_id, cid, CheckStatus.CANCELLED,
                                  {CheckStatus.PENDING_APPROVAL, CheckStatus.COOLING_OFF}, allow_principal=True)

    def history(self, actor_id: str, principal_id: str, limit: int = 50) -> list[dict]:
        self._require_principal_or_guardian(principal_id, actor_id)
        with self.db.tx() as c:
            self._refresh_principal(c, principal_id)
        rows = self.db.all("SELECT id FROM checks WHERE principal_id=? ORDER BY created_at DESC, rowid DESC LIMIT ?",
                           (principal_id, limit))
        return [self._check_view(r["id"]) for r in rows]

    def inbox(self, guardian_id: str) -> dict:
        """What needs this guardian's attention across all the people they protect."""
        wards = [g["principal_id"] for g in self.wards_of(guardian_id) if g["status"] == GuardianStatus.ACTIVE.value]
        approvals, changes = [], []
        for pid in wards:
            self._apply_due_changes(pid)
            with self.db.tx() as c:
                self._refresh_principal(c, pid)
            for r in self.db.all("SELECT id FROM checks WHERE principal_id=? AND status IN (?,?) ORDER BY created_at",
                                 (pid, CheckStatus.PENDING_APPROVAL.value, CheckStatus.COOLING_OFF.value)):
                approvals.append(self._check_view(r["id"]))
            changes.extend(self.changes_for(pid, only_pending=True))
        invites = [g for g in self.wards_of(guardian_id) if g["status"] == GuardianStatus.INVITED.value]
        return {"held_payments": approvals, "pending_changes": changes, "invitations": invites}

    # -------------------------------------------------------------- presets
    def apply_preset(self, principal_id: str, name: str) -> dict:
        """Apply a named rule bundle. It goes through update_rules, so any loosening is held."""
        if name not in PRESETS:
            raise NotFound(f"unknown preset; choose one of {sorted(PRESETS)}")
        return self.update_rules(principal_id, dict(PRESETS[name]["rules"]))

    # ---------------------------------------------------------------- sweeper
    def sweep(self) -> dict:
        """Move time-based state forward for everyone: release finished cooling-offs, expire
        unanswered approvals, apply held changes whose delay is over. The background worker
        calls this so alerts and webhooks fire on time even if nobody is reading."""
        now = self._now()
        principals = {r["principal_id"] for r in self.db.all(
            "SELECT DISTINCT principal_id FROM checks WHERE (status=? AND release_at<=?) OR (status=? AND expires_at<=?)",
            (CheckStatus.COOLING_OFF.value, now, CheckStatus.PENDING_APPROVAL.value, now))}
        changes = {r["principal_id"] for r in self.db.all(
            "SELECT DISTINCT principal_id FROM pending_changes WHERE status=? AND effective_at<=?",
            (ChangeStatus.PENDING.value, now))}
        for pid in principals:
            with self.db.tx() as c:
                self._refresh_principal(c, pid)
        for pid in changes:
            self._apply_due_changes(pid)
        return {"principals_refreshed": len(principals), "principals_with_changes": len(changes)}

    # ---------------------------------------------------------- notifications
    def notifications(self, user_id: str, unread_only: bool = False, limit: int = 50) -> list[dict]:
        sql = ("SELECT * FROM notifications WHERE recipient_type='user' AND recipient_id=? AND channel='inapp'"
               + (" AND read_at IS NULL" if unread_only else "") + " ORDER BY created_at DESC, rowid DESC LIMIT ?")
        return [{"id": r["id"], "kind": r["kind"], "title": r["title"], "body": r["body"],
                 "principal_id": r["principal_id"], "data": json.loads(r["payload"]),
                 "created_at": r["created_at"], "read": r["read_at"] is not None}
                for r in self.db.all(sql, (user_id, limit))]

    def mark_read(self, user_id: str, ids: list[str] | None = None) -> int:
        with self.db.tx() as c:
            if ids:
                q = ",".join("?" * len(ids))
                cur = c.execute(f"UPDATE notifications SET read_at=? WHERE recipient_type='user' AND recipient_id=? "
                                f"AND read_at IS NULL AND id IN ({q})", (self._now(), user_id, *ids))
            else:
                cur = c.execute("UPDATE notifications SET read_at=? WHERE recipient_type='user' AND recipient_id=? "
                                "AND read_at IS NULL", (self._now(), user_id))
            return cur.rowcount

    # -------------------------------------------------------------------- audit
    def audit_trail(self, actor_id: str, principal_id: str) -> list[dict]:
        self._require_principal_or_guardian(principal_id, actor_id)
        return [{"seq": r["seq"], "ts": r["ts"], "actor": r["actor"], "action": r["action"],
                 "data": json.loads(r["data"]), "hash": r["hash"]}
                for r in self.db.all("SELECT * FROM audit_log WHERE principal_id=? ORDER BY seq", (principal_id,))]

    def verify_audit(self) -> audit.VerifyResult:
        with self.db.tx() as c:
            return audit.verify(c)
