"""Account recovery when the number is gone and no phone is still signed in.

A disconnected number is detached from its account (simfeed.py). If the owner still has a
signed-in phone they add a new number from it. If they don't, they recover here:

  1. Start. On the NEW number they prove it with an SMS code, and say what their OLD
     (disconnected) number was. The answer is the same whether or not an account matches,
     so this can't be used to find out who is enrolled. They get a recovery token to
     check progress.
  2. Vouch. The people who know them in the registry (their guardians, and the people
     they guard) are alerted and asked to vouch from a TRUSTED session. "Only approve if
     you have spoken to them yourself, on a call you placed or in person."
       * 2 or more such contacts -> 2 must approve; exactly 1 -> that one.
       * Or a bank that previously KYC'd them vouches after seeing them (it must give the
         same customer id it used then, which we kept only as a keyed hash).
     Any contact can DENY, which ends the attempt for everyone.
  3. Hold. Once vouched, the recovery waits RECOVERY_HOLD_HOURS. Any contact, or the
     owner from any session still alive, can still stop it.
  4. Complete. The new number is linked, every old session is signed out (whoever has an
     old phone might not be the owner), and the owner signs in normally. Their first
     sign-in is on a new device, so it starts on probation as usual.

Requests that don't vouch in RECOVERY_TTL_HOURS expire. Someone with no contacts and no
bank KYC can't self-recover; that needs a person at the operator's back office.
"""

from __future__ import annotations

import sqlite3
from datetime import timedelta

from .clock import iso
from .errors import Conflict, Forbidden, Invalid, NotFound
from .kyc import _ref_hash
from .security import encrypt_mobile, mask_mobile, mobile_hash, new_id, new_secret, normalize_mobile, secret_hash

RECOVERY_TTL_HOURS = 72
RECOVERY_HOLD_HOURS = 24
OPEN = ("pending", "held")


class RecoveryMixin:
    """Mixed into Registry."""

    # ------------------------------------------------------------- helpers
    def _contacts(self, uid: str) -> list[str]:
        """People who know this person in the registry: their guardians and their wards."""
        rows = self.db.all(
            "SELECT guardian_id AS other FROM guardianships WHERE principal_id=? AND status='active' "
            "UNION SELECT principal_id FROM guardianships WHERE guardian_id=? AND status='active'", (uid, uid))
        return [r["other"] for r in rows]

    @staticmethod
    def _vouches_needed(n_contacts: int) -> int:
        return 2 if n_contacts >= 2 else n_contacts

    def _recovery(self, rid: str) -> sqlite3.Row:
        r = self.db.one("SELECT * FROM recoveries WHERE id=? AND user_id IS NOT NULL", (rid,))
        if not r:
            raise NotFound("recovery not found")
        return r

    def _recovery_view(self, r: sqlite3.Row, viewer: str | None = None) -> dict:
        votes = self.db.all("SELECT voucher_id, vote FROM recovery_vouches WHERE recovery_id=?", (r["id"],))
        out = {"recovery_id": r["id"], "status": r["status"], "person_id": r["user_id"],
               "person_name": self._name(r["user_id"]), "new_number": r["new_mobile_masked"],
               "created_at": r["created_at"], "expires_at": r["expires_at"], "effective_at": r["effective_at"],
               "approvals": sum(v["vote"] == "approve" for v in votes), "approvals_needed": r["needed"],
               "bank_vouched": r["bank_vouched_by"] is not None}
        if viewer:
            mine = [v["vote"] for v in votes if v["voucher_id"] == viewer]
            out["your_vote"] = mine[0] if mine else None
        return out

    # ------------------------------------------------------------- start
    def start_recovery(self, old_mobile: str, new_mobile: str, code: str) -> dict:
        try:
            old_h = mobile_hash(old_mobile)
            normalize_mobile(new_mobile)
        except ValueError as e:
            raise Invalid(str(e)) from None
        new_h = self._check_otp(new_mobile, code)  # proves they hold the NEW number
        if self.user_by_mobile(new_mobile):
            raise Conflict("that new number is already enrolled; recover with a number that isn't")
        self._consume_otp(new_h)
        target = self.db.one("SELECT id FROM users WHERE prev_mobile_hash=? AND number_status='disconnected'", (old_h,))
        uid = target["id"] if target else None
        if uid and self.db.one("SELECT 1 FROM recoveries WHERE user_id=? AND status IN ('pending','held')", (uid,)):
            uid = None  # one attempt at a time; answer exactly as if nothing matched
        token = new_secret("grr")
        now = self.clock.now()
        rid = new_id("rcv")
        contacts = self._contacts(uid) if uid else []
        with self.db.tx() as c:
            c.execute("INSERT INTO recoveries (id, token_hash, user_id, new_mobile_hash, new_mobile_enc, "
                      "new_mobile_masked, needed, status, created_at, expires_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
                      (rid, secret_hash(token), uid, new_h, encrypt_mobile(new_mobile), mask_mobile(new_mobile),
                       self._vouches_needed(len(contacts)), "pending", iso(now),
                       iso(now + timedelta(hours=RECOVERY_TTL_HOURS))))
            if uid:
                name = self._name(uid)
                self._audit(c, "recovery", "recovery.started", uid, recovery_id=rid,
                            new_mobile=mask_mobile(new_mobile), contacts=len(contacts))
                self._alert(c, contacts, "recovery_requested", "Account recovery request",
                            f"Someone is trying to recover {name}'s account on a new number "
                            f"{mask_mobile(new_mobile)}. Only approve if you have spoken to {name} yourself, on a call "
                            "YOU placed or in person. If in doubt, deny.", uid, recovery_id=rid)
                self._alert(c, [uid], "recovery_requested_self", "Someone is recovering your account",
                            f"A recovery to the number {mask_mobile(new_mobile)} was started. If this isn't you, "
                            "cancel it here.", uid, recovery_id=rid)
        return {"recovery_token": token, "status": "pending", "expires_at": iso(now + timedelta(hours=RECOVERY_TTL_HOURS)),
                "note": "If an account matches, the people who know you have been asked to vouch. "
                        "A bank that verified you before can also vouch for you in person."}

    def recovery_status(self, token: str) -> dict:
        """For the person recovering. Says nothing about contacts, so it reveals nothing."""
        self.sweep_recovery()
        r = self.db.one("SELECT * FROM recoveries WHERE token_hash=?", (secret_hash(token or ""),))
        if not r:
            raise NotFound("recovery not found")
        status = r["status"]
        if r["user_id"] is None and status == "pending" and r["expires_at"] <= self._now():
            status = "expired"
        return {"status": status, "expires_at": r["expires_at"], "effective_at": r["effective_at"]}

    # ------------------------------------------------------------- people who know them
    def recoveries_to_vouch(self, voucher_id: str) -> list[dict]:
        self.sweep_recovery()
        rows = self.db.all("SELECT * FROM recoveries WHERE status IN ('pending','held') AND user_id IS NOT NULL "
                           "ORDER BY created_at")
        return [self._recovery_view(r, voucher_id) for r in rows if voucher_id in self._contacts(r["user_id"])]

    def vouch_recovery(self, voucher_id: str, rid: str, approve: bool) -> dict:
        self.sweep_recovery()
        r = self._recovery(rid)
        if voucher_id not in self._contacts(r["user_id"]):
            raise Forbidden("only this person's guardians, or people they guard, can vouch")
        if r["status"] not in OPEN:
            raise Conflict(f"recovery is already {r['status']}")
        if approve and r["status"] != "pending":
            raise Conflict("recovery already has enough vouches")
        name, me = self._name(r["user_id"]), self._name(voucher_id)
        with self.db.tx() as c:
            c.execute("INSERT INTO recovery_vouches (recovery_id, voucher_id, vote, at) VALUES (?,?,?,?) "
                      "ON CONFLICT(recovery_id, voucher_id) DO UPDATE SET vote=excluded.vote, at=excluded.at",
                      (rid, voucher_id, "approve" if approve else "deny", self._now()))
            self._audit(c, voucher_id, "recovery.vouched" if approve else "recovery.denied", r["user_id"],
                        recovery_id=rid)
            if not approve:
                self._end_recovery(c, r, "denied", voucher_id,
                                   f"{me} stopped the attempt to recover {name}'s account.")
            else:
                n = c.execute("SELECT COUNT(*) n FROM recovery_vouches WHERE recovery_id=? AND vote='approve'",
                              (rid,)).fetchone()["n"]
                if r["needed"] and n >= r["needed"]:
                    self._hold_recovery(c, r, f"{n} people who know {name} vouched")
        return self._recovery_view(self._recovery(rid), voucher_id)

    def cancel_recovery(self, user_id: str, rid: str) -> dict:
        """The owner, from any session still alive, says 'that isn't me'."""
        r = self._recovery(rid)
        if r["user_id"] != user_id:
            raise NotFound("recovery not found")
        if r["status"] not in OPEN:
            raise Conflict(f"recovery is already {r['status']}")
        with self.db.tx() as c:
            self._audit(c, user_id, "recovery.cancelled", user_id, recovery_id=rid)
            self._end_recovery(c, r, "cancelled", user_id,
                               f"{self._name(user_id)} cancelled the attempt to recover their account.")
        return self._recovery_view(self._recovery(rid))

    def my_recoveries(self, user_id: str) -> list[dict]:
        rows = self.db.all("SELECT * FROM recoveries WHERE user_id=? ORDER BY created_at DESC", (user_id,))
        return [self._recovery_view(r) for r in rows]

    # ------------------------------------------------------------- bank
    def bank_vouch_recovery(self, participant_id: str, new_mobile: str, customer_ref: str) -> dict:
        """A bank that KYC'd this person before has seen them (branch, video KYC) and vouches.
        The customer id must match one the bank used in an earlier attestation."""
        self._require_participant(participant_id, "kyc_full")
        try:
            new_h = mobile_hash(new_mobile)
        except ValueError as e:
            raise Invalid(str(e)) from None
        ref_h = _ref_hash(participant_id, (customer_ref or "").strip())
        rows = self.db.all("SELECT * FROM recoveries WHERE new_mobile_hash=? AND status='pending' "
                           "AND user_id IS NOT NULL AND expires_at>?", (new_h, self._now()))
        r = next((r for r in rows if self.db.one(
            "SELECT 1 FROM kyc_attestations WHERE user_id=? AND participant_id=? AND customer_ref_hash=? "
            "AND status IN ('active','expired','superseded')", (r["user_id"], participant_id, ref_h))), None)
        if not r:
            raise NotFound("no pending recovery for that number matches a customer you verified before")
        with self.db.tx() as c:
            c.execute("UPDATE recoveries SET bank_vouched_by=? WHERE id=?", (participant_id, r["id"]))
            self._audit(c, participant_id, "recovery.bank_vouched", r["user_id"], recovery_id=r["id"])
            bank = c.execute("SELECT name FROM participants WHERE id=?", (participant_id,)).fetchone()["name"]
            self._hold_recovery(c, r, f"{bank} confirmed who they are")
        return {"recovery": "held", "effective_at": self._recovery(r["id"])["effective_at"]}

    # ------------------------------------------------------------- state changes
    def _hold_recovery(self, c: sqlite3.Connection, r: sqlite3.Row, why: str) -> None:
        eff = iso(self.clock.now() + timedelta(hours=RECOVERY_HOLD_HOURS))
        c.execute("UPDATE recoveries SET status='held', effective_at=? WHERE id=?", (eff, r["id"]))
        self._audit(c, "recovery", "recovery.held", r["user_id"], recovery_id=r["id"], effective_at=eff)
        name = self._name(r["user_id"])
        self._alert(c, self._contacts(r["user_id"]), "recovery_held", "Account recovery will complete",
                    f"{why}. {name}'s account moves to {r['new_mobile_masked']} at {eff} unless someone stops it.",
                    r["user_id"], recovery_id=r["id"])
        self._alert(c, [r["user_id"]], "recovery_held_self", "Your account is being recovered",
                    f"Your account moves to {r['new_mobile_masked']} at {eff}. If this isn't you, cancel it now.",
                    r["user_id"], recovery_id=r["id"])

    def _end_recovery(self, c: sqlite3.Connection, r: sqlite3.Row, status: str, by: str, msg: str) -> None:
        c.execute("UPDATE recoveries SET status=?, decided_at=?, ended_by=? WHERE id=?",
                  (status, self._now(), by, r["id"]))
        self._alert(c, [r["user_id"], *self._contacts(r["user_id"])], "recovery_stopped", "Account recovery stopped",
                    msg, r["user_id"], recovery_id=r["id"])

    def _complete_recovery(self, c: sqlite3.Connection, r: sqlite3.Row) -> None:
        uid = r["user_id"]
        u = c.execute("SELECT number_status FROM users WHERE id=?", (uid,)).fetchone()
        taken = c.execute("SELECT 1 FROM users WHERE mobile_hash=?", (r["new_mobile_hash"],)).fetchone()
        if u["number_status"] != "disconnected" or taken:
            c.execute("UPDATE recoveries SET status='cancelled', decided_at=?, ended_by='system' WHERE id=?",
                      (self._now(), r["id"]))
            self._audit(c, "system", "recovery.void", uid, recovery_id=r["id"],
                        reason="number already restored" if not taken else "new number enrolled by someone else")
            return
        now = self._now()
        c.execute("UPDATE users SET mobile_hash=?, mobile_enc=?, number_status='active', mobile_since=?, "
                  "number_detached_at=NULL WHERE id=?", (r["new_mobile_hash"], r["new_mobile_enc"], now, uid))
        n = c.execute("UPDATE sessions SET revoked_at=? WHERE user_id=? AND revoked_at IS NULL", (now, uid)).rowcount
        c.execute("UPDATE devices SET trusted_at=? WHERE user_id=?",  # every old device must re-earn trust
                  (iso(self.clock.now() + timedelta(hours=24)), uid))
        c.execute("DELETE FROM sim_lookups WHERE user_id=?", (uid,))
        c.execute("UPDATE recoveries SET status='completed', decided_at=? WHERE id=?", (now, r["id"]))
        self._audit(c, "recovery", "recovery.completed", uid, recovery_id=r["id"],
                    new_mobile=r["new_mobile_masked"], sessions_revoked=n)
        name = self._name(uid)
        self._alert(c, [uid], "recovery_completed", "Account recovered",
                    f"Your account now uses {r['new_mobile_masked']}. Sign in with it to continue.", uid)
        self._alert(c, self._contacts(uid), "recovery_completed", "Account recovered",
                    f"{name}'s account now uses {r['new_mobile_masked']}.", uid)

    def sweep_recovery(self) -> int:
        now = self._now()
        expired = self.db.all("SELECT * FROM recoveries WHERE status='pending' AND expires_at<=?", (now,))
        due = self.db.all("SELECT * FROM recoveries WHERE status='held' AND effective_at<=?", (now,))
        if not (expired or due):
            return 0
        with self.db.tx() as c:
            for r in expired:
                c.execute("UPDATE recoveries SET status='expired', decided_at=? WHERE id=?", (now, r["id"]))
                if r["user_id"]:
                    self._audit(c, "system", "recovery.expired", r["user_id"], recovery_id=r["id"])
            for r in due:
                self._complete_recovery(c, r)
        return len(expired) + len(due)
