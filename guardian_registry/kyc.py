"""Bank-vouched identity (KYC attestations).

An SMS code only proves someone holds a phone number. Banks have already done KYC on
their customers, so a participant bank can attest: "this registry user is our customer,
KYC'd to <level> on <date>", optionally with the date of birth from its KYC record.

Rules:
  * Consent first. An attestation counts only after the person approves it in the app.
    Without a response it lapses after KYC_CONSENT_DAYS. The person can withdraw it at
    any time, and the bank can revoke it (for example, the account was closed).
  * Data minimisation. The bank's customer id is stored only as a keyed hash, and the
    date of birth only encrypted. The registry never hands the date of birth to anyone:
    banks get a yes/no `senior` flag, and the person sees their own record.
  * Freshness. An approved attestation lasts KYC_VALID_DAYS (re-confirm yearly). A new
    attestation from the same bank replaces the old one once approved.
  * Disagreement is a signal, not a guess. If two banks report different dates of birth,
    `senior` becomes unknown (None) and the person is told.

What it unlocks:
  * identity level: 'bank_verified' (any active full-KYC attestation), 'bank_min_kyc', or 'otp'
  * `senior` (aged SENIOR_AGE or over) in every bank check response, so banks can apply
    RBI's proposed trusted-person check for people aged 70+ without each re-collecting age
  * the rule `require_verified_guardian`: only bank-verified guardians may approve payments
"""

from __future__ import annotations

import hashlib
import hmac
import sqlite3
from datetime import date, timedelta

from . import notify
from .clock import IST, iso
from .errors import Conflict, Invalid, NotFound
from .security import _fernet, new_id, normalize_mobile, pepper  # one key protects every encrypted field

KYC_LEVELS = ("full", "minimum")
KYC_CONSENT_DAYS = 7
KYC_VALID_DAYS = 365
KYC_MAX_AGE_OF_VERIFICATION_DAYS = 10 * 365  # refuse KYC records older than this
SENIOR_AGE = 70

LIVE = ("pending_consent", "active")


def _ref_hash(participant_id: str, customer_ref: str) -> str:
    return hmac.new(pepper(), f"{participant_id}:{customer_ref}".encode(), hashlib.sha256).hexdigest()


def _parse_date(value: str, field: str) -> date:
    try:
        return date.fromisoformat(value)
    except (TypeError, ValueError):
        raise Invalid(f"{field} must be a date like 1951-04-23") from None


def age_on(dob: date, today: date) -> int:
    return today.year - dob.year - ((today.month, today.day) < (dob.month, dob.day))


class KycMixin:
    """Mixed into Registry. Uses its db, clock, _audit, _alert and _name helpers."""

    # ------------------------------------------------------------- helpers
    def _today(self) -> date:
        return self.clock.now().astimezone(IST).date()

    def _kyc_view(self, r: sqlite3.Row, for_participant: bool) -> dict:
        view = {
            "attestation_id": r["id"], "kyc_level": r["kyc_level"], "status": r["status"],
            "verified_on": r["verified_on"], "created_at": r["created_at"],
            "consent_expires_at": r["consent_expires_at"], "expires_at": r["expires_at"],
            "decided_at": r["decided_at"], "includes_date_of_birth": r["dob_enc"] is not None,
        }
        if not for_participant:
            bank = self.db.one("SELECT name FROM participants WHERE id=?", (r["participant_id"],))
            view["bank"] = bank["name"] if bank else None
        return view

    def _kyc_row(self, aid: str) -> sqlite3.Row:
        r = self.db.one("SELECT * FROM kyc_attestations WHERE id=?", (aid,))
        if not r:
            raise NotFound("attestation not found")
        return r

    def _kyc_webhook(self, c: sqlite3.Connection, r_id: str) -> None:
        r = c.execute("SELECT * FROM kyc_attestations WHERE id=?", (r_id,)).fetchone()
        notify.enqueue_participant(c, self._now(), r["participant_id"], "kyc.updated",
                                   {"attestation": self._kyc_view(r, for_participant=True)}, r["user_id"])

    def _active_attestations(self, user_id: str) -> list[sqlite3.Row]:
        # claims from a suspended participant don't count until it is reinstated
        return self.db.all("SELECT k.* FROM kyc_attestations k JOIN participants p ON p.id=k.participant_id "
                           "WHERE k.user_id=? AND k.status='active' AND k.expires_at>? AND p.status='active'",
                           (user_id, self._now()))

    # ------------------------------------------------------------- facts
    def identity_level(self, user_id: str) -> str:
        levels = {r["kyc_level"] for r in self._active_attestations(user_id)}
        if "full" in levels:
            return "bank_verified"
        if "minimum" in levels:
            return "bank_min_kyc"
        return "otp"

    def age_facts(self, user_id: str) -> dict:
        """{'senior': True/False/None, 'dob_conflict': bool}. None means unknown."""
        dobs = {_fernet().decrypt(r["dob_enc"].encode()).decode()
                for r in self._active_attestations(user_id) if r["dob_enc"]}
        if not dobs:
            return {"senior": None, "dob_conflict": False}
        if len(dobs) > 1:
            return {"senior": None, "dob_conflict": True}
        return {"senior": age_on(date.fromisoformat(dobs.pop()), self._today()) >= SENIOR_AGE,
                "dob_conflict": False}

    def identity(self, user_id: str) -> dict:
        """The person's own view: their level, age facts, and every attestation."""
        rows = self.db.all("SELECT * FROM kyc_attestations WHERE user_id=? ORDER BY created_at DESC", (user_id,))
        facts = self.age_facts(user_id)
        out = {"level": self.identity_level(user_id), **facts,
               "attestations": [self._kyc_view(r, for_participant=False) for r in rows]}
        if facts["senior"] and self._rules_raw(user_id).approval_threshold is None:
            out["suggested_preset"] = "senior_with_guardian"
        return out

    # ------------------------------------------------------------- bank side
    def attest(self, participant_id: str, mobile: str, kyc_level: str, customer_ref: str,
               verified_on: str, date_of_birth: str | None = None) -> dict:
        if kyc_level not in KYC_LEVELS:
            raise Invalid(f"kyc_level must be one of {list(KYC_LEVELS)}")
        self._require_participant(participant_id, f"kyc_{kyc_level}")
        customer_ref = (customer_ref or "").strip()
        if not customer_ref or len(customer_ref) > 100:
            raise Invalid("customer_ref is required (max 100 characters)")
        today = self._today()
        vdate = _parse_date(verified_on, "verified_on")
        if vdate > today:
            raise Invalid("verified_on cannot be in the future")
        if (today - vdate).days > KYC_MAX_AGE_OF_VERIFICATION_DAYS:
            raise Invalid("KYC record is too old; re-verify the customer first")
        dob_enc = None
        if date_of_birth is not None:
            dob = _parse_date(date_of_birth, "date_of_birth")
            if dob > today or age_on(dob, today) > 120:
                raise Invalid("date_of_birth is not plausible")
            dob_enc = _fernet().encrypt(dob.isoformat().encode()).decode()
        try:
            normalize_mobile(mobile)
        except ValueError as e:
            raise Invalid(str(e)) from None
        uid = self.user_by_mobile(mobile)
        if not uid:
            raise NotFound("customer is not enrolled in the registry")

        now = self.clock.now()
        aid = new_id("kyc")
        with self.db.tx() as c:
            # a newer pending claim from the same bank replaces an older pending one
            c.execute("UPDATE kyc_attestations SET status='superseded', decided_at=? "
                      "WHERE user_id=? AND participant_id=? AND status='pending_consent'",
                      (iso(now), uid, participant_id))
            c.execute(
                "INSERT INTO kyc_attestations (id, user_id, participant_id, kyc_level, dob_enc, customer_ref_hash, "
                "verified_on, status, created_at, consent_expires_at, expires_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (aid, uid, participant_id, kyc_level, dob_enc, _ref_hash(participant_id, customer_ref),
                 vdate.isoformat(), "pending_consent", iso(now), iso(now + timedelta(days=KYC_CONSENT_DAYS)),
                 iso(now + timedelta(days=KYC_VALID_DAYS))))
            self._audit(c, participant_id, "kyc.attested", uid, attestation_id=aid, kyc_level=kyc_level,
                        includes_date_of_birth=dob_enc is not None)  # never the DOB itself
            bank = c.execute("SELECT name FROM participants WHERE id=?", (participant_id,)).fetchone()["name"]
            shares = " and your date of birth (used only to tell banks if you are 70 or over)" if dob_enc else ""
            self._alert(c, [uid], "kyc_consent_needed", "Confirm your identity?",
                        f"{bank} wants to confirm to Guardian Registry that you are their KYC-verified customer{shares}. "
                        "Approve only if you bank with them.", uid, attestation_id=aid)
        return self._kyc_view(self._kyc_row(aid), for_participant=True)

    def bank_attestation(self, participant_id: str, aid: str) -> dict:
        self._require_participant(participant_id, allow_suspended=True)
        r = self._kyc_row(aid)
        if r["participant_id"] != participant_id:
            raise NotFound("attestation not found")
        return self._kyc_view(r, for_participant=True)

    def revoke_attestation(self, participant_id: str, aid: str) -> dict:
        """The bank withdraws its claim, for example when the account is closed or KYC is in doubt."""
        self._require_participant(participant_id, allow_suspended=True)
        r = self._kyc_row(aid)
        if r["participant_id"] != participant_id:
            raise NotFound("attestation not found")
        if r["status"] not in LIVE:
            raise Conflict(f"attestation is already {r['status']}")
        with self.db.tx() as c:
            c.execute("UPDATE kyc_attestations SET status='revoked', decided_at=?, ended_by=? WHERE id=?",
                      (self._now(), participant_id, aid))
            self._audit(c, participant_id, "kyc.revoked", r["user_id"], attestation_id=aid)
            bank = c.execute("SELECT name FROM participants WHERE id=?", (participant_id,)).fetchone()["name"]
            self._alert(c, [r["user_id"]], "kyc_revoked", "Bank verification removed",
                        f"{bank} withdrew its identity confirmation.", r["user_id"], attestation_id=aid)
        return self._kyc_view(self._kyc_row(aid), for_participant=True)

    # ------------------------------------------------------------- person side
    def _own_attestation(self, user_id: str, aid: str) -> sqlite3.Row:
        r = self._kyc_row(aid)
        if r["user_id"] != user_id:
            raise NotFound("attestation not found")
        return r

    def respond_to_attestation(self, user_id: str, aid: str, approve: bool) -> dict:
        self.sweep_kyc()
        r = self._own_attestation(user_id, aid)
        if r["status"] != "pending_consent":
            raise Conflict(f"attestation is already {r['status']}")
        with self.db.tx() as c:
            if approve:
                c.execute("UPDATE kyc_attestations SET status='superseded', decided_at=? "
                          "WHERE user_id=? AND participant_id=? AND status='active'",
                          (self._now(), user_id, r["participant_id"]))
            c.execute("UPDATE kyc_attestations SET status=?, decided_at=? WHERE id=?",
                      ("active" if approve else "rejected", self._now(), aid))
            self._audit(c, user_id, "kyc.approved" if approve else "kyc.rejected", user_id, attestation_id=aid)
            self._kyc_webhook(c, aid)
        after = self.identity(user_id)
        if after["dob_conflict"]:
            with self.db.tx() as c:
                self._alert(c, [user_id], "kyc_dob_conflict", "Banks disagree on your date of birth",
                            "Two banks reported different dates of birth, so we can't confirm your age. "
                            "Ask one of them to correct their record.", user_id)
        return self._kyc_view(self._kyc_row(aid), for_participant=False)

    def withdraw_attestation(self, user_id: str, aid: str) -> dict:
        r = self._own_attestation(user_id, aid)
        if r["status"] not in LIVE:
            raise Conflict(f"attestation is already {r['status']}")
        with self.db.tx() as c:
            c.execute("UPDATE kyc_attestations SET status='withdrawn', decided_at=?, ended_by=? WHERE id=?",
                      (self._now(), user_id, aid))
            self._audit(c, user_id, "kyc.withdrawn", user_id, attestation_id=aid)
            self._kyc_webhook(c, aid)
        return self._kyc_view(self._kyc_row(aid), for_participant=False)

    # ------------------------------------------------------------- time
    def sweep_kyc(self) -> int:
        """Lapse unanswered requests and expire stale attestations (with an alert to re-confirm)."""
        now = self._now()
        changed = 0
        lapsed = self.db.all("SELECT id FROM kyc_attestations WHERE status='pending_consent' AND consent_expires_at<=?",
                             (now,))
        expired = self.db.all("SELECT id, user_id FROM kyc_attestations WHERE status='active' AND expires_at<=?", (now,))
        if lapsed or expired:
            with self.db.tx() as c:
                for r in lapsed:
                    c.execute("UPDATE kyc_attestations SET status='lapsed', decided_at=? WHERE id=?", (now, r["id"]))
                    self._kyc_webhook(c, r["id"])
                for r in expired:
                    c.execute("UPDATE kyc_attestations SET status='expired', decided_at=? WHERE id=?", (now, r["id"]))
                    self._audit(c, "system", "kyc.expired", r["user_id"], attestation_id=r["id"])
                    self._alert(c, [r["user_id"]], "kyc_expired", "Bank verification expired",
                                "Your bank's identity confirmation is more than a year old. Ask your bank to "
                                "confirm it again.", r["user_id"], attestation_id=r["id"])
                    self._kyc_webhook(c, r["id"])
                changed = len(lapsed) + len(expired)
        return changed

