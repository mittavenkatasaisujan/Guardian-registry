"""People's rights over their data (India's Digital Personal Data Protection Act, 2023).

  * Notice and consent. GET /v1/privacy/notice says what is collected, why, for how long,
    and who the grievance officer is (GR_GRIEVANCE_CONTACT). Accepting it is recorded per
    notice version (POST /v1/me/consents); a new version asks again. GET /v1/me/consents
    lists what the person agreed to and when.
  * Access. GET /v1/me/data-export returns everything the registry holds about the person,
    readable, in one JSON document: profile and number, rules, guardians and wards, payment
    checks, alerts, devices, sign-in sessions, identity claims (with the date of birth, which
    is theirs to see), SIM events, recoveries, consents and their audit trail.
  * Erasure. POST /v1/me/erasure asks to delete the account. It is HELD for ERASURE_HOLD_DAYS,
    guardians are told and the person can cancel: a scammer coaching someone to "delete the
    app account" must not be able to strip their protection in one tap, the same reason
    loosening rules is held. Afterwards the account is erased: number (hash and encrypted
    copy), name, push tokens, device keys, sessions, OTPs, devices, alerts, rules and trusted
    payees are deleted or blanked; guardianships end; identity claims are ended and their
    dates of birth deleted. What stays, and why, is listed in RETAINED: payment check records
    (banks' legal record-keeping) and the audit chain (tamper evidence; it holds ids and
    events, not numbers or names).
  * Retention. The worker deletes delivered alerts after GR_RETENTION_ALERT_DAYS (180),
    ended sessions after GR_RETENTION_SESSION_DAYS (90) and used sign-in challenges.

These cover the mechanics. A data-protection review of the notice text, the retention
periods and the lawful basis for each purpose is a legal task (see README: Still open).
"""

from __future__ import annotations

import json
import os
from datetime import timedelta

from . import notify
from .clock import iso
from .errors import Conflict, Invalid, NotFound
from .security import _fernet, decrypt_mobile, new_id

NOTICE_VERSION = "2026-11-23"
ERASURE_HOLD_DAYS = 7

NOTICE = {
    "version": NOTICE_VERSION,
    "controller": "Guardian Registry",
    "what_we_collect": [
        "your mobile number (stored as a keyed hash for lookups, and encrypted only to send you codes and alerts)",
        "the name you give, your protection rules, your guardians and the people you protect",
        "payment checks banks ask us to make for your account (amount, payee, time, decision)",
        "device and app details needed to recognise your phone (a public key, an app-install id)",
        "identity confirmations from your bank, if you approve them (KYC level; date of birth only if your "
        "bank shares it, used only to tell banks whether you are 70 or over)",
    ],
    "why": [
        "to hold payments for your guardian's approval and apply your rules, across all banks",
        "to alert you and your guardians",
        "to protect you from SIM-swap and account-takeover fraud",
    ],
    "who_sees_it": [
        "your guardians see your rules and payments; banks see only the decision for the payment they asked "
        "about, never who your guardians are",
    ],
    "how_long": [
        "while your account exists; alerts are deleted after 180 days and old sign-ins after 90",
        "payment check records and the tamper-evident audit trail are kept after an account is erased, "
        "as banks' records require, without your number or name",
    ],
    "your_rights": [
        "see everything we hold about you (data export)",
        "correct your name and rules in the app",
        "erase your account (held 7 days so nobody can pressure you into removing your protection at once)",
        "complain to our grievance officer, and then to the Data Protection Board of India",
    ],
}

RETAINED = {
    "checks": "payment check records: banks' legal record-keeping; no number or name is stored in them",
    "audit_log": "tamper-evident audit chain: ids and events only; deleting rows would break the chain",
}


def grievance_contact() -> str:
    return os.environ.get("GR_GRIEVANCE_CONTACT", "not configured: set GR_GRIEVANCE_CONTACT")


class PrivacyMixin:
    """Mixed into Registry."""

    # ------------------------------------------------------------- notice and consent
    def privacy_notice(self) -> dict:
        return {**NOTICE, "grievance_officer": grievance_contact(), "erasure_hold_days": ERASURE_HOLD_DAYS}

    def record_consent(self, uid: str, version: str) -> dict:
        if version != NOTICE_VERSION:
            raise Invalid(f"the current notice is version {NOTICE_VERSION}; read it and accept that version")
        with self.db.tx(uid) as c:
            if not c.execute("SELECT 1 FROM consents WHERE user_id=? AND notice_version=?", (uid, version)).fetchone():
                c.execute("INSERT INTO consents (id, user_id, notice_version, accepted_at) VALUES (?,?,?,?)",
                          (new_id("cns"), uid, version, self._now()))
                self._audit(c, uid, "privacy.consent_recorded", uid, notice_version=version)
        return self.consents(uid)

    def consents(self, uid: str) -> dict:
        rows = self.db.all("SELECT notice_version, accepted_at FROM consents WHERE user_id=? ORDER BY accepted_at",
                           (uid,))
        return {"current_version": NOTICE_VERSION, "accepted_current": any(r["notice_version"] == NOTICE_VERSION
                                                                           for r in rows),
                "accepted": [dict(r) for r in rows]}

    # ------------------------------------------------------------- access
    def data_export(self, uid: str) -> dict:
        u = self._user(uid)

        def rows(sql, *args):
            return [dict(r) for r in self.db.all(sql, args)]

        dobs = []
        for r in rows("SELECT * FROM kyc_attestations WHERE user_id=?", uid):
            if r.get("dob_enc"):
                r["date_of_birth"] = _fernet().decrypt(r["dob_enc"].encode()).decode()
            r.pop("dob_enc", None)
            r.pop("customer_ref_hash", None)
            dobs.append(r)
        audit_rows = rows("SELECT seq, ts, actor, action, data FROM audit_log WHERE principal_id=? ORDER BY seq", uid)
        for a in audit_rows:
            a["data"] = json.loads(a["data"])
        return {
            "exported_at": self._now(),
            "notice_version": NOTICE_VERSION,
            "profile": {"id": u["id"], "display_name": u["display_name"], "enrolled_at": u["created_at"],
                        "mobile": decrypt_mobile(u["mobile_enc"]) if u["mobile_enc"] else None,
                        "number_status": u["number_status"], "urgent_channel": u["urgent_channel"]},
            "rules": self.get_rules(uid).to_dict(),
            "trusted_payees": rows("SELECT * FROM trusted_payees WHERE principal_id=?", uid),
            "my_guardians": rows("SELECT g.id, g.status, g.invited_at, g.accepted_at, g.ended_at, u.display_name AS guardian "
                                 "FROM guardianships g JOIN users u ON u.id=g.guardian_id WHERE g.principal_id=?", uid),
            "people_i_protect": rows("SELECT g.id, g.status, g.invited_at, g.accepted_at, g.ended_at, u.display_name AS person "
                                     "FROM guardianships g JOIN users u ON u.id=g.principal_id WHERE g.guardian_id=?", uid),
            "payment_checks": rows("SELECT c.id, p.name AS bank, c.amount, c.payee, c.channel, c.status, c.reasons, "
                                   "c.created_at, c.decided_at, c.completed_at FROM checks c "
                                   "JOIN participants p ON p.id=c.participant_id WHERE c.principal_id=? "
                                   "ORDER BY c.created_at", uid),
            "pending_changes": rows("SELECT id, kind, status, created_at, effective_at FROM pending_changes "
                                    "WHERE principal_id=?", uid),
            "alerts": rows("SELECT kind, channel, title, body, status, created_at, sent_at, read_at FROM notifications "
                           "WHERE recipient_type='user' AND recipient_id=? ORDER BY created_at", uid),
            "devices": rows("SELECT first_seen, last_seen, trusted_at FROM devices WHERE user_id=?", uid),
            "device_keys": self.device_keys(uid),
            "push_devices": [{"platform": r["platform"], "added": r["created_at"]}
                             for r in self.db.all("SELECT platform, created_at FROM push_tokens WHERE user_id=?", (uid,))],
            "sessions": rows("SELECT created_at, expires_at, revoked_at, probation_until FROM sessions WHERE user_id=?",
                             uid),
            "identity_claims": dobs,
            "sim_events": rows("SELECT source, changed_at, created_at, window_ends_at, cleared_at FROM sim_events "
                               "WHERE user_id=?", uid),
            "recoveries": rows("SELECT id, new_mobile_masked, status, created_at, decided_at FROM recoveries "
                               "WHERE user_id=?", uid),
            "consents": self.consents(uid)["accepted"],
            "erasure": self._erasure_view(uid),
            "audit_trail": audit_rows,
        }

    # ------------------------------------------------------------- erasure
    def _erasure_view(self, uid: str) -> dict | None:
        r = self.db.one("SELECT * FROM erasure_requests WHERE user_id=? ORDER BY requested_at DESC LIMIT 1", (uid,))
        return None if not r else {"id": r["id"], "status": r["status"], "requested_at": r["requested_at"],
                                   "erase_at": r["erase_at"], "decided_at": r["decided_at"]}

    def request_erasure(self, uid: str) -> dict:
        now = self.clock.now()
        erase_at = iso(now + timedelta(days=ERASURE_HOLD_DAYS))
        with self.db.tx(uid) as c:
            if c.execute("SELECT 1 FROM erasure_requests WHERE user_id=? AND status='pending'", (uid,)).fetchone():
                raise Conflict("an erasure is already waiting; cancel it or wait")
            eid = new_id("era")
            c.execute("INSERT INTO erasure_requests (id, user_id, status, requested_at, erase_at) VALUES (?,?,?,?,?)",
                      (eid, uid, "pending", iso(now), erase_at))
            self._audit(c, uid, "privacy.erasure_requested", uid, erase_at=erase_at)
            self._alert(c, [uid], "erasure_requested", "Account deletion requested",
                        f"Your Guardian Registry account will be deleted on {erase_at[:10]}, and your guardians "
                        "will stop protecting your payments. If you didn't ask for this, or someone told you to, "
                        "cancel it in the app.", uid)
            self._alert_guardians(c, uid, "erasure_requested", "Protection ending",
                                  f"{self._user(uid)['display_name']} asked to delete their account on "
                                  f"{erase_at[:10]}. If someone may be pressuring them, call them now.")
        return self._erasure_view(uid)

    def cancel_erasure(self, uid: str) -> dict:
        with self.db.tx(uid) as c:
            if not c.execute("UPDATE erasure_requests SET status='cancelled', decided_at=? WHERE user_id=? "
                             "AND status='pending'", (self._now(), uid)).rowcount:
                raise NotFound("no erasure is waiting")
            self._audit(c, uid, "privacy.erasure_cancelled", uid)
        return self._erasure_view(uid)

    def sweep_erasure(self) -> int:
        due = self.db.all("SELECT id, user_id FROM erasure_requests WHERE status='pending' AND erase_at<=?",
                          (self._now(),))
        done = 0
        for r in due:
            with self.db.tx() as c:  # global: touches the person, their guardians' and wards' links
                if not c.execute("UPDATE erasure_requests SET status='completed', decided_at=? WHERE id=? "
                                 "AND status='pending'", (self._now(), r["id"])).rowcount:
                    continue  # cancelled meanwhile, or another node did it
                self._erase(c, r["user_id"])
                done += 1
        return done

    def _erase(self, c, uid: str) -> None:
        now = self._now()
        c.execute("UPDATE users SET mobile_hash=?, mobile_enc=NULL, prev_mobile_hash=NULL, display_name='Erased user', "
                  "number_status='erased', erased_at=? WHERE id=?", (f"erased:{uid}", now, uid))
        c.execute("UPDATE guardianships SET status='ended', ended_at=? WHERE (principal_id=? OR guardian_id=?) "
                  "AND status IN ('invited','active')", (now, uid, uid))
        c.execute("UPDATE kyc_attestations SET dob_enc=NULL, status=CASE WHEN status IN ('pending_consent','active') "
                  "THEN 'withdrawn' ELSE status END, decided_at=COALESCE(decided_at, ?), "
                  "ended_by=COALESCE(ended_by, 'erasure') WHERE user_id=?", (now, uid))
        c.execute("UPDATE checks SET payee='(erased)' WHERE principal_id=? AND status NOT IN "
                  "('cooling_off','pending_approval')", (uid,))
        c.execute("UPDATE recoveries SET new_mobile_enc='', new_mobile_masked='(erased)' WHERE user_id=?", (uid,))
        for table, col in (("sessions", "user_id"), ("push_tokens", "user_id"), ("device_keys", "user_id"),
                           ("devices", "user_id"), ("trusted_payees", "principal_id"), ("consents", "user_id"),
                           ("sim_events", "user_id")):
            c.execute(f"DELETE FROM {table} WHERE {col}=?", (uid,))
        c.execute("DELETE FROM notifications WHERE recipient_type='user' AND recipient_id=?", (uid,))
        c.execute("UPDATE pending_changes SET status='cancelled' WHERE principal_id=? AND status='pending'", (uid,))
        self._audit(c, "system:privacy", "privacy.erased", uid, retained=sorted(RETAINED))

    # ------------------------------------------------------------- retention
    def sweep_retention(self) -> dict:
        now = self.clock.now()
        alert_days = int(os.environ.get("GR_RETENTION_ALERT_DAYS", "180"))
        session_days = int(os.environ.get("GR_RETENTION_SESSION_DAYS", "90"))
        out = {}
        with self.db.tx(shared=True) as c:  # old rows only: no person's live state changes
            n = c.execute("DELETE FROM notifications WHERE status IN ('sent','skipped','failed') AND created_at<?",
                          (iso(now - timedelta(days=alert_days)),)).rowcount
            if n:
                out["alerts"] = n
            n = c.execute("DELETE FROM sessions WHERE (revoked_at IS NOT NULL AND revoked_at<?) OR expires_at<?",
                          (iso(now - timedelta(days=session_days)), iso(now - timedelta(days=session_days)))).rowcount
            if n:
                out["sessions"] = n
        return out


__all__ = ["PrivacyMixin", "NOTICE_VERSION", "ERASURE_HOLD_DAYS", "RETAINED", "notify"]
