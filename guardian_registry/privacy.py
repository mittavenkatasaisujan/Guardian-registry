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
from .security import _fernet, decrypt_mobile, encrypt_mobile, new_id, normalize_mobile

NOTICE_VERSION = "2026-11-25"
ERASURE_HOLD_DAYS = 7
GRIEVANCE_DAYS = 90        # DPDP Rules 2025: complaints are answered within 90 days
MAX_OPEN_GRIEVANCES = 5

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
        "messaging services that carry codes and alerts to your phone (an SMS provider, Google or Apple for app "
        "notifications, and WhatsApp if you choose it) receive your number or app id and the message; some of "
        "them are outside India. Outside the app, alerts can be sent without payment details (see alert detail)",
    ],
    "who_can_use_it": ["adults (18 or older); a child's data needs a parent's verifiable consent, which this "
                       "service does not collect, so children must not enrol"],
    "how_long": [
        "while your account exists; alerts are deleted after 180 days and old sign-ins after 90",
        "payment check records and the tamper-evident audit trail are kept after an account is erased, "
        "as banks' records require, without your number or name",
    ],
    "your_rights": [
        "see everything we hold about you (data export)",
        "correct your name (Your details in the app) and your rules",
        "nominate someone to exercise these rights if you die or can't act yourself (Your details in the app)",
        "erase your account (held 7 days so nobody can pressure you into removing your protection at once)",
        "complain to our grievance officer, and then to the Data Protection Board of India",
    ],
}

# The same notice in Hindi (DPDP Act s.5(3): English or a language in the Eighth Schedule).
# Same version: the content is the same. Counsel should check the wording of both.
NOTICE_HI = {
    "version": NOTICE_VERSION,
    "controller": "Guardian Registry",
    "what_we_collect": [
        "आपका मोबाइल नंबर (खोजने के लिए एक कुंजी वाले हैश के रूप में, और केवल आपको कोड और सूचनाएँ भेजने के लिए "
        "एन्क्रिप्ट करके रखा जाता है)",
        "आपका दिया हुआ नाम, आपके सुरक्षा नियम, आपके गार्डियन और वे लोग जिनकी आप सुरक्षा करते हैं",
        "आपके खाते के लिए बैंकों के कहने पर की गई भुगतान जाँचें (राशि, प्राप्तकर्ता, समय, फ़ैसला)",
        "आपका फ़ोन पहचानने के लिए ज़रूरी डिवाइस और ऐप की जानकारी (एक सार्वजनिक कुंजी, ऐप इंस्टॉल की पहचान)",
        "आपकी मंज़ूरी से आपके बैंक की पहचान-पुष्टि (KYC स्तर; जन्मतिथि केवल तब जब आपका बैंक उसे साझा करे, और "
        "उसका उपयोग सिर्फ़ बैंकों को यह बताने के लिए कि आप 70 या उससे ज़्यादा उम्र के हैं)",
    ],
    "why": [
        "सभी बैंकों में आपके नियम लागू करने और भुगतानों को गार्डियन की मंज़ूरी के लिए रोकने के लिए",
        "आपको और आपके गार्डियन को सूचना देने के लिए",
        "सिम-बदलाव और खाते पर कब्ज़े वाली धोखाधड़ी से आपकी रक्षा के लिए",
    ],
    "who_sees_it": [
        "आपके गार्डियन आपके नियम और भुगतान देखते हैं; बैंक केवल उस भुगतान का फ़ैसला देखते हैं जिसके बारे में "
        "उन्होंने पूछा, यह कभी नहीं कि आपके गार्डियन कौन हैं",
        "आपके फ़ोन तक कोड और सूचनाएँ पहुँचाने वाली मैसेजिंग सेवाएँ (एक SMS सेवा, ऐप सूचनाओं के लिए Google या "
        "Apple, और आप चुनें तो WhatsApp) आपका नंबर या ऐप पहचान और संदेश पाती हैं; इनमें से कुछ भारत के बाहर "
        "हैं। ऐप के बाहर सूचनाएँ भुगतान के विवरण के बिना भेजी जा सकती हैं",
    ],
    "who_can_use_it": ["वयस्क (18 वर्ष या उससे ज़्यादा); बच्चे के डेटा के लिए माता-पिता की सत्यापन योग्य सहमति "
                       "चाहिए, जो यह सेवा नहीं लेती, इसलिए बच्चे पंजीकरण न करें"],
    "how_long": [
        "जब तक आपका खाता है; सूचनाएँ 180 दिन बाद और पुराने साइन-इन 90 दिन बाद हटा दिए जाते हैं",
        "खाता मिटाने के बाद भी भुगतान जाँच के रिकॉर्ड और छेड़छाड़-रोधी ऑडिट रिकॉर्ड, बैंकों के रिकॉर्ड की ज़रूरत "
        "के अनुसार, आपके नंबर या नाम के बिना रखे जाते हैं",
    ],
    "your_rights": [
        "हमारे पास आपकी जो भी जानकारी है, उसे देखना (डेटा निर्यात)",
        "अपना नाम (ऐप में 'आपकी जानकारी') और अपने नियम सुधारना",
        "किसी को नामित करना जो आपकी मृत्यु होने पर या आपके खुद कुछ न कर पाने पर ये अधिकार इस्तेमाल करे "
        "(ऐप में 'आपकी जानकारी')",
        "अपना खाता मिटाना (7 दिन रोका जाता है ताकि कोई आप पर दबाव डालकर तुरंत आपकी सुरक्षा न हटवा सके)",
        "हमारे शिकायत अधिकारी से शिकायत करना, और फिर भारतीय डेटा संरक्षण बोर्ड से",
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
    def privacy_notice(self, lang: str = "en") -> dict:
        """The notice in English, or in Hindi for lang "hi" (same version, same content)."""
        body = NOTICE_HI if lang == "hi" else NOTICE
        return {**body, "language": "hi" if lang == "hi" else "en",
                "grievance_officer": grievance_contact(), "erasure_hold_days": ERASURE_HOLD_DAYS}

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
    # ------------------------------------------------------------- correction and nomination
    def set_display_name(self, uid: str, name: str) -> dict:
        """DPDP Act s.12: correct your name."""
        name = (name or "").strip()
        if not 1 <= len(name) <= 80:
            raise Invalid("your name must be 1 to 80 characters")
        with self.db.tx(uid) as c:
            c.execute("UPDATE users SET display_name=? WHERE id=?", (name, uid))
            self._audit(c, uid, "privacy.name_corrected", uid)
        return {"display_name": name}

    def nominee(self, uid: str) -> dict | None:
        r = self.db.one("SELECT name, relation, mobile_enc, created_at FROM nominees WHERE user_id=?", (uid,))
        if not r:
            return None
        return {"name": r["name"], "relation": r["relation"], "mobile": decrypt_mobile(r["mobile_enc"]),
                "nominated_at": r["created_at"]}

    def set_nominee(self, uid: str, name: str, relation: str, mobile: str) -> dict:
        """DPDP Act s.14: someone who may exercise your data rights if you die or can't act. It gives
        them no access to the account and no say over payments; the grievance officer handles their
        requests after checking the death or incapacity."""
        name, relation = (name or "").strip(), (relation or "").strip()
        if not 1 <= len(name) <= 80 or not 1 <= len(relation) <= 40:
            raise Invalid("the nominee needs a name (up to 80 characters) and a relation (up to 40)")
        try:
            mobile = normalize_mobile(mobile)
        except ValueError:
            raise Invalid("the nominee's mobile must be a valid Indian mobile number") from None
        with self.db.tx(uid) as c:
            c.execute("INSERT INTO nominees (user_id, name, relation, mobile_enc, created_at) VALUES (?,?,?,?,?) "
                      "ON CONFLICT(user_id) DO UPDATE SET name=excluded.name, relation=excluded.relation, "
                      "mobile_enc=excluded.mobile_enc, created_at=excluded.created_at",
                      (uid, name, relation, encrypt_mobile(mobile), self._now()))
            self._audit(c, uid, "privacy.nominee_set", uid)
        return self.nominee(uid)

    def remove_nominee(self, uid: str) -> None:
        with self.db.tx(uid) as c:
            if c.execute("DELETE FROM nominees WHERE user_id=?", (uid,)).rowcount:
                self._audit(c, uid, "privacy.nominee_removed", uid)

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
                        "number_status": u["number_status"], "urgent_channel": u["urgent_channel"],
                        "adult_confirmed_at": u["adult_confirmed_at"]},
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
            "nominee": self.nominee(uid),
            "complaints": self.grievances(uid),
            "erasure": self._erasure_view(uid),
            "audit_trail": audit_rows,
        }

    # ------------------------------------------------------------- complaints (grievance redressal)
    def _grievance_view(self, r, operator: bool = False) -> dict:
        from .security import decrypt_text
        view = {"id": r["id"], "status": r["status"], "text": decrypt_text(r["text_enc"]),
                "created_at": r["created_at"], "due_at": r["due_at"],
                "answer": decrypt_text(r["answer_enc"]) if r["answer_enc"] else None,
                "answered_at": r["answered_at"]}
        if operator:
            view.update(user_id=r["user_id"], person_name=self._user(r["user_id"])["display_name"],
                        answered_by=r["answered_by"],
                        overdue=r["status"] == "open" and r["due_at"] < self._now())
        return view

    def raise_grievance(self, uid: str, text: str) -> dict:
        """DPDP Act s.13: a complaint to the grievance officer, answered in the app within 90 days."""
        from .security import encrypt_text
        text = (text or "").strip()
        if not 10 <= len(text) <= 2000:
            raise Invalid("write your complaint in 10 to 2000 characters")
        now = self.clock.now()
        with self.db.tx(uid) as c:
            n = c.execute("SELECT COUNT(*) n FROM grievances WHERE user_id=? AND status='open'", (uid,)).fetchone()["n"]
            if n >= MAX_OPEN_GRIEVANCES:
                raise Conflict("you already have 5 complaints waiting; we answer each within 90 days")
            gid = new_id("grv")
            c.execute("INSERT INTO grievances (id, user_id, text_enc, status, created_at, due_at) VALUES (?,?,?,?,?,?)",
                      (gid, uid, encrypt_text(text), "open", iso(now), iso(now + timedelta(days=GRIEVANCE_DAYS))))
            self._audit(c, uid, "privacy.grievance_raised", uid, grievance_id=gid)
        return self._grievance_view(self.db.one("SELECT * FROM grievances WHERE id=?", (gid,)))

    def grievances(self, uid: str) -> list[dict]:
        return [self._grievance_view(r) for r in
                self.db.all("SELECT * FROM grievances WHERE user_id=? ORDER BY created_at DESC", (uid,))]

    def grievances_for_operator(self, status: str = "open") -> list[dict]:
        if status not in ("open", "answered", "all"):
            raise Invalid("status must be open, answered or all")
        sql = "SELECT * FROM grievances" + ("" if status == "all" else " WHERE status=?") + " ORDER BY due_at"
        return [self._grievance_view(r, operator=True)
                for r in self.db.all(sql, () if status == "all" else (status,))]

    def answer_grievance(self, operator_id: str, gid: str, answer: str) -> dict:
        from .security import encrypt_text
        answer = (answer or "").strip()
        if not 1 <= len(answer) <= 4000:
            raise Invalid("write an answer of 1 to 4000 characters")
        r = self.db.one("SELECT user_id, status FROM grievances WHERE id=?", (gid,))
        if not r:
            raise NotFound("complaint not found")
        uid = r["user_id"]
        with self.db.tx(uid) as c:
            if not c.execute("UPDATE grievances SET status='answered', answer_enc=?, answered_at=?, answered_by=? "
                             "WHERE id=? AND status='open'", (encrypt_text(answer), self._now(), operator_id, gid)).rowcount:
                raise Conflict("this complaint was already answered")
            self._audit(c, operator_id, "privacy.grievance_answered", uid, grievance_id=gid)
            self._alert(c, [uid], "grievance_answered", "Your complaint was answered",
                        "Our grievance officer has answered your complaint. Open the app to read the answer.", uid)
        return self._grievance_view(self.db.one("SELECT * FROM grievances WHERE id=?", (gid,)), operator=True)

    # ------------------------------------------------------------- erasure
    def _erasure_view(self, uid: str) -> dict | None:
        r = self.db.one("SELECT * FROM erasure_requests WHERE user_id=? ORDER BY requested_at DESC LIMIT 1", (uid,))
        return None if not r else {"id": r["id"], "status": r["status"], "requested_at": r["requested_at"],
                                   "erase_at": r["erase_at"], "decided_at": r["decided_at"]}

    def erasure_request(self, uid: str) -> dict | None:
        """The latest deletion request (pending, cancelled or completed), or None."""
        return self._erasure_view(uid)

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
        c.execute("UPDATE checks SET narration=NULL WHERE principal_id=?", (uid,))   # free text: may name people
        c.execute("UPDATE checks SET payee='(erased)' WHERE principal_id=? AND status NOT IN "
                  "('cooling_off','pending_approval')", (uid,))
        c.execute("UPDATE recoveries SET new_mobile_enc='', new_mobile_masked='(erased)' WHERE user_id=?", (uid,))
        for table, col in (("sessions", "user_id"), ("push_tokens", "user_id"), ("device_keys", "user_id"),
                           ("devices", "user_id"), ("trusted_payees", "principal_id"), ("consents", "user_id"),
                           ("sim_events", "user_id"), ("nominees", "user_id"),
                           ("grievances", "user_id")):
            c.execute(f"DELETE FROM {table} WHERE {col}=?", (uid,))  # nosec B608: only fixed SQL fragments / '?' placeholders are spliced in; values are parameters
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


__all__ = ["PrivacyMixin", "NOTICE_VERSION", "NOTICE_HI", "GRIEVANCE_DAYS", "ERASURE_HOLD_DAYS", "RETAINED", "notify"]
