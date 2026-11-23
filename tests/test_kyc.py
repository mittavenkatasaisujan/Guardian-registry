import json

import httpx
import pytest
from fastapi.testclient import TestClient

from guardian_registry.api import create_app
from guardian_registry.db import Database
from guardian_registry.errors import Conflict, Forbidden, Invalid, NotFound
from guardian_registry.kyc import KYC_CONSENT_DAYS, KYC_VALID_DAYS, age_on
from guardian_registry.notify import Dispatcher, LogSmsSender
from guardian_registry.service import LOOSENING_DELAY_HOURS, Registry

from .conftest import AMMA, PRIYA, RAVI, R, STRANGER

OLD_DOB = "1952-03-10"     # 74 on 2026-11-23
YOUNG_DOB = "1990-06-01"


def attest(reg, bank, mobile=AMMA, level="full", dob=OLD_DOB, ref="CUST-1", verified="2025-01-15"):
    return reg.attest(bank, mobile, level, ref, verified, dob)


def verified(reg, bank, uid, mobile, **kw):
    a = attest(reg, bank, mobile, **kw)
    reg.respond_to_attestation(uid, a["attestation_id"], True)
    return a


class TestAge:
    @pytest.mark.parametrize("dob,today,age", [
        ("1956-11-23", "2026-11-23", 70), ("1956-11-24", "2026-11-23", 69),
        ("1960-02-29", "2026-02-28", 65), ("1960-02-29", "2026-03-01", 66),
    ])
    def test_age_on(self, dob, today, age):
        from datetime import date
        assert age_on(date.fromisoformat(dob), date.fromisoformat(today)) == age


class TestConsent:
    def test_pending_until_customer_approves(self, reg, family):
        a = attest(reg, family["bank"])
        assert a["status"] == "pending_consent" and "bank" not in a
        assert reg.identity_level(family["amma"]) == "otp"
        assert reg.age_facts(family["amma"])["senior"] is None
        assert "kyc_consent_needed" in [n["kind"] for n in reg.notifications(family["amma"])]
        reg.respond_to_attestation(family["amma"], a["attestation_id"], True)
        assert reg.identity_level(family["amma"]) == "bank_verified"
        assert reg.age_facts(family["amma"]) == {"senior": True, "dob_conflict": False}

    def test_reject(self, reg, family):
        a = attest(reg, family["bank"])
        reg.respond_to_attestation(family["amma"], a["attestation_id"], False)
        assert reg.identity_level(family["amma"]) == "otp"
        with pytest.raises(Conflict):
            reg.respond_to_attestation(family["amma"], a["attestation_id"], True)

    def test_only_the_customer_can_respond(self, reg, family):
        a = attest(reg, family["bank"])
        with pytest.raises(NotFound):
            reg.respond_to_attestation(family["ravi"], a["attestation_id"], True)

    def test_consent_lapses(self, reg, family, clock):
        a = attest(reg, family["bank"])
        clock.advance(days=KYC_CONSENT_DAYS)
        with pytest.raises(Conflict, match="lapsed"):
            reg.respond_to_attestation(family["amma"], a["attestation_id"], True)

    def test_withdraw(self, reg, family):
        a = verified(reg, family["bank"], family["amma"], AMMA)
        reg.withdraw_attestation(family["amma"], a["attestation_id"])
        assert reg.identity_level(family["amma"]) == "otp"

    def test_bank_revoke(self, reg, family):
        a = verified(reg, family["bank"], family["amma"], AMMA)
        reg.revoke_attestation(family["bank"], a["attestation_id"])
        assert reg.identity_level(family["amma"]) == "otp"
        assert "kyc_revoked" in [n["kind"] for n in reg.notifications(family["amma"])]

    def test_other_bank_cannot_see_or_revoke(self, reg, family):
        other, _ = reg.register_participant("Other Bank")
        a = attest(reg, family["bank"])
        with pytest.raises(NotFound):
            reg.bank_attestation(other, a["attestation_id"])
        with pytest.raises(NotFound):
            reg.revoke_attestation(other, a["attestation_id"])


class TestLifecycle:
    def test_expires_after_a_year_and_alerts(self, reg, family, clock):
        verified(reg, family["bank"], family["amma"], AMMA)
        clock.advance(days=KYC_VALID_DAYS)
        assert reg.identity_level(family["amma"]) == "otp"     # lazily correct
        assert reg.sweep()["kyc_updated"] == 1
        assert "kyc_expired" in [n["kind"] for n in reg.notifications(family["amma"])]

    def test_new_claim_from_same_bank_replaces_old_once_approved(self, reg, family):
        a1 = verified(reg, family["bank"], family["amma"], AMMA, level="minimum")
        a2 = attest(reg, family["bank"], level="full")
        assert reg.identity_level(family["amma"]) == "bank_min_kyc"  # old one still counts while pending
        reg.respond_to_attestation(family["amma"], a2["attestation_id"], True)
        statuses = {a["attestation_id"]: a["status"] for a in reg.identity(family["amma"])["attestations"]}
        assert statuses == {a1["attestation_id"]: "superseded", a2["attestation_id"]: "active"}
        assert reg.identity_level(family["amma"]) == "bank_verified"

    def test_newer_pending_supersedes_older_pending(self, reg, family):
        a1 = attest(reg, family["bank"])
        attest(reg, family["bank"])
        with pytest.raises(Conflict, match="superseded"):
            reg.respond_to_attestation(family["amma"], a1["attestation_id"], True)

    def test_minimum_kyc_level(self, reg, family):
        verified(reg, family["bank"], family["amma"], AMMA, level="minimum")
        assert reg.identity_level(family["amma"]) == "bank_min_kyc"


class TestValidation:
    @pytest.mark.parametrize("kw,match", [
        ({"level": "gold"}, "kyc_level"),
        ({"ref": " "}, "customer_ref"),
        ({"verified": "2027-01-01"}, "future"),
        ({"verified": "2010-01-01"}, "too old"),
        ({"verified": "23/11/2026"}, "date"),
        ({"dob": "2030-01-01"}, "plausible"),
        ({"dob": "1890-01-01"}, "plausible"),
    ])
    def test_rejects(self, reg, family, kw, match):
        with pytest.raises(Invalid, match=match):
            attest(reg, family["bank"], **kw)

    def test_not_enrolled(self, reg, family):
        with pytest.raises(NotFound):
            attest(reg, family["bank"], mobile=STRANGER)


class TestPrivacy:
    def test_dob_and_ref_never_stored_or_logged_in_clear(self, reg, family):
        verified(reg, family["bank"], family["amma"], AMMA, ref="SBI-CIF-778899")
        dump = "\n".join(reg.db.conn.iterdump())
        assert OLD_DOB not in dump and "SBI-CIF-778899" not in dump

    def test_bank_check_shows_senior_flag_not_dob(self, reg, family):
        verified(reg, family["bank"], family["amma"], AMMA)
        out = reg.check(family["bank"], AMMA, "s1", 100 * R, "known@upi")
        assert out["customer"] == {"identity_level": "bank_verified", "senior": True}
        assert OLD_DOB not in json.dumps(out)

    def test_young_customer(self, reg, family):
        verified(reg, family["bank"], family["amma"], AMMA, dob=YOUNG_DOB)
        assert reg.check(family["bank"], AMMA, "s2", 100, "known@upi")["customer"]["senior"] is False

    def test_no_dob_means_unknown(self, reg, family):
        verified(reg, family["bank"], family["amma"], AMMA, dob=None)
        assert reg.check(family["bank"], AMMA, "s3", 100, "known@upi")["customer"]["senior"] is None

    def test_conflicting_dobs_make_senior_unknown(self, reg, family):
        other, _ = reg.register_participant("Other Bank")
        verified(reg, family["bank"], family["amma"], AMMA, dob=OLD_DOB)
        verified(reg, other, family["amma"], AMMA, dob="1953-03-10")
        assert reg.age_facts(family["amma"]) == {"senior": None, "dob_conflict": True}
        assert "kyc_dob_conflict" in [n["kind"] for n in reg.notifications(family["amma"])]

    def test_suggests_senior_preset(self, reg):
        uid, _ = reg.register_user(AMMA, "Amma")
        bank, _ = reg.register_participant("B")
        verified(reg, bank, uid, AMMA)
        assert reg.identity(uid)["suggested_preset"] == "senior_with_guardian"

    def test_audit_has_no_dob(self, reg, family):
        verified(reg, family["bank"], family["amma"], AMMA)
        blob = " ".join(r["data"] for r in reg.db.all("SELECT data FROM audit_log"))
        assert OLD_DOB not in blob and "includes_date_of_birth" in blob


class TestVerifiedGuardianRule:
    def test_unverified_guardian_cannot_approve_but_can_deny(self, reg, family):
        reg.update_rules(family["amma"], {"require_verified_guardian": True})
        c = reg.check(family["bank"], AMMA, "v1", 20_000 * R, "known@upi")
        assert c["outcome"] == "delay"  # Ravi is not bank-verified: no eligible approver
        verified(reg, family["bank"], family["ravi"], RAVI, dob=YOUNG_DOB, ref="R1")
        c = reg.check(family["bank"], AMMA, "v2", 20_000 * R, "known@upi")
        assert c["outcome"] == "needs_approval"

    def test_approve_blocked_after_verification_is_lost(self, reg, family):
        a = verified(reg, family["bank"], family["ravi"], RAVI, ref="R1")
        reg.update_rules(family["amma"], {"require_verified_guardian": True})
        c = reg.check(family["bank"], AMMA, "v3", 20_000 * R, "known@upi")
        reg.revoke_attestation(family["bank"], a["attestation_id"])
        with pytest.raises(Forbidden, match="bank-verified"):
            reg.approve_check(family["ravi"], c["check_id"])
        assert reg.deny_check(family["ravi"], c["check_id"])["status"] == "denied"

    def test_only_verified_guardians_get_approval_alert(self, reg, family):
        g = reg.invite_guardian(family["amma"], PRIYA)
        reg.respond_to_invite(family["priya"], g["id"], accept=True)
        verified(reg, family["bank"], family["priya"], PRIYA, ref="P1", dob=YOUNG_DOB)
        reg.update_rules(family["amma"], {"require_verified_guardian": True})
        reg.check(family["bank"], AMMA, "v4", 20_000 * R, "known@upi")
        assert "approval_needed" in [n["kind"] for n in reg.notifications(family["priya"])]
        assert "approval_needed" not in [n["kind"] for n in reg.notifications(family["ravi"])]

    def test_turning_rule_off_is_held(self, reg, family, clock):
        reg.update_rules(family["amma"], {"require_verified_guardian": True})
        out = reg.update_rules(family["amma"], {"require_verified_guardian": False})
        assert out["held"] is not None and reg.get_rules(family["amma"]).require_verified_guardian
        clock.advance(hours=LOOSENING_DELAY_HOURS)
        assert reg.get_rules(family["amma"]).require_verified_guardian is False

    def test_guardian_listing_shows_identity(self, reg, family):
        verified(reg, family["bank"], family["ravi"], RAVI, ref="R1")
        assert reg.guardians_of(family["amma"])[0]["guardian_identity_level"] == "bank_verified"

    def test_rule_must_be_bool(self, reg, family):
        with pytest.raises(Invalid):
            reg.update_rules(family["amma"], {"require_verified_guardian": "yes"})


class TestWebhook:
    def test_bank_hears_consent_decision(self, reg, family, clock):
        calls = []
        d = Dispatcher(reg.db, clock, sms=LogSmsSender(),
                       http=httpx.Client(transport=httpx.MockTransport(lambda r: calls.append(r) or httpx.Response(200))))
        reg.set_webhook(family["bank"], "https://bank.example/h")
        a = attest(reg, family["bank"])
        reg.respond_to_attestation(family["amma"], a["attestation_id"], True)
        d.run_once()
        body = json.loads(calls[-1].content)
        assert body["event"] == "kyc.updated" and body["data"]["attestation"]["status"] == "active"
        assert OLD_DOB not in calls[-1].content.decode()


class TestHttp:
    def test_full_flow_over_http(self, clock):
        import re
        sms = LogSmsSender()
        client = TestClient(create_app(Registry(Database(), clock), admin_token="a", sms=sms, run_worker=False))
        client.post("/v1/auth/otp", json={"mobile": AMMA})
        code = re.search(r"code: (\d{6})", sms.sent[-1][1]).group(1)
        tok = client.post("/v1/auth/verify", json={"mobile": AMMA, "code": code, "display_name": "Amma"}).json()["token"]
        me = {"Authorization": f"Bearer {tok}"}
        bank = {"X-Api-Key": client.post("/v1/admin/participants", json={"name": "B", "regulator_ref": "RBI-TEST-1"},
                                         headers={"X-Admin-Token": "a"}).json()["api_key"]}

        a = client.post("/v1/kyc/attestations", headers=bank, json={
            "mobile": AMMA, "kyc_level": "full", "customer_ref": "C1", "verified_on": "2025-01-01",
            "date_of_birth": OLD_DOB})
        assert a.status_code == 201
        aid = a.json()["attestation_id"]
        assert client.get("/v1/me", headers=me).json()["identity_level"] == "otp"
        assert client.post(f"/v1/me/identity/attestations/{aid}/approve", headers=me).status_code == 200
        ident = client.get("/v1/me/identity", headers=me).json()
        assert ident["level"] == "bank_verified" and ident["senior"] is True
        assert ident["attestations"][0]["bank"] == "B"
        assert client.get(f"/v1/kyc/attestations/{aid}", headers=bank).json()["status"] == "active"
        chk = client.post("/v1/checks", headers=bank, json={
            "mobile": AMMA, "participant_txn_id": "t", "amount": 100, "payee": "p@upi"}).json()
        assert chk["customer"]["senior"] is True
        assert client.patch("/v1/me/rules", headers=me, json={"require_verified_guardian": True}).status_code == 200
        assert client.delete(f"/v1/kyc/attestations/{aid}", headers=bank).json()["status"] == "revoked"
        assert client.post("/v1/kyc/attestations", headers=bank, json={
            "mobile": AMMA, "kyc_level": "platinum", "customer_ref": "C", "verified_on": "2025-01-01"}).status_code == 422
