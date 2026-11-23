import re
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient

from guardian_registry.api import create_app
from guardian_registry.clock import FixedClock, iso
from guardian_registry.db import Database
from guardian_registry.errors import Conflict, Forbidden, Invalid
from guardian_registry.models import Outcome, Rules, Transaction
from guardian_registry.notify import Dispatcher, LogSmsSender
from guardian_registry.policy import SIM_SWAP_DELAY_MINUTES, SIM_SWAP_KNOWN_PAYEE_LIMIT, evaluate
from guardian_registry.service import LOOSENING_DELAY_HOURS, OTP_RESEND_SECONDS, Registry
from guardian_registry.simswap import NEW_DEVICE_PROBATION_HOURS, SIM_SWAP_WINDOW_HOURS

from .conftest import AMMA, PRIYA, RAVI, R, STRANGER

NEW_NUMBER = "9876500077"


# ------------------------------------------------------------------ policy
class TestPolicy:
    def ev(self, amount, *, known=True, guardian=True, sim=True, rules=None):
        return evaluate(rules or Rules(), Transaction(amount, "p@upi"), spent_today=0, payee_known=known,
                        has_active_guardian=guardian, sim_swap_recent=sim)

    def test_no_window_no_effect(self):
        assert self.ev(10_00_000 * R, known=False, sim=False).outcome is Outcome.ALLOW

    def test_new_payee_any_amount_needs_approval(self):
        d = self.ev(1 * R, known=False)
        assert d.outcome is Outcome.NEEDS_APPROVAL and "SIM card" in d.reasons[0]

    def test_known_payee_small_amount_allowed(self):
        assert self.ev(SIM_SWAP_KNOWN_PAYEE_LIMIT - 1).outcome is Outcome.ALLOW
        assert self.ev(SIM_SWAP_KNOWN_PAYEE_LIMIT).outcome is Outcome.NEEDS_APPROVAL

    def test_no_guardian_long_delay(self):
        d = self.ev(1 * R, known=False, guardian=False)
        assert d.outcome is Outcome.DELAY and d.delay_minutes == SIM_SWAP_DELAY_MINUTES

    def test_rule_can_be_off(self):
        assert self.ev(1 * R, known=False, rules=Rules(sim_swap_hold=False)).outcome is Outcome.ALLOW

    def test_block_still_wins(self):
        assert self.ev(1 * R, known=False, rules=Rules(kill_switch=True)).outcome is Outcome.BLOCK

    def test_turning_rule_off_is_loosening(self):
        assert Rules().is_loosening(Rules(sim_swap_hold=False))


# ------------------------------------------------------------------ service
def pay(reg, f, rupees, payee="known@upi", txn=None):
    pay.n = getattr(pay, "n", 0) + 1
    return reg.check(f["bank"], AMMA, txn or f"s{pay.n}", rupees * R, payee)


def kinds(reg, uid):
    return [n["kind"] for n in reg.notifications(uid)]


class TestSignals:
    def test_bank_report_opens_window_and_alerts(self, reg, family, clock):
        out = reg.report_sim_change(family["bank"], AMMA)
        assert out["window_open"] and reg.sim_swap_active(family["amma"])
        assert "sim_changed" in kinds(reg, family["ravi"])
        assert "sim_changed_self" in kinds(reg, family["amma"])
        clock.advance(hours=SIM_SWAP_WINDOW_HOURS)
        assert not reg.sim_swap_active(family["amma"])

    def test_payments_held_during_window(self, reg, family):
        assert pay(reg, family, 3_000)["outcome"] == "allow"
        reg.report_sim_change(family["bank"], AMMA)
        assert pay(reg, family, 3_000)["outcome"] == "needs_approval"     # known payee, >= ₹2,000
        assert pay(reg, family, 500)["outcome"] == "allow"                # small, known payee
        assert pay(reg, family, 100, payee="fresh@upi")["outcome"] == "needs_approval"

    def test_old_change_outside_window(self, reg, family, clock):
        old = iso(clock.now() - timedelta(hours=SIM_SWAP_WINDOW_HOURS + 8))
        assert reg.report_sim_change(family["bank"], AMMA, old)["window_open"] is False

    def test_changed_at_validation(self, reg, family, clock):
        with pytest.raises(Invalid, match="timezone"):
            reg.report_sim_change(family["bank"], AMMA, "2026-11-23T09:00:00")
        with pytest.raises(Invalid, match="future"):
            reg.report_sim_change(family["bank"], AMMA, "2030-01-01T00:00:00+00:00")
        with pytest.raises(Invalid):
            reg.report_sim_change(family["bank"], AMMA, "yesterday")

    def test_unenrolled(self, reg, family):
        assert reg.report_sim_change(family["bank"], STRANGER) == {"enrolled": False}

    def test_lost_phone_signs_out_everywhere(self, reg, sms_family):
        reg_, f, tokens = sms_family
        out = reg_.report_lost_phone(f["ravi"], f["amma"])  # guardian reports
        assert out["sessions_revoked"] >= 1
        assert reg_.user_by_token(tokens["amma"]) is None
        assert reg_.sim_swap_active(f["amma"])

    def test_outsider_cannot_report_lost_phone(self, reg, family):
        with pytest.raises(Forbidden):
            reg.report_lost_phone(family["priya"], family["amma"])

    def test_guardian_sim_change_tells_wards(self, reg, family):
        reg.report_sim_change(family["bank"], RAVI)
        assert "guardian_sim_changed" in kinds(reg, family["amma"])

    def test_confirm_clears_window(self, reg, family):
        reg.report_sim_change(family["bank"], AMMA)
        assert reg.confirm_sim_change(family["ravi"], family["amma"]) == {"cleared": 1}
        assert not reg.sim_swap_active(family["amma"])
        with pytest.raises(Conflict):
            reg.confirm_sim_change(family["ravi"], family["amma"])

    def test_sms_suppressed_to_swapped_number(self, reg, family, clock):
        sms = LogSmsSender()
        d = Dispatcher(reg.db, clock, sms=sms)
        d.run_once()
        before = len(sms.sent)
        reg.report_sim_change(family["bank"], RAVI)  # the guardian's number is compromised
        pay(reg, family, 20_000)                     # approval_needed -> would SMS Ravi
        d.run_once()
        assert not any(to.endswith(RAVI) for to, _ in sms.sent[before:])
        assert "approval_needed" in kinds(reg, family["ravi"])  # still in-app


@pytest.fixture
def sms_family(clock):
    """Same family, but everyone signed in through OTP with a device id, so sessions are real."""
    reg = Registry(Database(), clock)
    sms = LogSmsSender()
    tokens = {}

    def sign_in(mobile, name, device):
        code = reg.request_otp(mobile, sms)
        return reg.verify_otp(mobile, code, name, device)

    a = sign_in(AMMA, "Amma", "amma-phone")
    r = sign_in(RAVI, "Ravi", "ravi-phone")
    tokens["amma"], tokens["ravi"] = a["token"], r["token"]
    g = reg.invite_guardian(a["user_id"], RAVI)
    reg.respond_to_invite(r["user_id"], g["id"], True)
    bank, _ = reg.register_participant("Bank")
    return reg, {"amma": a["user_id"], "ravi": r["user_id"], "bank": bank, "sms": sms, "sign_in": sign_in}, tokens


class TestSessions:
    def test_first_device_is_trusted(self, sms_family):
        reg, f, t = sms_family
        assert reg.session_info(t["amma"])["restricted"] is False

    def test_same_device_again_is_trusted(self, sms_family, clock):
        reg, f, t = sms_family
        clock.advance(seconds=OTP_RESEND_SECONDS)
        assert f["sign_in"](AMMA, "Amma", "amma-phone")["restricted"] is False

    def test_new_device_probation_and_cannot_be_skipped(self, sms_family, clock):
        reg, f, t = sms_family
        clock.advance(seconds=OTP_RESEND_SECONDS)
        s1 = f["sign_in"](AMMA, "Amma", "new-phone")
        assert s1["restricted"] and "new device" in s1["restriction_reasons"][0]
        assert "new_device_sign_in" in kinds(reg, f["amma"])
        clock.advance(seconds=OTP_RESEND_SECONDS)
        assert f["sign_in"](AMMA, "Amma", "new-phone")["restricted"]  # signing in twice doesn't help
        clock.advance(hours=NEW_DEVICE_PROBATION_HOURS)
        assert reg.session_info(s1["token"])["restricted"] is False
        assert f["sign_in"](AMMA, "Amma", "new-phone")["restricted"] is False

    def test_no_device_id_after_first_is_probation(self, sms_family, clock):
        reg, f, t = sms_family
        clock.advance(seconds=OTP_RESEND_SECONDS)
        assert f["sign_in"](AMMA, "Amma", None)["restricted"]

    def test_sign_in_after_sim_change_is_restricted_old_session_is_not(self, sms_family, clock):
        reg, f, t = sms_family
        clock.advance(minutes=5)
        reg.report_sim_change(f["bank"], AMMA, iso(clock.now()))
        clock.advance(minutes=1)
        attacker = f["sign_in"](AMMA, "Amma", "amma-phone")  # even a "known" device id can be faked
        assert attacker["restricted"] and "SIM change" in attacker["restriction_reasons"][0]
        assert reg.session_info(t["amma"])["restricted"] is False   # the real phone, signed in before

    def test_report_arriving_late_still_restricts(self, sms_family, clock):
        """The bank's signal arrives after the attacker already signed in."""
        reg, f, t = sms_family
        clock.advance(minutes=10)
        swap_time = iso(clock.now())
        clock.advance(minutes=5)
        attacker = f["sign_in"](AMMA, "Amma", "amma-phone")
        assert attacker["restricted"] is False
        clock.advance(minutes=30)
        reg.report_sim_change(f["bank"], AMMA, swap_time)
        assert reg.session_info(attacker["token"])["restricted"] is True

    def test_lost_phone_resets_device_trust(self, sms_family, clock):
        reg, f, t = sms_family
        reg.report_lost_phone(f["ravi"], f["amma"])
        reg.confirm_sim_change(f["ravi"], f["amma"])
        clock.advance(seconds=OTP_RESEND_SECONDS)
        assert f["sign_in"](AMMA, "Amma", "amma-phone")["restricted"]  # device must re-earn trust


class TestMobileChange:
    def test_held_then_applied_and_kyc_ends(self, sms_family, clock):
        reg, f, t = sms_family
        a = reg.attest(f["bank"], AMMA, "full", "C1", "2025-01-01", "1950-01-01")
        reg.respond_to_attestation(f["amma"], a["attestation_id"], True)
        code = reg.request_mobile_change(f["amma"], NEW_NUMBER, f["sms"])
        out = reg.confirm_mobile_change(f["amma"], NEW_NUMBER, code)
        assert out["applied"] is False
        assert out["change"]["payload"] == {"new_mobile_masked": "+91******0077"}
        assert "change_proposed" in kinds(reg, f["ravi"])
        assert reg.user_by_mobile(AMMA) == f["amma"]
        clock.advance(hours=LOOSENING_DELAY_HOURS)
        reg.sweep()
        assert reg.user_by_mobile(NEW_NUMBER) == f["amma"] and reg.user_by_mobile(AMMA) is None
        assert reg.identity_level(f["amma"]) == "otp"

    def test_guardian_vetoes_move(self, sms_family, clock):
        reg, f, t = sms_family
        code = reg.request_mobile_change(f["amma"], NEW_NUMBER, f["sms"])
        cid = reg.confirm_mobile_change(f["amma"], NEW_NUMBER, code)["change"]["id"]
        reg.veto_change(f["ravi"], cid)
        clock.advance(hours=LOOSENING_DELAY_HOURS + 1)
        reg.sweep()
        assert reg.user_by_mobile(AMMA) == f["amma"]

    def test_wrong_code(self, sms_family):
        reg, f, t = sms_family
        reg.request_mobile_change(f["amma"], NEW_NUMBER, f["sms"])
        with pytest.raises(Exception):
            reg.confirm_mobile_change(f["amma"], NEW_NUMBER, "000001")

    def test_number_taken(self, sms_family):
        reg, f, t = sms_family
        with pytest.raises(Conflict):
            reg.request_mobile_change(f["amma"], RAVI, f["sms"])

    def test_no_secrets_in_audit(self, sms_family):
        reg, f, t = sms_family
        code = reg.request_mobile_change(f["amma"], NEW_NUMBER, f["sms"])
        reg.confirm_mobile_change(f["amma"], NEW_NUMBER, code)
        blob = " ".join(r["data"] for r in reg.db.all("SELECT data FROM audit_log"))
        assert NEW_NUMBER not in blob and "new_mobile_enc" not in blob and "new_mobile_hash" not in blob


# ------------------------------------------------------------------ HTTP
@pytest.fixture
def http():
    clock = FixedClock()
    sms = LogSmsSender()
    c = TestClient(create_app(Registry(Database(), clock), admin_token="adm", sms=sms, run_worker=False))

    def sign_in(mobile, name, device):
        c.post("/v1/auth/otp", json={"mobile": mobile})
        code = re.search(r"code: (\d{6})", sms.sent[-1][1]).group(1)
        return c.post("/v1/auth/verify", json={"mobile": mobile, "code": code, "display_name": name,
                                               "device_id": device}).json()

    amma, ravi = sign_in(AMMA, "Amma", "a-phone"), sign_in(RAVI, "Ravi", "r-phone")
    A, G = {"Authorization": f"Bearer {amma['token']}"}, {"Authorization": f"Bearer {ravi['token']}"}
    gid = c.post("/v1/me/guardians", json={"mobile": RAVI}, headers=A).json()["id"]
    c.post(f"/v1/guardian/invitations/{gid}/accept", headers=G)
    bank = {"X-Api-Key": c.post("/v1/admin/participants", json={"name": "B", "regulator_ref": "RBI-TEST-1"},
                                headers={"X-Admin-Token": "adm"}).json()["api_key"]}
    return {"c": c, "clock": clock, "sign_in": sign_in, "A": A, "G": G, "bank": bank, "amma": amma, "ravi": ravi}


class TestHttp:
    def test_hijacked_guardian_cannot_approve(self, http):
        c, clock = http["c"], http["clock"]
        c.patch("/v1/me/rules", headers=http["A"], json={"approval_threshold": 10_000 * R})
        # attacker swaps RAVI's SIM, signs in as Ravi
        clock.advance(minutes=10)
        c.post("/v1/signals/sim-change", headers=http["bank"], json={"mobile": RAVI})
        clock.advance(seconds=OTP_RESEND_SECONDS)
        thief = http["sign_in"](RAVI, "Ravi", "thief-phone")
        T = {"Authorization": f"Bearer {thief['token']}"}
        chk = c.post("/v1/checks", headers=http["bank"], json={
            "mobile": AMMA, "participant_txn_id": "x", "amount": 40_000 * R, "payee": "mule@upi"}).json()
        r = c.post(f"/v1/guardian/payments/{chk['check_id']}/approve", headers=T)
        assert r.status_code == 403 and r.json()["error"] == "RestrictedSession"
        assert c.post(f"/v1/guardian/wards/{http['amma']['user_id']}/confirm-sim-change", headers=T).status_code == 403
        assert c.post("/v1/me/security/confirm-sim-change", headers=T).status_code == 403
        # protective actions still work from the restricted session
        assert c.post(f"/v1/guardian/payments/{chk['check_id']}/deny", headers=T).status_code == 200
        # the real Ravi, on his old phone, is unaffected
        assert c.get("/v1/me/security", headers=http["G"]).json()["this_session"]["restricted"] is False
        assert c.post("/v1/me/security/confirm-sim-change", headers=http["G"]).json() == {"cleared": 1}

    def test_restricted_principal_can_tighten_not_loosen(self, http):
        c, clock = http["c"], http["clock"]
        clock.advance(seconds=OTP_RESEND_SECONDS)
        new = http["sign_in"](AMMA, "Amma", "new-phone")
        N = {"Authorization": f"Bearer {new['token']}"}
        assert c.post("/v1/me/rules/preset/strict", headers=N).status_code == 200            # tighter
        assert c.patch("/v1/me/rules", headers=N, json={"per_txn_limit": 5_000 * R}).status_code == 200
        assert c.patch("/v1/me/rules", headers=N, json={"per_txn_limit": None}).status_code == 403
        assert c.post("/v1/me/rules/preset/strict", headers=N).status_code == 403            # now looser
        assert c.post("/v1/me/kill-switch/on", headers=N).status_code == 200
        assert c.post("/v1/me/kill-switch/off", headers=N).status_code == 403
        assert c.post("/v1/me/guardians", headers=N, json={"mobile": PRIYA}).status_code == 403
        assert c.post("/v1/me/mobile/change", headers=N, json={"new_mobile": NEW_NUMBER}).status_code == 403
        sec = c.get("/v1/me/security", headers=N).json()
        assert sec["this_session"]["restricted"] and sec["devices_on_probation"] == 1

    def test_lost_phone_over_http(self, http):
        c = http["c"]
        r = c.post(f"/v1/guardian/wards/{http['amma']['user_id']}/lost-phone", headers=http["G"]).json()
        assert r["sessions_revoked"] == 1
        assert c.get("/v1/me", headers=http["A"]).status_code == 401
        sec = c.get(f"/v1/guardian/wards/{http['amma']['user_id']}/security", headers=http["G"]).json()
        assert sec["sim_swap_window_open"] and sec["reported_by"] == ["guardian"]

    def test_mobile_change_over_http(self, http):
        c = http["c"]
        r = c.post("/v1/me/mobile/change", headers=http["A"], json={"new_mobile": NEW_NUMBER})
        assert r.status_code == 202
        sms = c.app.state.dispatcher.sms
        code = re.search(r"code: (\d{6})", sms.sent[-1][1]).group(1)
        out = c.post("/v1/me/mobile/verify", headers=http["A"], json={"new_mobile": NEW_NUMBER, "code": code}).json()
        assert out["applied"] is False and out["change"]["kind"] == "change_mobile"
        ok = c.post(f"/v1/guardian/changes/{out['change']['id']}/approve", headers=http["G"]).json()
        assert ok["status"] == "applied"
        assert c.post("/v1/checks", headers=http["bank"], json={
            "mobile": NEW_NUMBER, "participant_txn_id": "n", "amount": 100, "payee": "p@upi"}).json()["enrolled"]

    def test_bank_signal_validation(self, http):
        r = http["c"].post("/v1/signals/sim-change", headers=http["bank"], json={"mobile": AMMA, "changed_at": "nope"})
        assert r.status_code == 422
