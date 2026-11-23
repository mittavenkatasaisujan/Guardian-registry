"""Account recovery after a number is disconnected and no phone is still signed in."""

import re
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient

from guardian_registry.api import create_app
from guardian_registry.clock import FixedClock, iso
from guardian_registry.db import Database
from guardian_registry.errors import Conflict, Forbidden, NotFound, Unauthorized
from guardian_registry.notify import LogSmsSender
from guardian_registry.recovery import RECOVERY_HOLD_HOURS, RECOVERY_TTL_HOURS
from guardian_registry.service import OTP_RESEND_SECONDS, Registry

from .conftest import AMMA, PRIYA, R, RAVI

NEW = "9876500077"
NEW2 = "9876500078"


@pytest.fixture
def telco(reg):
    pid, _ = reg.register_participant("Telco", "telecom", "DOT-UL-1")
    return pid


def disconnect(reg, telco, clock, mobile, eid="d1"):
    out = reg.ingest_operator_events(telco, [{"event_id": eid, "type": "disconnected", "mobile": mobile,
                                              "occurred_at": iso(clock.now())}])
    assert out["results"][0]["result"] == "number_detached"


def start(reg, old, new=NEW):
    code = reg.request_otp(new, LogSmsSender())
    return reg.start_recovery(old, new, code)


def rid_of(reg, uid):
    return reg.my_recoveries(uid)[0]["recovery_id"]


@pytest.fixture
def lost_ravi(reg, family, telco, clock):
    """Ravi's number was disconnected and he has no phone signed in (sessions gone)."""
    disconnect(reg, telco, clock, RAVI)
    reg.db.conn.execute("UPDATE sessions SET revoked_at=? WHERE user_id=?", (reg._now(), family["ravi"]))
    return family


class TestStart:
    def test_answer_looks_the_same_with_or_without_a_match(self, reg, lost_ravi):
        real = start(reg, RAVI)
        fake = start(reg, "9876500055", NEW2)
        assert real.keys() == fake.keys() and real["status"] == fake["status"] == "pending"
        assert reg.recovery_status(real["recovery_token"]).keys() == reg.recovery_status(fake["recovery_token"]).keys()

    def test_only_disconnected_accounts_can_be_recovered(self, reg, family):
        start(reg, AMMA)  # Amma's number is active: nothing matches, nothing happens
        assert reg.my_recoveries(family["amma"]) == []
        assert not [n for n in reg.notifications(family["ravi"]) if n["kind"] == "recovery_requested"]

    def test_contacts_are_alerted(self, reg, lost_ravi):
        start(reg, RAVI)
        msg = [n for n in reg.notifications(lost_ravi["amma"]) if n["kind"] == "recovery_requested"][0]
        assert "call YOU placed" in msg["body"] and NEW not in msg["body"]
        sms = reg.db.one("SELECT 1 FROM notifications WHERE kind='recovery_requested' AND channel='sms'")
        assert sms  # urgent: guardians/wards get it by SMS too

    def test_needs_the_new_number_code(self, reg, lost_ravi):
        reg.request_otp(NEW, LogSmsSender())
        with pytest.raises(Unauthorized):
            reg.start_recovery(RAVI, NEW, "000000")

    def test_new_number_must_be_free(self, reg, lost_ravi):
        with pytest.raises(Conflict):
            start(reg, RAVI, PRIYA)

    def test_one_attempt_at_a_time(self, reg, lost_ravi, clock):
        start(reg, RAVI)
        second = start(reg, RAVI, NEW2)  # looks fine to the caller, but matches nothing
        assert second["status"] == "pending"
        assert len(reg.my_recoveries(lost_ravi["ravi"])) == 1


class TestVouching:
    def test_single_contact_then_hold_then_complete(self, reg, lost_ravi, clock):
        token = start(reg, RAVI)["recovery_token"]
        rid = rid_of(reg, lost_ravi["ravi"])
        v = reg.vouch_recovery(lost_ravi["amma"], rid, True)
        assert v["status"] == "held" and v["approvals"] == 1 and v["approvals_needed"] == 1
        assert reg.recovery_status(token)["status"] == "held"
        clock.advance(hours=RECOVERY_HOLD_HOURS - 1)
        reg.sweep()
        assert reg.user_by_mobile(NEW) is None
        clock.advance(hours=1, minutes=1)
        reg.sweep()
        assert reg.recovery_status(token)["status"] == "completed"
        assert reg.user_by_mobile(NEW) == lost_ravi["ravi"]
        assert reg.profile(lost_ravi["ravi"])["number_status"] == "active"
        assert lost_ravi["ravi"] in reg._active_guardian_ids(lost_ravi["amma"])  # still guards Amma
        assert [n for n in reg.notifications(lost_ravi["ravi"]) if n["kind"] == "recovery_completed"]

    def test_two_contacts_need_two(self, reg, family, telco, clock):
        g = reg.invite_guardian(family["amma"], PRIYA)
        reg.respond_to_invite(family["priya"], g["id"], True)
        disconnect(reg, telco, clock, AMMA)
        start(reg, AMMA)
        rid = rid_of(reg, family["amma"])
        assert reg.vouch_recovery(family["ravi"], rid, True)["status"] == "pending"
        assert reg.vouch_recovery(family["priya"], rid, True)["status"] == "held"

    def test_deny_stops_it_and_a_new_attempt_can_start(self, reg, lost_ravi, clock):
        start(reg, RAVI)
        rid = rid_of(reg, lost_ravi["ravi"])
        assert reg.vouch_recovery(lost_ravi["amma"], rid, False)["status"] == "denied"
        with pytest.raises(Conflict):
            reg.vouch_recovery(lost_ravi["amma"], rid, True)
        clock.advance(minutes=1)
        start(reg, RAVI, NEW2)
        assert reg.my_recoveries(lost_ravi["ravi"])[0]["status"] == "pending"

    def test_veto_during_hold(self, reg, family, telco, clock):
        g = reg.invite_guardian(family["amma"], PRIYA)
        reg.respond_to_invite(family["priya"], g["id"], True)
        disconnect(reg, telco, clock, AMMA)
        start(reg, AMMA)
        rid = rid_of(reg, family["amma"])
        reg.vouch_recovery(family["ravi"], rid, True)
        reg.vouch_recovery(family["priya"], rid, True)
        assert reg.vouch_recovery(family["ravi"], rid, False)["status"] == "denied"
        clock.advance(hours=RECOVERY_HOLD_HOURS + 1)
        reg.sweep()
        assert reg.user_by_mobile(NEW) is None

    def test_strangers_cannot_vouch(self, reg, lost_ravi):
        start(reg, RAVI)
        with pytest.raises(Forbidden):
            reg.vouch_recovery(lost_ravi["priya"], rid_of(reg, lost_ravi["ravi"]), True)
        assert reg.recoveries_to_vouch(lost_ravi["priya"]) == []
        assert [r["person_name"] for r in reg.recoveries_to_vouch(lost_ravi["amma"])] == ["Ravi"]
        assert reg.inbox(lost_ravi["amma"])["recoveries"][0]["your_vote"] is None

    def test_owner_with_a_live_session_can_cancel(self, reg, family, telco, clock):
        disconnect(reg, telco, clock, RAVI)  # Ravi's phone is still signed in
        start(reg, RAVI)
        rid = rid_of(reg, family["ravi"])
        assert reg.cancel_recovery(family["ravi"], rid)["status"] == "cancelled"
        with pytest.raises(NotFound):
            reg.cancel_recovery(family["amma"], rid)

    def test_expires(self, reg, lost_ravi, clock):
        token = start(reg, RAVI)["recovery_token"]
        fake = start(reg, "9876500055", NEW2)["recovery_token"]
        clock.advance(hours=RECOVERY_TTL_HOURS + 1)
        assert reg.recovery_status(token)["status"] == "expired"
        assert reg.recovery_status(fake)["status"] == "expired"

    def test_completion_signs_out_old_sessions(self, reg, family, telco, clock):
        disconnect(reg, telco, clock, RAVI)  # a phone still signed in, maybe in the wrong hands
        start(reg, RAVI)
        reg.vouch_recovery(family["amma"], rid_of(reg, family["ravi"]), True)
        clock.advance(hours=RECOVERY_HOLD_HOURS + 1)
        reg.sweep()
        assert reg.db.one("SELECT COUNT(*) n FROM sessions WHERE user_id=? AND revoked_at IS NULL",
                          (family["ravi"],))["n"] == 0

    def test_void_if_new_number_taken_meanwhile(self, reg, lost_ravi, clock):
        start(reg, RAVI)
        reg.vouch_recovery(lost_ravi["amma"], rid_of(reg, lost_ravi["ravi"]), True)
        reg.register_user(NEW, "Someone else")
        clock.advance(hours=RECOVERY_HOLD_HOURS + 1)
        reg.sweep()
        assert reg.my_recoveries(lost_ravi["ravi"])[0]["status"] == "cancelled"
        assert reg.profile(lost_ravi["ravi"])["number_status"] == "disconnected"


class TestBankVouch:
    @pytest.fixture
    def kycd_ravi(self, reg, family, telco, clock):
        a = reg.attest(family["bank"], RAVI, "full", "CIF-22", "2025-01-15")
        reg.respond_to_attestation(family["ravi"], a["attestation_id"], True)
        clock.advance(minutes=1)
        disconnect(reg, telco, clock, RAVI)
        return family

    def test_bank_that_knew_them_can_vouch(self, reg, kycd_ravi):
        start(reg, RAVI)
        out = reg.bank_vouch_recovery(kycd_ravi["bank"], NEW, "CIF-22")
        assert out["recovery"] == "held"
        assert reg.my_recoveries(kycd_ravi["ravi"])[0]["bank_vouched"] is True

    def test_wrong_customer_id_or_other_bank(self, reg, kycd_ravi):
        start(reg, RAVI)
        with pytest.raises(NotFound):
            reg.bank_vouch_recovery(kycd_ravi["bank"], NEW, "CIF-99")
        other, _ = reg.register_participant("Other Bank", "bank", "RBI-2")
        with pytest.raises(NotFound):
            reg.bank_vouch_recovery(other, NEW, "CIF-22")
        app, _ = reg.register_participant("App", "tpap", "NPCI-1")
        with pytest.raises(Forbidden):
            reg.bank_vouch_recovery(app, NEW, "CIF-22")

    def test_no_contacts_only_bank_can_recover(self, reg, telco, clock):
        uid, _ = reg.register_user("9876500044", "Loner")
        bank, _ = reg.register_participant("B", "bank", "RBI-3")
        a = reg.attest(bank, "9876500044", "full", "L-1", "2025-01-15")
        reg.respond_to_attestation(uid, a["attestation_id"], True)
        clock.advance(minutes=1)
        disconnect(reg, telco, clock, "9876500044")
        start(reg, "9876500044")
        assert reg.my_recoveries(uid)[0]["approvals_needed"] == 0
        reg.bank_vouch_recovery(bank, NEW, "L-1")
        clock.advance(hours=RECOVERY_HOLD_HOURS + 1)
        reg.sweep()
        assert reg.user_by_mobile(NEW) == uid


# ------------------------------------------------------------------ HTTP
def test_http_flow():
    clock = FixedClock()
    sms = LogSmsSender()
    c = TestClient(create_app(Registry(Database(), clock), admin_token="adm", sms=sms, run_worker=False))

    def code_for(mobile):
        assert c.post("/v1/auth/otp", json={"mobile": mobile}).status_code == 202
        return re.search(r"code: (\d{6})", sms.sent[-1][1]).group(1)

    def sign_in(mobile, name, device):
        return c.post("/v1/auth/verify", json={"mobile": mobile, "code": code_for(mobile), "display_name": name,
                                               "device_id": device}).json()

    amma, ravi = sign_in(AMMA, "Amma", "a"), sign_in(RAVI, "Ravi", "r")
    A, G = {"Authorization": f"Bearer {amma['token']}"}, {"Authorization": f"Bearer {ravi['token']}"}
    gid = c.post("/v1/me/guardians", json={"mobile": RAVI}, headers=A).json()["id"]
    c.post(f"/v1/guardian/invitations/{gid}/accept", headers=G)
    telco = {"X-Api-Key": c.post("/v1/admin/participants", headers={"X-Admin-Token": "adm"},
                                 json={"name": "T", "kind": "telecom", "regulator_ref": "DOT-1"}).json()["api_key"]}
    c.post("/v1/signals/operator-events", headers=telco, json={"events": [
        {"event_id": "d1", "type": "disconnected", "mobile": RAVI, "occurred_at": iso(clock.now())}]})
    c.post("/v1/auth/logout", json={"everywhere": True}, headers=G)  # Ravi has no phone signed in

    r = c.post("/v1/recovery/start", json={"old_mobile": RAVI, "new_mobile": NEW, "code": code_for(NEW)})
    assert r.status_code == 202
    token = r.json()["recovery_token"]
    pending = c.get("/v1/guardian/recoveries", headers=A).json()
    assert pending[0]["person_name"] == "Ravi"
    assert c.post(f"/v1/guardian/recoveries/{pending[0]['recovery_id']}/approve", headers=A).json()["status"] == "held"
    clock.advance(hours=RECOVERY_HOLD_HOURS + 1)
    c.post("/v1/admin/sweep", headers={"X-Admin-Token": "adm"})
    assert c.post("/v1/recovery/status", json={"recovery_token": token}).json()["status"] == "completed"
    back = sign_in(NEW, None, "ravi-new-phone")
    assert back["user_id"] == ravi["user_id"] and back["new_user"] is False
    assert back["restricted"] is True  # a new device starts on probation, as always
    assert c.post("/v1/recovery/status", json={"recovery_token": "grr_nope_nope"}).status_code == 404
