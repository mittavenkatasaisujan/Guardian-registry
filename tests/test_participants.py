"""Participant trust: kinds, capabilities, four-eyes onboarding, suspension and offboarding."""

import pytest
from fastapi.testclient import TestClient

from guardian_registry.api import create_app, parse_operators
from guardian_registry.audit import verify
from guardian_registry.db import Database
from guardian_registry.errors import Conflict, Forbidden, Invalid
from guardian_registry.notify import LogSmsSender
from guardian_registry.service import Registry

from .conftest import AMMA, R, RAVI, new_db


def pending(reg, name="New Bank", kind="bank", ref="RBI-001", caps=None, op="alice"):
    return reg.register_participant(name, kind, ref, caps, operator=op, activate=False)


def verified_amma(reg, family, bank=None):
    a = reg.attest(bank or family["bank"], AMMA, "full", "C-1", "2025-01-15", "1950-01-01")
    reg.respond_to_attestation(family["amma"], a["attestation_id"], True)
    return a


class TestKinds:
    def test_defaults_follow_kind(self, reg):
        bank, _ = reg.register_participant("B", "bank", "RBI-1")
        app, _ = reg.register_participant("App", "tpap", "NPCI-1")
        wallet, _ = reg.register_participant("W", "ppi_issuer", "RBI-PPI-1")
        assert reg.participant_view(bank)["capabilities"] == ["checks", "kyc_full", "kyc_minimum", "sim_signals"]
        assert reg.participant_view(app)["capabilities"] == ["checks"]
        assert reg.participant_view(wallet)["capabilities"] == ["checks", "kyc_minimum"]
        assert reg.participant_view(app)["kind_allows"] == ["checks", "sim_signals"]

    def test_kind_is_a_ceiling(self, reg):
        with pytest.raises(Invalid, match="may not be granted"):
            reg.register_participant("App", "tpap", "NPCI-1", ["checks", "kyc_full"])
        with pytest.raises(Invalid, match="unknown capabilities"):
            reg.register_participant("App", "tpap", "NPCI-1", ["teleport"])
        with pytest.raises(Invalid, match="kind must be"):
            reg.register_participant("X", "casino", "X-1")

    def test_regulator_ref_is_unique(self, reg):
        reg.register_participant("A", "bank", "RBI-1")
        with pytest.raises(Conflict, match="regulator reference"):
            reg.register_participant("B", "bank", "RBI-1")

    def test_upi_app_cannot_vouch_for_identity(self, reg, family):
        app, _ = reg.register_participant("App", "tpap", "NPCI-1")
        with pytest.raises(Forbidden, match="kyc_full"):
            reg.attest(app, AMMA, "full", "C-1", "2025-01-15")
        assert reg.check(app, AMMA, "t1", 100 * R, "known@upi")["status"] == "allowed"

    def test_wallet_limited_to_minimum_kyc(self, reg, family):
        wallet, _ = reg.register_participant("W", "ppi_issuer", "RBI-PPI-1")
        with pytest.raises(Forbidden):
            reg.attest(wallet, AMMA, "full", "C-1", "2025-01-15")
        a = reg.attest(wallet, AMMA, "minimum", "C-1", "2025-01-15")
        reg.respond_to_attestation(family["amma"], a["attestation_id"], True)
        assert reg.identity_level(family["amma"]) == "bank_min_kyc"

    def test_sim_signals_need_the_capability(self, reg, family):
        app, _ = reg.register_participant("App", "tpap", "NPCI-1")
        with pytest.raises(Forbidden, match="sim_signals"):
            reg.report_sim_change(app, AMMA)
        assert reg.report_sim_change(family["bank"], AMMA)["window_open"] is True


class TestFourEyes:
    def test_pending_participant_can_do_nothing_yet(self, reg, family):
        pid, key = pending(reg)
        assert reg.participant_by_key(key) == pid  # can authenticate (webhook setup, status)
        assert reg.participant_view(pid)["status"] == "pending"
        assert reg.participant_view(pid)["pending_request"]["action"] == "activate"
        for call in (lambda: reg.check(pid, AMMA, "t1", 100 * R, "x@upi"),
                     lambda: reg.attest(pid, AMMA, "full", "C", "2025-01-15"),
                     lambda: reg.report_sim_change(pid, AMMA)):
            with pytest.raises(Forbidden, match="awaiting operator approval"):
                call()
        reg.set_webhook(pid, "https://bank.example/hook")  # allowed while pending

    def test_registrar_cannot_approve_own_request(self, reg, family):
        pid, _ = pending(reg, op="alice")
        with pytest.raises(Forbidden, match="four-eyes"):
            reg.approve_participant_request("alice", pid)
        v = reg.approve_participant_request("bob", pid)
        assert v["status"] == "active" and v["pending_request"] is None
        assert reg.check(pid, AMMA, "t1", 100 * R, "known@upi")["status"] == "allowed"

    def test_reject_drops_request(self, reg):
        pid, _ = pending(reg)
        reg.reject_participant_request("alice", pid)
        assert reg.participant_view(pid)["status"] == "pending"
        with pytest.raises(Conflict, match="nothing is waiting"):
            reg.approve_participant_request("bob", pid)

    def test_operator_names_in_audit(self, reg):
        pid, _ = pending(reg, op="alice")
        reg.approve_participant_request("bob", pid)
        actions = [(r["actor"], r["action"]) for r in reg.db.all("SELECT actor, action FROM audit_log")]
        assert ("operator:alice", "participant.registered") in actions
        assert ("operator:bob", "participant.activate_approved") in actions
        assert verify(reg.db.conn).ok


class TestCapabilities:
    def test_removal_is_instant_addition_needs_second_operator(self, reg, family):
        app, _ = reg.register_participant("App", "tpap", "NPCI-1")
        v = reg.set_participant_capabilities("alice", app, ["checks", "sim_signals"])
        assert v["capabilities"] == ["checks"]
        assert v["pending_request"] == {"action": "grant", "requested_by": "alice",
                                        "requested_at": v["pending_request"]["requested_at"],
                                        "capabilities": ["sim_signals"]}
        with pytest.raises(Forbidden):
            reg.report_sim_change(app, AMMA)
        with pytest.raises(Forbidden, match="four-eyes"):
            reg.approve_participant_request("alice", app)
        reg.approve_participant_request("bob", app)
        assert reg.report_sim_change(app, AMMA)["window_open"] is True

        v = reg.set_participant_capabilities("alice", app, ["sim_signals"])
        assert v["capabilities"] == ["sim_signals"] and v["pending_request"] is None
        with pytest.raises(Forbidden, match="'checks'"):
            reg.check(app, AMMA, "t9", 100 * R, "known@upi")

    def test_cannot_grant_beyond_kind(self, reg):
        app, _ = reg.register_participant("App", "tpap", "NPCI-1")
        with pytest.raises(Invalid):
            reg.set_participant_capabilities("alice", app, ["checks", "kyc_full"])


class TestSuspension:
    def test_suspend_blocks_new_work_but_not_closing_old(self, reg, family):
        bank = family["bank"]
        c = reg.check(bank, AMMA, "t1", 100 * R, "known@upi")
        reg.suspend_participant("alice", bank, "key leaked")
        with pytest.raises(Forbidden, match="suspended"):
            reg.check(bank, AMMA, "t2", 100 * R, "known@upi")
        assert reg.get_check(bank, c["check_id"])["status"] == "allowed"
        assert reg.report_outcome(bank, c["check_id"], True)["completed_at"] is not None
        reg.rotate_participant_key(bank)  # it should be able to fix a leaked key

    def test_suspended_bank_kyc_stops_counting(self, reg, family):
        verified_amma(reg, family)
        assert reg.identity_level(family["amma"]) == "bank_verified"
        reg.suspend_participant("alice", family["bank"], "regulator inquiry")
        assert reg.identity_level(family["amma"]) == "otp"
        assert reg.age_facts(family["amma"])["senior"] is None
        reg.request_reinstatement("alice", family["bank"])
        assert reg.participant_view(family["bank"])["status"] == "suspended"
        reg.approve_participant_request("bob", family["bank"])
        assert reg.identity_level(family["amma"]) == "bank_verified"

    def test_suspension_affects_verified_guardian_rule(self, reg, family):
        verified_ravi = reg.attest(family["bank"], RAVI, "full", "C-2", "2025-01-15")
        reg.respond_to_attestation(family["ravi"], verified_ravi["attestation_id"], True)
        reg.update_rules(family["amma"], {"require_verified_guardian": True})
        assert reg._approver_ids(family["amma"]) == [family["ravi"]]
        reg.suspend_participant("alice", family["bank"], "bad data")
        assert reg._approver_ids(family["amma"]) == []

    def test_suspend_cancels_pending_activation_and_grant(self, reg):
        pid, _ = pending(reg)
        reg.suspend_participant("bob", pid, "failed due diligence")
        v = reg.participant_view(pid)
        assert v["status"] == "suspended" and v["pending_request"] is None

    def test_validation(self, reg, family):
        with pytest.raises(Invalid):
            reg.suspend_participant("alice", family["bank"], " ")
        with pytest.raises(Conflict):
            reg.request_reinstatement("alice", family["bank"])
        reg.suspend_participant("alice", family["bank"], "x-ray")
        with pytest.raises(Conflict):
            reg.suspend_participant("alice", family["bank"], "again")


class TestOffboarding:
    def test_offboard_is_permanent_and_revokes_kyc(self, reg, family):
        bank = family["bank"]
        verified_amma(reg, family)
        reg.check(bank, AMMA, "t1", 100 * R, "known@upi")
        key = reg.rotate_participant_key(bank)["api_key"]
        reg.set_webhook(bank, "https://bank.example/hook")
        v = reg.offboard_participant("alice", bank, "left the network")
        assert v["status"] == "offboarded" and v["webhook_url"] is None
        assert reg.participant_by_key(key) is None
        assert reg.identity_level(family["amma"]) == "otp"
        att = reg.identity(family["amma"])["attestations"][0]
        assert att["status"] == "revoked"
        n = [n for n in reg.notifications(family["amma"]) if n["kind"] == "kyc_revoked"]
        assert n and "has left Guardian Registry" in n[0]["body"]
        with pytest.raises(Conflict):
            reg.request_reinstatement("bob", bank)
        with pytest.raises(Conflict):
            reg.offboard_participant("bob", bank, "again")

    def test_sim_window_from_offboarded_bank_stays_open(self, reg, family):
        reg.report_sim_change(family["bank"], AMMA)
        reg.offboard_participant("alice", family["bank"], "left")
        assert reg.sim_swap_active(family["amma"])


class TestMigration:
    def test_old_participants_become_active_banks(self, tmp_path):
        from guardian_registry import db as dbmod
        path = str(tmp_path / "old.db")
        old = dbmod.Database.__new__(dbmod.Database)
        import sqlite3
        conn = sqlite3.connect(path, isolation_level=None)
        for i, script in enumerate(dbmod.MIGRATIONS[:4], start=1):
            conn.executescript(f"BEGIN;\n{script}\nPRAGMA user_version = {i};\nCOMMIT;")
        conn.execute("INSERT INTO participants (id, name, key_hash, created_at) VALUES ('p1','Old','h','t')")
        conn.close()
        del old
        reg = Registry(Database(path))
        v = reg.participant_view("p1")
        assert v["status"] == "active" and v["kind"] == "bank"
        assert v["capabilities"] == ["checks", "kyc_full", "kyc_minimum", "sim_signals"]


# ------------------------------------------------------------------------ API
OPS = {"alice": "alice-token-0000001", "bob": "bob-token-00000002"}
A = {"X-Admin-Token": OPS["alice"]}
B = {"X-Admin-Token": OPS["bob"]}


@pytest.fixture
def client(clock):
    return TestClient(create_app(Registry(new_db(), clock), operators=OPS, sms=LogSmsSender(), run_worker=False))


def test_parse_operators():
    assert parse_operators("alice:t1, bob:t2") == {"alice": "t1", "bob": "t2"}
    assert parse_operators("") == {}
    for bad in ("alice", "alice:", "a:t,a:u", "a:t,b:t"):
        with pytest.raises(RuntimeError):
            parse_operators(bad)


def test_production_refuses_single_operator(monkeypatch, clock):
    monkeypatch.setenv("GR_ENV", "production")
    monkeypatch.setattr("guardian_registry.api.check_production_config", lambda: None)
    with pytest.raises(RuntimeError, match="at least two operators"):
        create_app(Registry(new_db(), clock), operators={"solo": "x" * 20}, run_worker=False)


class TestApi:
    def test_four_eyes_onboarding(self, client):
        r = client.post("/v1/admin/participants", headers=A,
                        json={"name": "Bank A", "kind": "bank", "regulator_ref": "RBI-9"})
        assert r.status_code == 201
        body = r.json()
        assert body["status"] == "pending" and body["created_by"] == "alice"
        key = {"X-Api-Key": body["api_key"]}
        pid = body["participant_id"]

        assert client.get("/v1/participant/me", headers=key).json()["status"] == "pending"
        r = client.post("/v1/checks", headers=key, json={"mobile": AMMA, "participant_txn_id": "t",
                                                         "amount": 100, "payee": "x@upi"})
        assert r.status_code == 403 and "awaiting operator approval" in r.json()["detail"]

        assert client.post(f"/v1/admin/participants/{pid}/approve", headers=A).status_code == 403
        assert client.post(f"/v1/admin/participants/{pid}/approve", headers=B).json()["status"] == "active"
        assert client.get("/v1/participant/me", headers=key).json()["capabilities"][0] == "checks"
        assert [p["participant_id"] for p in client.get("/v1/admin/participants?status=active",
                                                         headers=A).json()] == [pid]

    def test_kind_ceiling_and_validation(self, client):
        r = client.post("/v1/admin/participants", headers=A,
                        json={"name": "App", "kind": "tpap", "regulator_ref": "NPCI-1", "capabilities": ["kyc_full"]})
        assert r.status_code == 422
        r = client.post("/v1/admin/participants", headers=A, json={"name": "App", "kind": "tpap"})
        assert r.status_code == 422  # regulator_ref required

    def test_suspend_reinstate_capabilities_offboard(self, client):
        pid = client.post("/v1/admin/participants", headers=A,
                          json={"name": "App", "kind": "tpap", "regulator_ref": "NPCI-1"}).json()["participant_id"]
        client.post(f"/v1/admin/participants/{pid}/approve", headers=B)

        v = client.put(f"/v1/admin/participants/{pid}/capabilities", headers=A,
                       json={"capabilities": ["checks", "sim_signals"]}).json()
        assert v["pending_request"]["capabilities"] == ["sim_signals"]
        assert client.post(f"/v1/admin/participants/{pid}/approve", headers=B).json()["capabilities"] == \
            ["checks", "sim_signals"]

        assert client.post(f"/v1/admin/participants/{pid}/suspend", headers=A,
                           json={"reason": "audit"}).json()["status"] == "suspended"
        client.post(f"/v1/admin/participants/{pid}/reinstate", headers=A)
        assert client.post(f"/v1/admin/participants/{pid}/approve", headers=B).json()["status"] == "active"

        assert client.post(f"/v1/admin/participants/{pid}/offboard", headers=B,
                           json={"reason": "left"}).json()["status"] == "offboarded"
        assert client.get(f"/v1/admin/participants/{pid}", headers=A).json()["status"] == "offboarded"

    def test_single_dev_operator_auto_approves(self, clock):
        c = TestClient(create_app(Registry(new_db(), clock), admin_token="dev", sms=LogSmsSender(),
                                  run_worker=False))
        body = c.post("/v1/admin/participants", headers={"X-Admin-Token": "dev"},
                      json={"name": "B", "regulator_ref": "RBI-1"}).json()
        assert body["status"] == "active"

    def test_operator_auth(self, client):
        assert client.get("/v1/admin/participants").status_code == 401
        assert client.get("/v1/admin/participants", headers={"X-Admin-Token": "nope"}).status_code == 401
