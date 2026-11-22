"""HTTP-level tests: auth, status codes and a full family scenario over the wire."""

import pytest
from fastapi.testclient import TestClient

from guardian_registry.api import create_app
from guardian_registry.clock import FixedClock
from guardian_registry.db import Database
from guardian_registry.service import LOOSENING_DELAY_HOURS, Registry

from .conftest import AMMA, PRIYA, RAVI, R

ADMIN = "test-admin-token"


@pytest.fixture
def clock():
    return FixedClock()


@pytest.fixture
def client(clock):
    return TestClient(create_app(Registry(Database(), clock), admin_token=ADMIN))


def bearer(t):
    return {"Authorization": f"Bearer {t}"}


@pytest.fixture
def world(client):
    amma = client.post("/v1/users", json={"mobile": AMMA, "display_name": "Amma"}).json()
    ravi = client.post("/v1/users", json={"mobile": RAVI, "display_name": "Ravi"}).json()
    bank = client.post("/v1/admin/participants", json={"name": "Demo Bank"},
                       headers={"X-Admin-Token": ADMIN}).json()
    g = client.post("/v1/me/guardians", json={"mobile": RAVI}, headers=bearer(amma["token"])).json()
    client.post(f"/v1/guardian/invitations/{g['id']}/accept", headers=bearer(ravi["token"]))
    client.patch("/v1/me/rules", headers=bearer(amma["token"]), json={
        "per_txn_limit": 50_000 * R, "daily_limit": 75_000 * R,
        "approval_threshold": 10_000 * R, "new_payee_delay_threshold": 5_000 * R})
    return {"amma": amma, "ravi": ravi, "bank": {"X-Api-Key": bank["api_key"]}, "link": g["id"]}


def check(client, w, txn, rupees, payee="shop@upi", **kw):
    return client.post("/v1/checks", headers=w["bank"], json={
        "mobile": AMMA, "participant_txn_id": txn, "amount": round(rupees * R), "payee": payee, **kw})


class TestAuth:
    def test_health(self, client):
        assert client.get("/healthz").json()["ok"] is True

    def test_admin_requires_token(self, client):
        assert client.post("/v1/admin/participants", json={"name": "X"}).status_code == 401
        assert client.post("/v1/admin/participants", json={"name": "X"},
                           headers={"X-Admin-Token": "wrong"}).status_code == 401

    def test_admin_disabled_without_config(self, clock):
        c = TestClient(create_app(Registry(Database(), clock), admin_token=""))
        assert c.post("/v1/admin/participants", json={"name": "X"},
                      headers={"X-Admin-Token": ""}).status_code == 503

    def test_checks_require_api_key(self, client, world):
        r = client.post("/v1/checks", json={"mobile": AMMA, "participant_txn_id": "a", "amount": 1, "payee": "p"})
        assert r.status_code == 401
        r = client.post("/v1/checks", headers={"X-Api-Key": "bad"},
                        json={"mobile": AMMA, "participant_txn_id": "a", "amount": 1, "payee": "p"})
        assert r.status_code == 401

    def test_user_routes_require_bearer(self, client):
        assert client.get("/v1/me").status_code == 401
        assert client.get("/v1/me", headers=bearer("nope")).status_code == 401

    def test_user_token_is_not_a_bank_key(self, client, world):
        r = client.post("/v1/checks", headers={"X-Api-Key": world["amma"]["token"]},
                        json={"mobile": AMMA, "participant_txn_id": "a", "amount": 1, "payee": "p"})
        assert r.status_code == 401


class TestErrors:
    def test_duplicate_enrol_409(self, client, world):
        r = client.post("/v1/users", json={"mobile": AMMA, "display_name": "Again"})
        assert r.status_code == 409 and r.json()["error"] == "Conflict"

    def test_bad_mobile_422(self, client):
        assert client.post("/v1/users", json={"mobile": "12", "display_name": "X"}).status_code == 422

    def test_unknown_rule_field_422(self, client, world):
        r = client.patch("/v1/me/rules", headers=bearer(world["amma"]["token"]), json={"kill_switch": False})
        assert r.status_code == 422

    def test_bad_channel_422(self, client, world):
        assert check(client, world, "c", 10, channel="pigeon").status_code == 422

    def test_outsider_403(self, client, world):
        priya = client.post("/v1/users", json={"mobile": PRIYA, "display_name": "Priya"}).json()
        amma_id = world["amma"]["user_id"]
        r = client.post(f"/v1/guardian/wards/{amma_id}/kill-switch/on", headers=bearer(priya["token"]))
        assert r.status_code == 403
        assert client.get(f"/v1/guardian/wards/{amma_id}/rules", headers=bearer(priya["token"])).status_code == 403

    def test_unknown_check_404(self, client, world):
        assert client.get("/v1/checks/chk_nope", headers=world["bank"]).status_code == 404


class TestScenario:
    def test_scam_call_is_stopped(self, client, world, clock):
        """A scammer pressures Amma into a ₹40,000 transfer and then into turning protection off."""
        amma, ravi = bearer(world["amma"]["token"]), bearer(world["ravi"]["token"])

        r = check(client, world, "scam-1", 40_000, payee="refund-desk@upi").json()
        assert r["outcome"] == "needs_approval" and r["may_execute"] is False

        inbox = client.get("/v1/guardian/inbox", headers=ravi).json()
        assert inbox["held_payments"][0]["check_id"] == r["check_id"]
        assert inbox["held_payments"][0]["amount"] == 40_000 * R

        assert client.post(f"/v1/guardian/payments/{r['check_id']}/deny", headers=ravi).json()["status"] == "denied"
        assert client.get(f"/v1/checks/{r['check_id']}", headers=world["bank"]).json()["may_execute"] is False

        # scammer: "switch off your limits"
        held = client.patch("/v1/me/rules", headers=amma, json={"approval_threshold": None}).json()
        assert held["held"]["applied"] is False
        change_id = held["held"]["change"]["id"]
        assert client.get("/v1/guardian/inbox", headers=ravi).json()["pending_changes"][0]["id"] == change_id
        client.post(f"/v1/guardian/changes/{change_id}/veto", headers=ravi)
        clock.advance(hours=LOOSENING_DELAY_HOURS + 1)
        assert client.get("/v1/me/rules", headers=amma).json()["approval_threshold"] == 10_000 * R

        # Ravi locks everything while he visits
        client.post(f"/v1/guardian/wards/{world['amma']['user_id']}/kill-switch/on", headers=ravi)
        assert check(client, world, "after-lock", 10).json()["outcome"] == "block"

        trail = client.get("/v1/me/audit", headers=amma).json()
        assert {"check.denied", "change.vetoed", "kill_switch.on"} <= {e["action"] for e in trail}
        assert client.get("/v1/admin/audit/verify", headers={"X-Admin-Token": ADMIN}).json()["ok"] is True

    def test_genuine_payment_flow(self, client, world, clock):
        """Amma pays a new plumber ₹6,000: cooling-off, then released, then completed."""
        r = check(client, world, "plumber", 6_000, payee="plumber@upi").json()
        assert r["outcome"] == "delay" and r["status"] == "cooling_off"
        clock.advance(minutes=60)
        r = client.get(f"/v1/checks/{r['check_id']}", headers=world["bank"]).json()
        assert r["status"] == "released" and r["may_execute"]
        done = client.post(f"/v1/checks/{r['check_id']}/outcome", headers=world["bank"], json={"completed": True}).json()
        assert done["completed_at"] and done["may_execute"] is False
        assert check(client, world, "plumber-2", 6_000, payee="plumber@upi").json()["outcome"] == "allow"

    def test_approved_payment(self, client, world):
        r = check(client, world, "fees", 15_000).json()
        out = client.post(f"/v1/guardian/payments/{r['check_id']}/approve",
                          headers=bearer(world["ravi"]["token"])).json()
        assert out["status"] == "approved"
        assert client.get(f"/v1/checks/{r['check_id']}", headers=world["bank"]).json()["may_execute"] is True

    def test_vouch_and_history(self, client, world):
        ravi = bearer(world["ravi"]["token"])
        aid = world["amma"]["user_id"]
        r = client.post(f"/v1/guardian/wards/{aid}/trusted-payees", headers=ravi, json={"payee": "pharmacy@upi"})
        assert r.status_code == 201
        assert check(client, world, "med", 7_000, payee="pharmacy@upi").json()["outcome"] == "allow"
        assert len(client.get(f"/v1/guardian/wards/{aid}/payments", headers=ravi).json()) == 1
        assert len(client.get("/v1/me/payments", headers=bearer(world["amma"]["token"])).json()) == 1

    def test_not_enrolled_customer_passes_through(self, client, world):
        r = client.post("/v1/checks", headers=world["bank"], json={
            "mobile": "9000000001", "participant_txn_id": "x", "amount": 100, "payee": "a@upi"}).json()
        assert r["enrolled"] is False and r["may_execute"] is True

    def test_openapi_docs_build(self, client):
        spec = client.get("/openapi.json").json()
        assert "/v1/checks" in spec["paths"]
