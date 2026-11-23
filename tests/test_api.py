"""HTTP-level tests: auth, status codes and a full family scenario over the wire."""

import re

import pytest
from fastapi.testclient import TestClient

from guardian_registry.api import create_app
from guardian_registry.clock import FixedClock
from guardian_registry.db import Database
from guardian_registry.notify import LogSmsSender
from guardian_registry.service import LOOSENING_DELAY_HOURS, OTP_RESEND_SECONDS, Registry

from .conftest import AMMA, PRIYA, R, RAVI, new_db

ADMIN = "test-admin-token"


@pytest.fixture
def clock():
    return FixedClock()


@pytest.fixture
def sms():
    return LogSmsSender()


@pytest.fixture
def client(clock, sms):
    return TestClient(create_app(Registry(new_db(), clock), admin_token=ADMIN, sms=sms, run_worker=False))


def sign_in(client, sms, mobile, name=None):
    """Full OTP flow: request a code, read it from the (fake) SMS, verify it."""
    assert client.post("/v1/auth/otp", json={"mobile": mobile}).status_code == 202
    code = re.search(r"code: (\d{6})", sms.sent[-1][1]).group(1)
    r = client.post("/v1/auth/verify", json={"mobile": mobile, "code": code, "display_name": name})
    assert r.status_code == 200, r.text
    return r.json()


def bearer(t):
    return {"Authorization": f"Bearer {t}"}


@pytest.fixture
def world(client, sms):
    amma = sign_in(client, sms, AMMA, "Amma")
    ravi = sign_in(client, sms, RAVI, "Ravi")
    bank = client.post("/v1/admin/participants", json={"name": "Demo Bank", "regulator_ref": "RBI-TEST-1"},
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
        c = TestClient(create_app(Registry(new_db(), clock), admin_token=""))
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
    def test_sign_in_again_logs_in_same_user(self, client, world, sms, clock):
        clock.advance(seconds=OTP_RESEND_SECONDS)
        again = sign_in(client, sms, AMMA, "Ignored")
        assert again["new_user"] is False and again["user_id"] == world["amma"]["user_id"]

    def test_bad_mobile_422(self, client):
        assert client.post("/v1/auth/otp", json={"mobile": "12"}).status_code == 422

    def test_unknown_rule_field_422(self, client, world):
        r = client.patch("/v1/me/rules", headers=bearer(world["amma"]["token"]), json={"kill_switch": False})
        assert r.status_code == 422

    def test_bad_channel_422(self, client, world):
        assert check(client, world, "c", 10, channel="pigeon").status_code == 422

    def test_outsider_403(self, client, world):
        priya = sign_in(client, client.app.state.dispatcher.sms, PRIYA, "Priya")
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


class TestSignIn:
    def test_wrong_code_401(self, client):
        client.post("/v1/auth/otp", json={"mobile": AMMA})
        r = client.post("/v1/auth/verify", json={"mobile": AMMA, "code": "abcdef", "display_name": "A"})
        assert r.status_code == 401

    def test_resend_too_soon_429(self, client):
        client.post("/v1/auth/otp", json={"mobile": AMMA})
        assert client.post("/v1/auth/otp", json={"mobile": AMMA}).status_code == 429

    def test_response_does_not_leak_code_or_enrolment(self, client, world):
        r = client.post("/v1/auth/otp", json={"mobile": "9000000002"}).json()
        assert r == {"sent": True, "expires_in_seconds": 300}

    def test_dev_echo_only_when_enabled(self, clock, monkeypatch):
        monkeypatch.setenv("GR_OTP_DEV_ECHO", "1")
        c = TestClient(create_app(Registry(new_db(), clock), admin_token=ADMIN, sms=LogSmsSender(), run_worker=False))
        assert len(c.post("/v1/auth/otp", json={"mobile": AMMA}).json()["dev_code"]) == 6

    def test_ip_rate_limit(self, clock):
        c = TestClient(create_app(Registry(new_db(), clock), admin_token=ADMIN, sms=LogSmsSender(),
                                  run_worker=False, otp_rate="2/60"))
        assert c.post("/v1/auth/otp", json={"mobile": "9000000011"}).status_code == 202
        assert c.post("/v1/auth/otp", json={"mobile": "9000000012"}).status_code == 202
        r = c.post("/v1/auth/otp", json={"mobile": "9000000013"})
        assert r.status_code == 429 and int(r.headers["Retry-After"]) >= 1

    def test_logout(self, client, world):
        t = bearer(world["amma"]["token"])
        assert client.post("/v1/auth/logout", json={}, headers=t).status_code == 204
        assert client.get("/v1/me", headers=t).status_code == 401


class TestAlertsOverHttp:
    def test_guardian_sees_alert_and_gets_sms(self, client, world, sms):
        r = check(client, world, "alert-1", 25_000).json()
        feed = client.get("/v1/guardian/inbox", headers=bearer(world["ravi"]["token"])).json()
        assert feed["held_payments"][0]["check_id"] == r["check_id"]
        notes = client.get("/v1/me/notifications", headers=bearer(world["ravi"]["token"])).json()
        assert notes[0]["kind"] == "approval_needed" and "₹25,000.00" in notes[0]["body"]
        out = client.post("/v1/admin/sweep", headers={"X-Admin-Token": ADMIN}).json()
        assert out["delivered"] >= 1
        assert any("Approve payment?" in text for to, text in sms.sent if to.endswith(RAVI))
        marked = client.post("/v1/me/notifications/read", json={}, headers=bearer(world["ravi"]["token"])).json()
        assert marked["marked"] >= 1
        assert client.get("/v1/me/notifications?unread_only=true",
                          headers=bearer(world["ravi"]["token"])).json() == []

    def test_presets_endpoint(self, client, world):
        assert "senior_with_guardian" in client.get("/v1/presets").json()
        r = client.post("/v1/me/rules/preset/strict", headers=bearer(world["amma"]["token"])).json()
        assert r["rules"]["blocked_channels"] == ["rtgs"]
        assert client.post("/v1/me/rules/preset/nope", headers=bearer(world["amma"]["token"])).status_code == 404


class TestBankFeatures:
    def test_webhook_registration_and_key_rotation(self, client, world):
        r = client.put("/v1/participant/webhook", headers=world["bank"], json={"url": "https://bank.example/h"}).json()
        assert r["webhook_secret"].startswith("whs_")
        assert client.put("/v1/participant/webhook", headers=world["bank"],
                          json={"url": "http://evil.example/h"}).status_code == 422
        new = client.post("/v1/participant/rotate-key", headers=world["bank"]).json()
        assert client.get("/healthz").status_code == 200
        assert check(client, world, "old-key", 10).status_code == 200            # grace period
        assert client.post("/v1/checks", headers={"X-Api-Key": new["api_key"]}, json={
            "mobile": AMMA, "participant_txn_id": "new-key", "amount": 1000, "payee": "a@upi"}).status_code == 200

    def test_check_rate_limit(self, clock, sms):
        c = TestClient(create_app(Registry(new_db(), clock), admin_token=ADMIN, sms=sms,
                                  run_worker=False, check_rate="3/60"))
        key = c.post("/v1/admin/participants", json={"name": "B", "regulator_ref": "RBI-TEST-1"}, headers={"X-Admin-Token": ADMIN}).json()["api_key"]
        codes = [c.post("/v1/checks", headers={"X-Api-Key": key}, json={
            "mobile": "9000000001", "participant_txn_id": f"r{i}", "amount": 100, "payee": "a@upi"}).status_code
            for i in range(4)]
        assert codes == [200, 200, 200, 429]


class TestWorker:
    def test_worker_runs_in_lifespan(self, monkeypatch):
        """A cooling-off payment is released by the background worker on its own, without any read."""
        monkeypatch.setenv("GR_WORKER_INTERVAL", "0.05")
        clock = FixedClock()
        reg = Registry(new_db(), clock)
        sms = LogSmsSender()
        app = create_app(reg, admin_token=ADMIN, sms=sms, run_worker=True)
        with TestClient(app) as c:
            amma = sign_in(c, sms, AMMA, "Amma")
            c.patch("/v1/me/rules", headers=bearer(amma["token"]),
                    json={"new_payee_delay_threshold": 100})  # tightening: applies now, 60-min wait
            key = c.post("/v1/admin/participants", json={"name": "B", "regulator_ref": "RBI-TEST-1"}, headers={"X-Admin-Token": ADMIN}).json()["api_key"]
            r = c.post("/v1/checks", headers={"X-Api-Key": key}, json={
                "mobile": AMMA, "participant_txn_id": "w1", "amount": 500, "payee": "new@upi"}).json()
            assert r["status"] == "cooling_off"
            clock.advance(minutes=60)
            import time
            for _ in range(60):
                row = reg.db.one("SELECT status FROM checks WHERE id=?", (r["check_id"],))
                if row["status"] == "released":
                    break
                time.sleep(0.05)
            assert row["status"] == "released"
