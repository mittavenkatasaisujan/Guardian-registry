"""Official entity register, operator SSO, shared rate limits, WhatsApp and push alerts."""

import time

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

from guardian_registry.api import create_app
from guardian_registry.db import Database
from guardian_registry.errors import Invalid, NotFound
from guardian_registry.notify import Dispatcher, LogPushSender, LogSmsSender, LogWhatsAppSender
from guardian_registry.operator_auth import OidcVerifier, OperatorAuthError
from guardian_registry.ratelimit import SharedRateLimiter, make_limiter, RateLimiter
from guardian_registry.service import Registry

from .conftest import AMMA, R, RAVI, new_db

BANKS = [{"regulator_ref": "RBI-SCB-001", "name": "State Bank"}, {"regulator_ref": "RBI-SCB-002", "name": "Other Bank"}]


# ------------------------------------------------------------------ official register
class TestRegister:
    def test_no_list_no_check_in_development(self, reg):
        reg.register_participant("X", "bank", "anything", operator="a", activate=False)

    def test_ref_must_be_on_loaded_list(self, reg):
        out = reg.load_regulated_entities("alice", "bank", "https://rbi.org.in/list.xlsx", "2026-11-01", BANKS)
        assert out["entities"] == 2
        with pytest.raises(Invalid, match="not on the bank register"):
            reg.register_participant("Fake", "bank", "RBI-SCB-999", operator="alice", activate=False)
        pid, _ = reg.register_participant("State Bank", "bank", "RBI-SCB-001", operator="alice", activate=False)
        assert reg.participant_view(pid)["register_match"]["name"] == "State Bank"
        # lists are per kind: a UPI app isn't checked against the bank list
        reg.register_participant("App", "tpap", "NPCI-1", operator="alice", activate=False)

    def test_approval_rechecks_the_register(self, reg):
        reg.load_regulated_entities("alice", "bank", "src", "2026-11-01", BANKS)
        pid, _ = reg.register_participant("State Bank", "bank", "RBI-SCB-001", operator="alice", activate=False)
        reg.load_regulated_entities("alice", "bank", "src", "2026-12-01", BANKS[1:])  # licence gone
        with pytest.raises(Invalid):
            reg.approve_participant_request("bob", pid)

    def test_required_in_production(self, reg, monkeypatch):
        monkeypatch.setenv("GR_REQUIRE_ENTITY_REGISTER", "1")
        with pytest.raises(Invalid, match="no official register is loaded"):
            reg.register_participant("B", "bank", "RBI-1", operator="a", activate=False)

    def test_validation(self, reg):
        with pytest.raises(Invalid):
            reg.load_regulated_entities("a", "casino", "s", "d", BANKS)
        with pytest.raises(Invalid):
            reg.load_regulated_entities("a", "bank", "", "d", BANKS)
        with pytest.raises(Invalid):
            reg.load_regulated_entities("a", "bank", "s", "d", [BANKS[0], BANKS[0]])
        reg.load_regulated_entities("a", "bank", "s", "2026-11-01", BANKS)
        assert reg.register_status() == [{"kind": "bank", "entities": 2, "source": "s", "as_of": "2026-11-01"}]


# ------------------------------------------------------------------ SSO
KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
OTHER = rsa.generate_private_key(public_exponent=65537, key_size=2048)
ISS, AUD = "https://login.example.com", "guardian-registry-admin"


def id_token(email="alice@bank-ops.in", key=KEY, amr=("pwd", "hwk"), **over):
    now = int(time.time())
    claims = {"iss": ISS, "aud": AUD, "iat": now, "exp": now + 300, "email": email, "email_verified": True,
              "amr": list(amr), **over}
    return jwt.encode(claims, key, algorithm="RS256")


def verifier(require_hwk=True):
    return OidcVerifier(ISS, AUD, {"alice@bank-ops.in", "bob@bank-ops.in"}, require_hwk=require_hwk,
                        key_resolver=lambda t: KEY.public_key())


class TestSso:
    def test_valid(self):
        assert verifier().verify(id_token()) == "alice@bank-ops.in"

    @pytest.mark.parametrize("token,why", [
        (lambda: id_token(key=OTHER), "invalid"),
        (lambda: id_token(iss="https://evil.example"), "invalid"),
        (lambda: id_token(aud="other-app"), "invalid"),
        (lambda: id_token(exp=int(time.time()) - 600), "invalid"),
        (lambda: id_token(email="mallory@bank-ops.in"), "not an allowed"),
        (lambda: id_token(email_verified=False), "verified email"),
        (lambda: id_token(amr=("pwd", "otp")), "hardware security key"),
    ])
    def test_rejected(self, token, why):
        with pytest.raises(OperatorAuthError, match=why):
            verifier().verify(token())

    def test_hwk_optional(self):
        assert verifier(require_hwk=False).verify(id_token(amr=("pwd",)))

    def test_api_four_eyes_with_sso(self, clock):
        c = TestClient(create_app(Registry(new_db(), clock), operators={}, operator_sso=verifier(),
                                  sms=LogSmsSender(), run_worker=False))
        alice = {"Authorization": f"Bearer {id_token()}"}
        bob = {"Authorization": f"Bearer {id_token('bob@bank-ops.in')}"}
        p = c.post("/v1/admin/participants", headers=alice, json={"name": "B", "regulator_ref": "RBI-1"}).json()
        assert p["status"] == "pending" and p["created_by"] == "alice@bank-ops.in"
        assert c.post(f"/v1/admin/participants/{p['participant_id']}/approve", headers=alice).status_code == 403
        assert c.post(f"/v1/admin/participants/{p['participant_id']}/approve", headers=bob).json()["status"] == "active"
        r = c.get("/v1/admin/participants", headers={"Authorization": f"Bearer {id_token(amr=('pwd',))}"})
        assert r.status_code == 401 and "hardware" in r.json()["detail"]
        assert c.get("/v1/admin/participants", headers={"X-Admin-Token": "x"}).status_code == 401


# ------------------------------------------------------------------ shared limiter
class TestSharedLimiter:
    def test_two_nodes_share_one_limit(self):
        db = new_db()
        t = [1000.0]
        node_a = SharedRateLimiter(db, "otp", 3, 60, now=lambda: t[0])
        node_b = SharedRateLimiter(db, "otp", 3, 60, now=lambda: t[0])
        assert [node_a.hit("ip1")[0], node_b.hit("ip1")[0], node_a.hit("ip1")[0]] == [True, True, True]
        ok, retry = node_b.hit("ip1")
        assert ok is False and 0 < retry <= 60
        assert node_a.hit("ip2")[0] is True  # per key
        t[0] += 60
        assert node_b.hit("ip1")[0] is True  # next window

    def test_make_limiter(self):
        db = new_db()
        assert isinstance(make_limiter(db, "x", "5/60"), RateLimiter)
        assert isinstance(make_limiter(db, "x", "5/60", "db"), SharedRateLimiter)

    def test_api_uses_it(self, clock, monkeypatch):
        monkeypatch.setenv("GR_RATE_BACKEND", "db")
        reg = Registry(new_db(), clock)
        c = TestClient(create_app(reg, admin_token="a", sms=LogSmsSender(), run_worker=False, otp_rate="2/60"))
        codes = [c.post("/v1/auth/otp", json={"mobile": m}).status_code for m in (AMMA, RAVI, "9876500055")]
        assert codes == [202, 202, 429]
        assert reg.db.one("SELECT COUNT(*) n FROM rate_counters")["n"] >= 1


# ------------------------------------------------------------------ channels
@pytest.fixture
def senders(reg, clock):
    sms, wa, push = LogSmsSender(), LogWhatsAppSender(), LogPushSender()
    return sms, wa, push, Dispatcher(reg.db, clock, sms=sms, whatsapp=wa, push=push)


def held_payment(reg, family):
    return reg.check(family["bank"], AMMA, "t1", 20_000 * R, "known@upi")  # needs Ravi's approval


class TestChannels:
    def test_whatsapp_instead_of_sms(self, reg, family, senders):
        sms, wa, push, d = senders
        d.run_once()
        sms.sent.clear()
        reg.set_urgent_channel(family["ravi"], "whatsapp")
        held_payment(reg, family)
        d.run_once()
        assert wa.sent and wa.sent[0][1] == "Approve payment?" and not sms.sent

    def test_whatsapp_falls_back_to_sms(self, reg, family, clock):
        sms = LogSmsSender()
        d = Dispatcher(reg.db, clock, sms=sms, whatsapp=None, push=None)
        d.run_once()
        sms.sent.clear()
        reg.set_urgent_channel(family["ravi"], "whatsapp")
        held_payment(reg, family)
        d.run_once()
        assert sms.sent

    def test_push_to_each_device_even_during_sim_swap(self, reg, family, senders):
        sms, wa, push, d = senders
        reg.add_push_token(family["ravi"], "fcm-token-AAAAAAAA", "android")
        reg.add_push_token(family["ravi"], "apns-token-BBBBBBBB", "ios")
        reg.report_sim_change(family["bank"], RAVI)
        d.run_once()
        sms.sent.clear()
        push.sent.clear()
        held_payment(reg, family)
        d.run_once()
        assert {p[1] for p in push.sent if p[2] == "Approve payment?"} == {"android", "ios"}
        assert not [s for s in sms.sent if s[0].endswith("500002")]  # no SMS to the swapped number

    def test_tokens_encrypted_and_dropped_on_lost_phone(self, reg, family):
        reg.add_push_token(family["ravi"], "fcm-token-AAAAAAAA", "android")
        assert b"fcm-token" not in reg.db.one("SELECT token_enc FROM push_tokens")["token_enc"].encode()
        reg.report_lost_phone(family["ravi"], family["ravi"])
        assert reg.alert_settings(family["ravi"])["push_devices"] == []

    def test_token_moves_with_device_and_is_capped(self, reg, family):
        reg.add_push_token(family["ravi"], "shared-device-token", "android")
        reg.add_push_token(family["amma"], "shared-device-token", "android")
        assert reg.alert_settings(family["ravi"])["push_devices"] == []
        for i in range(7):
            reg.add_push_token(family["amma"], f"token-number-{i}", "web")
        assert len(reg.alert_settings(family["amma"])["push_devices"]) == 5

    def test_validation(self, reg, family):
        with pytest.raises(Invalid):
            reg.set_urgent_channel(family["ravi"], "pigeon")
        with pytest.raises(Invalid):
            reg.add_push_token(family["ravi"], "tok-tok-tok", "blackberry")
        with pytest.raises(NotFound):
            reg.remove_push_token(family["ravi"], "psh_nope")

    def test_api(self, clock):
        import re
        sms = LogSmsSender()
        c = TestClient(create_app(Registry(new_db(), clock), admin_token="a", sms=sms, run_worker=False))
        c.post("/v1/auth/otp", json={"mobile": AMMA})
        code = re.search(r"code: (\d{6})", sms.sent[-1][1]).group(1)
        tok = c.post("/v1/auth/verify", json={"mobile": AMMA, "code": code, "display_name": "Amma"}).json()["token"]
        H = {"Authorization": f"Bearer {tok}"}
        assert c.put("/v1/me/alerts", headers=H, json={"urgent_channel": "whatsapp"}).json()["urgent_channel"] == "whatsapp"
        out = c.post("/v1/me/alerts/push", headers=H, json={"token": "fcm-token-AAAAAAAA", "platform": "android"})
        assert out.status_code == 201
        dev = out.json()["push_devices"][0]["id"]
        assert c.delete(f"/v1/me/alerts/push/{dev}", headers=H).json()["push_devices"] == []


# ------------------------------------------------------------------ several nodes / threads
class TestNoDoubleProcessing:
    def test_two_dispatchers_send_each_alert_once(self, reg, family, clock):
        sms_a, sms_b = LogSmsSender(), LogSmsSender()
        a = Dispatcher(reg.db, clock, sms=sms_a, whatsapp=None, push=None)
        b = Dispatcher(reg.db, clock, sms=sms_b, whatsapp=None, push=None)
        a.run_once(), b.run_once()
        sms_a.sent.clear(), sms_b.sent.clear()
        held_payment(reg, family)
        import threading
        ts = [threading.Thread(target=d.run_once) for d in (a, b, a, b)]
        [t.start() for t in ts]
        [t.join() for t in ts]
        texts = [t for _, t in sms_a.sent + sms_b.sent if t.startswith("Approve payment?")]
        assert len(texts) == 1

    def test_claimed_alert_is_retried_after_lease(self, reg, family, clock):
        from guardian_registry.notify import LEASE_SECONDS
        held_payment(reg, family)
        row = reg.db.one("SELECT id, next_attempt_at FROM notifications WHERE status='pending' LIMIT 1")
        # a node claims it and dies before sending
        from guardian_registry.clock import iso
        from datetime import timedelta
        reg.db.conn.execute("UPDATE notifications SET next_attempt_at=? WHERE id=?",
                            (iso(clock.now() + timedelta(seconds=LEASE_SECONDS)), row["id"]))
        sms = LogSmsSender()
        d = Dispatcher(reg.db, clock, sms=sms, whatsapp=None, push=None)
        d.run_once()
        assert reg.db.one("SELECT status FROM notifications WHERE id=?", (row["id"],))["status"] == "pending"
        clock.advance(seconds=LEASE_SECONDS + 1)
        d.run_once()
        assert reg.db.one("SELECT status FROM notifications WHERE id=?", (row["id"],))["status"] == "sent"

    def test_veto_after_apply_and_apply_after_veto_conflict(self, reg, family, clock):
        from guardian_registry.errors import Conflict
        from guardian_registry.service import LOOSENING_DELAY_HOURS
        g = reg.invite_guardian(family["amma"], "9876500003")
        reg.respond_to_invite(family["priya"], g["id"], True)
        ch = reg.update_rules(family["amma"], {"daily_limit": None})["held"]
        cid = ch["change"]["id"]
        reg.veto_change(family["ravi"], cid)
        with pytest.raises(Conflict):
            reg.approve_change(family["priya"], cid)
        with pytest.raises(Conflict):
            reg.veto_change(family["priya"], cid)
        clock.advance(hours=LOOSENING_DELAY_HOURS + 1)
        reg.sweep()
        assert reg.get_rules(family["amma"]).daily_limit == 75_000 * R  # the veto stands
