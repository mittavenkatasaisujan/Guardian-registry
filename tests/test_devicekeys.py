"""Device-bound keys: signed sign-ins prove the same phone; SIM thieves can't."""

import base64
import re
from datetime import timedelta

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from fastapi.testclient import TestClient

from guardian_registry.api import create_app
from guardian_registry.devicekeys import NEW_KEY_PROBATION_HOURS, SIGNING_PREFIX, KeyAttestor, key_id_for
from guardian_registry.errors import Invalid, NotFound, Unauthorized
from guardian_registry.notify import LogSmsSender
from guardian_registry.service import OTP_RESEND_SECONDS, Registry

from .conftest import AMMA, R, RAVI, new_db


class Phone:
    """An app install with a key in 'secure hardware'."""

    def __init__(self):
        self.key = ec.generate_private_key(ec.SECP256R1())
        der = self.key.public_key().public_bytes(serialization.Encoding.DER,
                                                 serialization.PublicFormat.SubjectPublicKeyInfo)
        self.public = base64.b64encode(der).decode()
        self.key_id = key_id_for(self.public)

    def sign(self, challenge: str) -> str:
        return base64.b64encode(self.key.sign(SIGNING_PREFIX + challenge.encode(), ec.ECDSA(hashes.SHA256()))).decode()


def sign_in(reg, mobile, phone=None, name=None, tamper=False):
    sms = LogSmsSender()
    reg.clock.advance(seconds=OTP_RESEND_SECONDS + 1)
    code = reg.request_otp(mobile, sms)
    kw = {}
    if phone:
        ch = reg.new_challenge()["challenge"]
        kw = {"device_key": phone.public, "challenge": ch,
              "device_proof": phone.sign(ch + ("x" if tamper else ""))}
    return reg.verify_otp(mobile, code, name, None, **kw)


@pytest.fixture
def people(reg):
    amma_phone, ravi_phone = Phone(), Phone()
    amma = sign_in(reg, AMMA, amma_phone, "Amma")
    ravi = sign_in(reg, RAVI, ravi_phone, "Ravi")
    g = reg.invite_guardian(amma["user_id"], RAVI)
    reg.respond_to_invite(ravi["user_id"], g["id"], True)
    reg.update_rules(amma["user_id"], {"approval_threshold": 10_000 * R})
    bank, _ = reg.register_participant("Bank", "bank", "RBI-1")
    return {"amma": amma, "ravi": ravi, "ravi_phone": ravi_phone, "amma_phone": amma_phone, "bank": bank}


class TestProof:
    def test_first_key_trusted_at_once(self, reg, people):
        keys = reg.device_keys(people["ravi"]["user_id"])
        assert [k["status"] for k in keys] == ["trusted"]

    def test_same_phone_is_proven(self, reg, people):
        again = sign_in(reg, RAVI, people["ravi_phone"])
        assert again["device_proven"] is True and again["restricted"] is False

    def test_new_phone_starts_on_probation(self, reg, people):
        other = sign_in(reg, RAVI, Phone())
        assert other["device_proven"] is False and other["restricted"] is True
        assert [k["status"] for k in reg.device_keys(people["ravi"]["user_id"])] == ["trusted", "probation"]

    def test_bad_signature_and_reused_challenge(self, reg, people):
        with pytest.raises(Unauthorized, match="does not verify"):
            sign_in(reg, RAVI, people["ravi_phone"], tamper=True)
        ch = reg.new_challenge()["challenge"]
        reg.clock.advance(seconds=OTP_RESEND_SECONDS + 1)
        code = reg.request_otp(RAVI, LogSmsSender())
        proof = people["ravi_phone"].sign(ch)
        reg.verify_otp(RAVI, code, None, None, device_key=people["ravi_phone"].public, challenge=ch, device_proof=proof)
        reg.clock.advance(seconds=OTP_RESEND_SECONDS + 1)
        code = reg.request_otp(RAVI, LogSmsSender())
        with pytest.raises(Unauthorized, match="used or expired"):
            reg.verify_otp(RAVI, code, None, None, device_key=people["ravi_phone"].public, challenge=ch,
                           device_proof=proof)

    def test_expired_challenge(self, reg, people):
        ch = reg.new_challenge()["challenge"]
        reg.clock.advance(minutes=6)
        code = reg.request_otp(RAVI, LogSmsSender())
        with pytest.raises(Unauthorized):
            reg.verify_otp(RAVI, code, None, None, device_key=people["ravi_phone"].public, challenge=ch,
                           device_proof=people["ravi_phone"].sign(ch))

    def test_wrong_key_types(self, reg, people):
        rsa_pub = rsa.generate_private_key(public_exponent=65537, key_size=2048).public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        for key in (base64.b64encode(rsa_pub).decode(), "not base64!!", base64.b64encode(b"junk").decode()):
            ch = reg.new_challenge()["challenge"]
            reg.clock.advance(seconds=OTP_RESEND_SECONDS + 1)
            code = reg.request_otp(RAVI, LogSmsSender())
            with pytest.raises(Invalid):
                reg.verify_otp(RAVI, code, None, None, device_key=key, challenge=ch, device_proof="AAAA")

    def test_all_three_fields_or_none(self, reg, people):
        reg.clock.advance(seconds=OTP_RESEND_SECONDS + 1)
        code = reg.request_otp(RAVI, LogSmsSender())
        with pytest.raises(Invalid, match="together"):
            reg.verify_otp(RAVI, code, None, None, device_key=people["ravi_phone"].public)

    def test_no_key_still_works(self, reg, people):
        legacy = sign_in(reg, RAVI)
        assert legacy["device_proven"] is False


class TestSimSwap:
    def test_owner_keeps_working_thief_stays_restricted(self, reg, people):
        reg.clock.advance(minutes=5)
        reg.report_sim_change(people["bank"], RAVI)
        owner = sign_in(reg, RAVI, people["ravi_phone"])       # signs in again on his own phone
        thief = sign_in(reg, RAVI, Phone())                     # has the SIM, not the phone
        assert owner["restricted"] is False and owner["device_proven"] is True
        assert thief["restricted"] is True
        assert any("SIM change" in r for r in thief["restriction_reasons"])

    def test_thief_key_never_counts_for_that_swap(self, reg, people):
        reg.clock.advance(minutes=5)
        reg.report_sim_change(people["bank"], RAVI)
        thief_phone = Phone()
        sign_in(reg, RAVI, thief_phone)
        reg.clock.advance(hours=NEW_KEY_PROBATION_HOURS + 1)  # probation over, window (72 h) still open
        later = sign_in(reg, RAVI, thief_phone)
        assert later["device_proven"] is True  # trusted key now...
        assert later["restricted"] is True     # ...but trusted only AFTER the swap: still restricted

    def test_lost_phone_revokes_keys_and_sessions(self, reg, people):
        reg.report_lost_phone(people["ravi"]["user_id"], people["ravi"]["user_id"])
        assert {k["status"] for k in reg.device_keys(people["ravi"]["user_id"])} == {"revoked"}
        assert reg.session_info(people["ravi"]["token"]) is None
        with pytest.raises(Unauthorized, match="revoked"):
            sign_in(reg, RAVI, people["ravi_phone"])

    def test_revoke_one_key_signs_that_device_out(self, reg, people):
        uid = people["ravi"]["user_id"]
        reg.revoke_device_key(uid, people["ravi_phone"].key_id)
        assert reg.session_info(people["ravi"]["token"]) is None
        with pytest.raises(NotFound):
            reg.revoke_device_key(uid, people["ravi_phone"].key_id)


class GoodAttestor(KeyAttestor):
    def __init__(self, ok=True):
        self.ok = ok

    def verify(self, public_key_b64, attestation, platform, challenge=""):
        return {"hardware_backed": self.ok, "app_genuine": self.ok}


class TestAttestation:
    def test_attested_flag(self, reg, people):
        reg.key_attestor = GoodAttestor()
        p = Phone()
        reg.clock.advance(seconds=OTP_RESEND_SECONDS + 1)
        ch = reg.new_challenge()["challenge"]
        code = reg.request_otp(RAVI, LogSmsSender())
        reg.verify_otp(RAVI, code, None, None, device_key=p.public, challenge=ch, device_proof=p.sign(ch),
                       key_attestation="integrity-token", platform="android")
        k = [k for k in reg.device_keys(people["ravi"]["user_id"]) if k["key_id"] == p.key_id][0]
        assert k["platform_attested"] is True

    def test_required_attestation_refuses_bad_keys(self, reg, people, monkeypatch):
        monkeypatch.setenv("GR_REQUIRE_KEY_ATTESTATION", "1")
        reg.key_attestor = GoodAttestor(ok=False)
        with pytest.raises(Unauthorized, match="hardware-backed"):
            sign_in(reg, RAVI, Phone())
        # a key registered earlier keeps working
        assert sign_in(reg, RAVI, people["ravi_phone"])["device_proven"] is True


def test_http(clock):
    sms = LogSmsSender()
    c = TestClient(create_app(Registry(new_db(), clock), admin_token="a", sms=sms, run_worker=False))
    phone = Phone()

    def login(name=None, p=phone):
        clock.advance(seconds=OTP_RESEND_SECONDS + 1)
        c.post("/v1/auth/otp", json={"mobile": AMMA})
        code = re.search(r"code: (\d{6})", sms.sent[-1][1]).group(1)
        ch = c.post("/v1/auth/challenge").json()["challenge"]
        return c.post("/v1/auth/verify", json={"mobile": AMMA, "code": code, "display_name": name,
                                               "device_key": p.public, "challenge": ch,
                                               "device_proof": p.sign(ch), "platform": "android"}).json()

    first = login("Amma")
    again = login()
    assert again["device_proven"] is True
    H = {"Authorization": f"Bearer {again['token']}"}
    assert c.get("/v1/me/devices", headers=H).json()[0]["status"] == "trusted"
    other = login(p=Phone())
    O = {"Authorization": f"Bearer {other['token']}"}
    assert c.delete(f"/v1/me/devices/{phone.key_id}", headers=O).status_code == 403  # new phone can't remove old
    assert c.delete(f"/v1/me/devices/{phone.key_id}", headers=H).status_code == 200
    assert c.get("/v1/me", headers={"Authorization": f"Bearer {first['token']}"}).status_code == 401
