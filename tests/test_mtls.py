"""Mutual TLS for participants: pinned client certificates forwarded by a trusted proxy."""

from datetime import datetime, timedelta, timezone
from urllib.parse import quote

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from fastapi.testclient import TestClient

from guardian_registry.api import create_app
from guardian_registry.certs import ProxyTrust, parse_certificate
from guardian_registry.errors import Conflict, Forbidden, Invalid, Unauthorized
from guardian_registry.notify import LogSmsSender
from guardian_registry.service import Registry

from .conftest import AMMA, new_db


def make_cert(cn="bank-a.example", days=365, start_days_ago=1):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = datetime(2026, 11, 23, tzinfo=timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=start_days_ago)).not_valid_after(now + timedelta(days=days))
            .sign(key, hashes.SHA256()))
    return cert.public_bytes(serialization.Encoding.PEM).decode()


CERT_A, CERT_B, CERT_OTHER = make_cert(), make_cert("bank-a-next.example"), make_cert("mallory.example")


class TestParsing:
    def test_fingerprint_and_escaped_form(self):
        a = parse_certificate(CERT_A)
        assert len(a["fingerprint"]) == 64 and a["subject"] == "CN=bank-a.example"
        assert parse_certificate(quote(CERT_A))["fingerprint"] == a["fingerprint"]  # nginx escaped cert

    def test_proxy_trust(self):
        t = ProxyTrust("10.0.0.0/8,proxy.internal")
        assert t.trusted("10.1.2.3") and t.trusted("proxy.internal")
        assert not t.trusted("203.0.113.9") and not t.trusted(None)
        assert t.certificate("203.0.113.9", {"x-client-cert": CERT_A}) is None  # spoofed header ignored


class TestPins:
    def test_four_eyes_pin_then_required(self, reg, family):
        bank = family["bank"]
        assert reg.check_client_cert(bank, None) is None  # no pin yet: mTLS not required in dev
        fp = reg.request_cert_pin("alice", bank, CERT_A)["fingerprint"]
        with pytest.raises(Forbidden, match="four-eyes"):
            reg.approve_cert_pin("alice", bank, fp)
        assert reg.check_client_cert(bank, None) is None  # pending pins don't apply yet
        reg.approve_cert_pin("bob", bank, fp)
        with pytest.raises(Unauthorized, match="required"):
            reg.check_client_cert(bank, None)
        with pytest.raises(Unauthorized, match="not pinned"):
            reg.check_client_cert(bank, CERT_OTHER)
        assert reg.check_client_cert(bank, CERT_A) == fp
        assert reg.participant_view(bank)["mtls"]["pinned_certificates"] == 1

    def test_required_everywhere(self, reg, family, monkeypatch):
        monkeypatch.setenv("GR_REQUIRE_MTLS", "1")
        with pytest.raises(Unauthorized):
            reg.check_client_cert(family["bank"], CERT_A)  # nothing pinned: can't call at all

    def test_expired_or_not_yet_valid(self, reg, family, clock):
        bank = family["bank"]
        fp = reg.request_cert_pin("alice", bank, CERT_A)["fingerprint"]
        reg.approve_cert_pin("bob", bank, fp)
        clock.advance(days=400)
        with pytest.raises(Unauthorized, match="not valid now"):
            reg.check_client_cert(bank, CERT_A)
        with pytest.raises(Invalid, match="expired"):
            reg.request_cert_pin("alice", bank, make_cert(days=10))

    def test_rotation_needs_a_pinned_cert(self, reg, family):
        bank = family["bank"]
        fp_a = reg.request_cert_pin("alice", bank, CERT_A)["fingerprint"]
        reg.approve_cert_pin("bob", bank, fp_a)
        with pytest.raises(Forbidden, match="mutual TLS"):
            reg.rotate_cert(bank, None, CERT_B)
        fp_b = reg.rotate_cert(bank, fp_a, CERT_B)["fingerprint"]
        assert reg.check_client_cert(bank, CERT_B) == fp_b and reg.check_client_cert(bank, CERT_A) == fp_a
        reg.remove_cert_pin(bank, bank, fp_a, presented=fp_b)
        with pytest.raises(Unauthorized):
            reg.check_client_cert(bank, CERT_A)

    def test_cannot_remove_the_only_cert_in_use(self, reg, family):
        bank = family["bank"]
        fp = reg.request_cert_pin("alice", bank, CERT_A)["fingerprint"]
        reg.approve_cert_pin("bob", bank, fp)
        with pytest.raises(Conflict, match="only one"):
            reg.remove_cert_pin(bank, bank, fp, presented=fp)
        reg.remove_cert_pin("operator:alice", bank, fp)  # an operator can (e.g. key compromise)
        assert reg.check_client_cert(bank, None) is None

    def test_one_cert_one_participant(self, reg, family):
        other, _ = reg.register_participant("Other", "bank", "RBI-2")
        fp = reg.request_cert_pin("alice", family["bank"], CERT_A)["fingerprint"]
        reg.approve_cert_pin("bob", family["bank"], fp)
        with pytest.raises(Conflict, match="another participant"):
            reg.request_cert_pin("alice", other, CERT_A)

    def test_audit_and_garbage(self, reg, family):
        with pytest.raises(Invalid):
            reg.request_cert_pin("alice", family["bank"], "hello")
        fp = reg.request_cert_pin("alice", family["bank"], CERT_A)["fingerprint"]
        reg.approve_cert_pin("bob", family["bank"], fp)
        actions = [r["action"] for r in reg.db.all("SELECT action FROM audit_log")]
        assert "cert.pin_requested" in actions and "cert.pinned" in actions
        assert reg.verify_audit().ok


OPS = {"alice": "alice-token-0000001", "bob": "bob-token-00000002"}


@pytest.fixture
def http(clock):
    c = TestClient(create_app(Registry(new_db(), clock), operators=OPS, sms=LogSmsSender(), run_worker=False,
                              proxy_trust=ProxyTrust("testclient")))
    A, B = {"X-Admin-Token": OPS["alice"]}, {"X-Admin-Token": OPS["bob"]}
    p = c.post("/v1/admin/participants", headers=A, json={"name": "Bank A", "regulator_ref": "RBI-1"}).json()
    c.post(f"/v1/admin/participants/{p['participant_id']}/approve", headers=B)
    return c, A, B, p["participant_id"], {"X-Api-Key": p["api_key"]}


def check(c, headers):
    return c.post("/v1/checks", headers=headers, json={"mobile": AMMA, "participant_txn_id": "t1",
                                                        "amount": 100, "payee": "x@upi"})


def test_http_flow(http):
    c, A, B, pid, key = http
    assert check(c, key).status_code == 200  # no pin yet
    fp = c.post(f"/v1/admin/participants/{pid}/certificates", headers=A, json={"certificate": CERT_A}).json()
    assert fp["status"] == "pending"
    c.post(f"/v1/admin/participants/{pid}/certificates/{fp['fingerprint']}/approve", headers=B)
    r = check(c, key)
    assert r.status_code == 401 and "client certificate required" in r.json()["detail"]
    with_cert = {**key, "X-Client-Cert": quote(CERT_A)}
    assert check(c, with_cert).status_code == 200
    assert check(c, {**key, "X-Client-Cert": quote(CERT_OTHER)}).status_code == 401
    # the bank rotates over mTLS, then drops the old certificate
    new = c.post("/v1/participant/certificates", headers=with_cert, json={"certificate": CERT_B}).json()
    next_cert = {**key, "X-Client-Cert": quote(CERT_B)}
    assert c.delete(f"/v1/participant/certificates/{fp['fingerprint']}", headers=next_cert).status_code == 200
    assert check(c, with_cert).status_code == 401
    listed = {x["fingerprint"]: x["status"] for x in c.get("/v1/participant/certificates", headers=next_cert).json()}
    assert listed == {fp["fingerprint"]: "removed", new["fingerprint"]: "active"}
    assert new["status"] == "active"


def test_header_from_untrusted_hop_is_ignored(clock):
    c = TestClient(create_app(Registry(new_db(), clock), admin_token="a", sms=LogSmsSender(), run_worker=False,
                              proxy_trust=ProxyTrust("10.0.0.1")))
    p = c.post("/v1/admin/participants", headers={"X-Admin-Token": "a"},
               json={"name": "B", "regulator_ref": "RBI-1"}).json()
    key = {"X-Api-Key": p["api_key"]}
    c.post(f"/v1/admin/participants/{p['participant_id']}/certificates", headers={"X-Admin-Token": "a"},
           json={"certificate": CERT_A})  # single dev operator: active at once
    # the caller is not the trusted proxy, so its own X-Client-Cert header counts for nothing
    assert check(c, {**key, "X-Client-Cert": quote(CERT_A)}).status_code == 401


class TestClientIp:
    def test_forwarded_for_only_from_trusted_proxies(self):
        from guardian_registry.certs import ProxyTrust
        t = ProxyTrust("10.0.0.5,172.28.0.0/24")
        h = {"x-forwarded-for": "6.6.6.6, 49.36.1.2, 172.28.0.3"}
        assert t.client_ip("10.0.0.5", h) == "49.36.1.2"      # rightmost hop that isn't ours
        assert t.client_ip("49.36.9.9", h) == "49.36.9.9"     # direct client: header ignored
        assert t.client_ip("10.0.0.5", {}) == "10.0.0.5"
        assert t.client_ip(None, h) == "unknown"
