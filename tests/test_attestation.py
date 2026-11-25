"""Android Key Attestation and Apple App Attest, verified locally against test roots."""

import base64
import hashlib
import json
from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from guardian_registry import attestation as A
from guardian_registry.clock import FixedClock
from guardian_registry.errors import Unauthorized
from guardian_registry.notify import LogSmsSender
from guardian_registry.service import OTP_RESEND_SECONDS

from .conftest import RAVI

NOW = datetime(2026, 11, 23, 4, 30, tzinfo=timezone.utc)
PKG, DIGEST = "in.guardianregistry.app", hashlib.sha256(b"release signing cert").hexdigest()
APP_ID = "ABCDE12345.in.guardianregistry.app"


# ------------------------------------------------------------------ DER / CBOR encoders for tests
def _len(n):
    if n < 128:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def tlv(tag: bytes, content: bytes) -> bytes:
    return tag + _len(len(content)) + content


def ctx(n: int, content: bytes) -> bytes:  # [n] EXPLICIT, constructed, any tag number
    if n < 31:
        return tlv(bytes([0xA0 | n]), content)
    enc = [n & 0x7F]
    n >>= 7
    while n:
        enc.insert(0, 0x80 | (n & 0x7F))
        n >>= 7
    return tlv(bytes([0xBF, *enc]), content)


def seq(*items):
    return tlv(b"\x30", b"".join(items))


def set_(*items):
    return tlv(b"\x31", b"".join(items))


def integer(v):
    return tlv(b"\x02", v.to_bytes(max(1, (v.bit_length() + 8) // 8), "big"))


def enum(v):
    return tlv(b"\x0a", bytes([v]))


def octets(b):
    return tlv(b"\x04", b)


def boolean(v):
    return tlv(b"\x01", b"\xff" if v else b"\x00")


def cbor(v) -> bytes:
    def head(major, n):
        if n < 24:
            return bytes([major << 5 | n])
        for info, size in ((24, 1), (25, 2), (26, 4), (27, 8)):
            if n < 1 << (8 * size):
                return bytes([major << 5 | info]) + n.to_bytes(size, "big")
    if isinstance(v, bytes):
        return head(2, len(v)) + v
    if isinstance(v, str):
        return head(3, len(v.encode())) + v.encode()
    if isinstance(v, int):
        return head(0, v)
    if isinstance(v, list):
        return head(4, len(v)) + b"".join(cbor(x) for x in v)
    if isinstance(v, dict):
        return head(5, len(v)) + b"".join(cbor(k) + cbor(x) for k, x in v.items())
    raise TypeError(v)


# ------------------------------------------------------------------ certificates
def _name(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def make_cert(subject_key, issuer_key, cn, issuer_cn, ca=False, ext=None, serial=None,
              not_before=NOW - timedelta(days=1), not_after=NOW + timedelta(days=365)):
    b = (x509.CertificateBuilder().subject_name(_name(cn)).issuer_name(_name(issuer_cn))
         .public_key(subject_key).serial_number(serial or x509.random_serial_number())
         .not_valid_before(not_before).not_valid_after(not_after)
         .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True))
    for oid, value in (ext or []):
        b = b.add_extension(x509.UnrecognizedExtension(oid, value), critical=False)
    return b.sign(issuer_key, hashes.SHA256())


def der(cert):
    return cert.public_bytes(serialization.Encoding.DER)


def spki(key):
    return key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


class Pki:
    def __init__(self):
        self.root_key = ec.generate_private_key(ec.SECP256R1())
        self.root = make_cert(self.root_key.public_key(), self.root_key, "Test Root", "Test Root", ca=True)
        self.int_key = ec.generate_private_key(ec.SECP256R1())
        self.intermediate = make_cert(self.int_key.public_key(), self.root_key, "Test Intermediate", "Test Root",
                                      ca=True)


def key_description(challenge: bytes, level=A.SECURITY_TEE, locked=True, boot=A.BOOT_VERIFIED,
                    pkg=PKG, digest=DIGEST) -> bytes:
    app_id = seq(set_(seq(octets(pkg.encode()), integer(1))), set_(octets(bytes.fromhex(digest))))
    sw = seq(ctx(709, octets(app_id)))
    hw = seq(ctx(1, set_(integer(2))), ctx(704, seq(octets(b"\x11" * 32), boolean(locked), enum(boot),
                                                       octets(b"\x22" * 32))))
    return seq(integer(200), enum(level), integer(200), enum(level), octets(challenge), octets(b""), sw, hw)


class AndroidPhone:
    def __init__(self, pki):
        self.pki = pki
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.public = base64.b64encode(spki(self.key.public_key())).decode()

    def evidence(self, challenge: str, chain_key=None, **kd):
        leaf = make_cert((chain_key or self.key).public_key(), self.pki.int_key, "Android Keystore Key",
                         "Test Intermediate",
                         ext=[(A.ANDROID_KEY_DESCRIPTION_OID, key_description(challenge.encode(), **kd))])
        chain = [leaf, self.pki.intermediate, self.pki.root]
        return json.dumps({"format": "android-key", "chain": [base64.b64encode(der(c)).decode() for c in chain]})

    def sign(self, challenge):
        return base64.b64encode(self.key.sign(A.SIGNING_PREFIX + challenge.encode(),
                                              ec.ECDSA(hashes.SHA256()))).decode()


class IPhone:
    def __init__(self, pki, app_id=APP_ID, aaguid=A.AAGUID_PRODUCTION):
        self.pki, self.app_id, self.aaguid = pki, app_id, aaguid
        self.key = ec.generate_private_key(ec.SECP256R1())  # Secure Enclave device key
        self.public = base64.b64encode(spki(self.key.public_key())).decode()

    def evidence(self, challenge: str, bind_to: bytes | None = None, counter=0, wrong_key_id=False):
        attest_key = ec.generate_private_key(ec.SECP256R1())  # App Attest key
        point = attest_key.public_key().public_bytes(serialization.Encoding.X962,
                                                     serialization.PublicFormat.UncompressedPoint)
        key_id = hashlib.sha256(point).digest()
        auth = (hashlib.sha256(self.app_id.encode()).digest() + b"\x40" + counter.to_bytes(4, "big") + self.aaguid
                + len(key_id).to_bytes(2, "big") + key_id + b"\xa0")
        cdh = A.apple_client_data_hash(challenge, bind_to if bind_to is not None else spki(self.key.public_key()))
        nonce = hashlib.sha256(auth + cdh).digest()
        cred = make_cert(attest_key.public_key(), self.pki.int_key, key_id.hex(), "Test Intermediate",
                         ext=[(A.APPLE_NONCE_OID, seq(ctx(1, octets(nonce))))])
        obj = cbor({"fmt": "apple-appattest", "attStmt": {"x5c": [der(cred), der(self.pki.intermediate)],
                                                          "receipt": b"r"}, "authData": auth})
        kid = hashlib.sha256(b"other").digest() if wrong_key_id else key_id
        return json.dumps({"format": "apple-appattest", "key_id": base64.b64encode(kid).decode(),
                           "object": base64.b64encode(obj).decode()})


@pytest.fixture
def pki():
    return Pki()


@pytest.fixture
def android(pki):
    return A.LocalKeyAttestor(android=A.AndroidKeyAttestation([pki.root], {PKG}, {DIGEST}, clock=FixedClock(NOW)))


@pytest.fixture
def apple(pki):
    return A.LocalKeyAttestor(apple=A.AppleAppAttest([pki.root], {APP_ID}, clock=FixedClock(NOW)))


# ------------------------------------------------------------------ parsers
def test_der_high_tag_numbers_round_trip():
    cls, cons, tag, value, _ = A.der_read(ctx(709, octets(b"x")))
    assert (cls, cons, tag) == (2, True, 709) and A.der_read(value)[3] == b"x"


def test_cbor_decodes_what_apple_sends():
    assert A.cbor_decode(cbor({"a": [1, b"\x00" * 300, "t"]})) == {"a": [1, b"\x00" * 300, "t"]}
    with pytest.raises(A.AttestationError):
        A.cbor_decode(b"\x5f")  # indefinite length


# ------------------------------------------------------------------ Android
class TestAndroid:
    def test_good_evidence(self, android, pki):
        p = AndroidPhone(pki)
        v = android.verify(p.public, p.evidence("chl_1"), "android", "chl_1")
        assert v == {"hardware_backed": True, "app_genuine": True, "strongbox": False}

    def test_strongbox(self, android, pki):
        p = AndroidPhone(pki)
        assert android.verify(p.public, p.evidence("c", level=A.SECURITY_STRONGBOX), "android", "c")["strongbox"]

    @pytest.mark.parametrize("kd,flag", [
        ({"level": A.SECURITY_SOFTWARE}, "hardware_backed"),
        ({"locked": False}, "hardware_backed"),
        ({"boot": 2}, "hardware_backed"),               # unverified boot
        ({"pkg": "com.evil.clone"}, "app_genuine"),
        ({"digest": "00" * 32}, "app_genuine"),         # re-signed APK
    ])
    def test_weak_evidence_is_not_attested(self, android, pki, kd, flag):
        p = AndroidPhone(pki)
        assert android.verify(p.public, p.evidence("c", **kd), "android", "c")[flag] is False

    def test_replayed_challenge(self, android, pki):
        p = AndroidPhone(pki)
        with pytest.raises(A.AttestationError, match="challenge"):
            android.verify(p.public, p.evidence("old"), "android", "new")

    def test_attested_key_must_be_the_device_key(self, android, pki):
        p = AndroidPhone(pki)
        other = ec.generate_private_key(ec.SECP256R1())
        with pytest.raises(A.AttestationError, match="not this device key"):
            android.verify(p.public, p.evidence("c", chain_key=other), "android", "c")

    def test_chain_from_another_root(self, android):
        p = AndroidPhone(Pki())
        with pytest.raises(A.AttestationError, match="pinned root"):
            android.verify(p.public, p.evidence("c"), "android", "c")

    def test_broken_link(self, android, pki):
        p = AndroidPhone(pki)
        ev = json.loads(p.evidence("c"))
        ev["chain"][1] = base64.b64encode(der(Pki().intermediate)).decode()
        with pytest.raises(A.AttestationError):
            android.verify(p.public, json.dumps(ev), "android", "c")

    def test_expired_certificate(self, pki):
        att = A.LocalKeyAttestor(android=A.AndroidKeyAttestation([pki.root], {PKG}, {DIGEST},
                                                                 clock=FixedClock(NOW + timedelta(days=400))))
        p = AndroidPhone(pki)
        with pytest.raises(A.AttestationError, match="validity"):
            att.verify(p.public, p.evidence("c"), "android", "c")

    def test_revoked_intermediate(self, pki):
        class FakeClient:
            def get(self, url):
                import httpx
                return httpx.Response(200, request=httpx.Request("GET", url), json={"entries": {format(pki.intermediate.serial_number, "x"):
                                                             {"status": "REVOKED", "reason": "KEY_COMPROMISE"}}})
        status = A.RevocationList("https://example.test/status", client=FakeClient())
        att = A.LocalKeyAttestor(android=A.AndroidKeyAttestation([pki.root], {PKG}, {DIGEST}, status,
                                                                 clock=FixedClock(NOW)))
        p = AndroidPhone(pki)
        with pytest.raises(A.AttestationError, match="revoked"):
            att.verify(p.public, p.evidence("c"), "android", "c")


# ------------------------------------------------------------------ Apple
class TestApple:
    def test_good_evidence(self, apple, pki):
        p = IPhone(pki)
        assert apple.verify(p.public, p.evidence("chl_1"), "ios", "chl_1") == {"hardware_backed": True,
                                                                                "app_genuine": True}

    def test_bound_to_another_key(self, apple, pki):
        p = IPhone(pki)
        other = spki(ec.generate_private_key(ec.SECP256R1()).public_key())
        with pytest.raises(A.AttestationError, match="nonce"):
            apple.verify(p.public, p.evidence("c", bind_to=other), "ios", "c")

    def test_replayed_challenge(self, apple, pki):
        p = IPhone(pki)
        with pytest.raises(A.AttestationError, match="nonce"):
            apple.verify(p.public, p.evidence("old"), "ios", "new")

    def test_other_app(self, apple, pki):
        p = IPhone(pki, app_id="ZZZZZ99999.com.clone")
        with pytest.raises(A.AttestationError, match="different app"):
            apple.verify(p.public, p.evidence("c"), "ios", "c")

    def test_development_build_in_production(self, apple, pki):
        p = IPhone(pki, aaguid=A.AAGUID_DEVELOPMENT)
        with pytest.raises(A.AttestationError, match="environment"):
            apple.verify(p.public, p.evidence("c"), "ios", "c")

    def test_counter_and_key_id(self, apple, pki):
        p = IPhone(pki)
        with pytest.raises(A.AttestationError, match="counter"):
            apple.verify(p.public, p.evidence("c", counter=3), "ios", "c")
        with pytest.raises(A.AttestationError, match="key_id"):
            apple.verify(p.public, p.evidence("c", wrong_key_id=True), "ios", "c")

    def test_not_from_apple(self, apple):
        p = IPhone(Pki())
        with pytest.raises(A.AttestationError, match="pinned root"):
            apple.verify(p.public, p.evidence("c"), "ios", "c")


def test_unknown_format_and_garbage(android):
    with pytest.raises(A.AttestationError):
        android.verify("AAAA", "not json", "android", "c")
    with pytest.raises(A.AttestationError, match="not configured"):
        android.verify("AAAA", json.dumps({"format": "apple-appattest"}), "ios", "c")


# ------------------------------------------------------------------ through sign-in
def _sign_in(reg, phone, make_evidence, platform):
    reg.clock.advance(seconds=OTP_RESEND_SECONDS + 1)
    ch = reg.new_challenge()["challenge"]
    code = reg.request_otp(RAVI, LogSmsSender())
    return reg.verify_otp(RAVI, code, "Ravi", None, device_key=phone.public, challenge=ch,
                          device_proof=phone.sign(ch) if hasattr(phone, "sign") else _sign(phone, ch),
                          key_attestation=make_evidence(ch), platform=platform, adult=True)


def _sign(phone, ch):
    return base64.b64encode(phone.key.sign(A.SIGNING_PREFIX + ch.encode(), ec.ECDSA(hashes.SHA256()))).decode()


class TestSignIn:
    def test_android_key_is_marked_attested(self, reg, pki):
        reg.key_attestor = A.LocalKeyAttestor(android=A.AndroidKeyAttestation([pki.root], {PKG}, {DIGEST},
                                                                              clock=reg.clock))
        p = AndroidPhone(pki)
        out = _sign_in(reg, p, p.evidence, "android")
        assert reg.device_keys(out["user_id"])[0]["platform_attested"] is True

    def test_iphone_key_is_marked_attested(self, reg, pki):
        reg.key_attestor = A.LocalKeyAttestor(apple=A.AppleAppAttest([pki.root], {APP_ID}, clock=reg.clock))
        p = IPhone(pki)
        out = _sign_in(reg, p, p.evidence, "ios")
        assert reg.device_keys(out["user_id"])[0]["platform_attested"] is True

    def test_required_attestation_refuses_and_says_why(self, reg, pki, monkeypatch):
        monkeypatch.setenv("GR_REQUIRE_KEY_ATTESTATION", "1")
        reg.key_attestor = A.LocalKeyAttestor(android=A.AndroidKeyAttestation([pki.root], {PKG}, {DIGEST},
                                                                              clock=reg.clock))
        p = AndroidPhone(pki)
        with pytest.raises(Unauthorized, match="challenge does not match"):
            _sign_in(reg, p, lambda ch: p.evidence("someone-elses"), "android")


def test_config_from_env(tmp_path, monkeypatch, pki):
    roots = tmp_path / "roots.pem"
    roots.write_bytes(pki.root.public_bytes(serialization.Encoding.PEM))
    monkeypatch.setenv("GR_ANDROID_ATTESTATION_ROOTS", str(roots))
    monkeypatch.setenv("GR_ANDROID_PACKAGES", PKG)
    with pytest.raises(RuntimeError, match="GR_ANDROID_CERT_DIGESTS"):
        A.local_attestor_from_env()
    monkeypatch.setenv("GR_ANDROID_CERT_DIGESTS", DIGEST.upper())
    monkeypatch.setenv("GR_APPLE_ATTESTATION_ROOT", str(roots))
    monkeypatch.setenv("GR_APPLE_APP_IDS", APP_ID)
    att = A.local_attestor_from_env(FixedClock(NOW))
    assert att.android and att.apple
    p = AndroidPhone(pki)
    assert att.verify(p.public, p.evidence("c"), "android", "c")["app_genuine"]
