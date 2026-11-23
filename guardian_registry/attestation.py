"""Platform attestation for device keys, verified here, with no third-party service in the loop.

A device key (devicekeys.py) proves "the same phone as before". Attestation adds two more
facts about the FIRST time a key is seen:
  * hardware_backed - the private key lives in secure hardware and can't be copied out;
  * app_genuine     - the key was made by OUR app (right package / bundle, right signing
                      certificate), not by a script that imitates the API.

Android: Key Attestation. The app generates the device key in Android Keystore with
  setAttestationChallenge(challenge) and sends the certificate chain Keystore returns.
  The leaf certificate holds the device key itself plus Google's KeyDescription extension
  (OID 1.3.6.1.4.1.11129.2.1.17). We check:
    - the chain is signed link by link, is within its dates, and ends at a pinned Google
      hardware-attestation root (GR_ANDROID_ATTESTATION_ROOTS, a PEM file);
    - no certificate in the chain is on Google's revocation list (optional,
      GR_ANDROID_ATTESTATION_STATUS_URL, fetched at most daily);
    - the leaf's public key IS the device key, and its attestation challenge IS this
      sign-in's challenge (so an old chain can't be replayed);
    - both security levels are TEE or StrongBox, the bootloader is locked and verified boot
      says "Verified" -> hardware_backed;
    - the package name is in GR_ANDROID_PACKAGES and one of its signing-certificate SHA-256
      digests is in GR_ANDROID_CERT_DIGESTS -> app_genuine.

iOS: App Attest. The app keeps the device key in the Secure Enclave and asks
  DCAppAttestService to attest an App Attest key with
      clientDataHash = SHA256("guardian-registry/v1:" + challenge + device key DER)
  which binds Apple's statement to THIS device key and THIS challenge. We check (Apple's
  "Validating apps that connect to your server" steps):
    - the x5c chain ends at the pinned Apple App Attestation Root CA (GR_APPLE_ATTESTATION_ROOT);
    - the nonce in the credential certificate = SHA256(authData + clientDataHash);
    - SHA256(credential public key) = key_id = the credential id in authData;
    - authData's RP ID hash = SHA256("<team id>.<bundle id>") for an app in GR_APPLE_APP_IDS,
      the counter is 0, and the AAGUID matches GR_APPLE_APP_ATTEST_ENV (production default).
  Only Apple's attestation service can produce that chain, and only for a genuine app on a
  genuine device, so a pass sets app_genuine and hardware_backed (the app creates the
  device key in the Secure Enclave; App Attest keys themselves can only sign assertions).

The roots are configuration, not code: download them from Google's and Apple's
documentation and pin them. Nothing here trusts a certificate the operator didn't choose.

Attestation format sent by the app in `key_attestation` (JSON):
    {"format": "android-key", "chain": ["<base64 DER leaf>", ..., "<base64 DER root>"]}
    {"format": "apple-appattest", "key_id": "<base64>", "object": "<base64 CBOR>"}
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import threading
import time
from datetime import datetime, timezone

import httpx
from cryptography import x509
from cryptography.hazmat.primitives import serialization

log = logging.getLogger("guardian_registry.attestation")

SIGNING_PREFIX = b"guardian-registry/v1:"
ANDROID_KEY_DESCRIPTION_OID = x509.ObjectIdentifier("1.3.6.1.4.1.11129.2.1.17")
APPLE_NONCE_OID = x509.ObjectIdentifier("1.2.840.113635.100.8.2")
AAGUID_PRODUCTION = b"appattest" + b"\x00" * 7
AAGUID_DEVELOPMENT = b"appattestdevelop"
STATUS_CACHE_SECONDS = 24 * 3600

# Android security levels (KeyDescription.attestationSecurityLevel) and boot states
SECURITY_SOFTWARE, SECURITY_TEE, SECURITY_STRONGBOX = 0, 1, 2
BOOT_VERIFIED = 0


class AttestationError(Exception):
    """The evidence is malformed, forged, replayed or from the wrong app."""


# ------------------------------------------------------------------ DER (just enough of it)
def der_read(data: bytes, i: int = 0) -> tuple[int, bool, int, bytes, int]:
    """One TLV at data[i]: (class, constructed, tag number, value, next index)."""
    try:
        first = data[i]
        cls, constructed, tag = first >> 6, bool(first & 0x20), first & 0x1F
        i += 1
        if tag == 0x1F:  # high tag number: base-128, high bit = more
            tag = 0
            while True:
                b = data[i]
                i += 1
                tag = (tag << 7) | (b & 0x7F)
                if not b & 0x80:
                    break
        length = data[i]
        i += 1
        if length & 0x80:
            n = length & 0x7F
            if n == 0 or n > 4:
                raise AttestationError("unsupported DER length")
            length = int.from_bytes(data[i:i + n], "big")
            i += n
        if i + length > len(data):
            raise AttestationError("truncated DER")
        return cls, constructed, tag, data[i:i + length], i + length
    except IndexError:
        raise AttestationError("truncated DER") from None


def der_children(value: bytes) -> list[tuple[int, bool, int, bytes]]:
    out, i = [], 0
    while i < len(value):
        cls, cons, tag, v, i = der_read(value, i)
        out.append((cls, cons, tag, v))
    return out


def der_int(value: bytes) -> int:
    return int.from_bytes(value, "big", signed=True) if value else 0


# ------------------------------------------------------------------ CBOR (just enough of it)
def cbor_decode(data: bytes):
    value, i = _cbor(data, 0)
    if i != len(data):
        raise AttestationError("trailing bytes after CBOR")
    return value


def _cbor(d: bytes, i: int):
    try:
        ib = d[i]
        major, info = ib >> 5, ib & 0x1F
        i += 1
        if info < 24:
            arg = info
        elif info in (24, 25, 26, 27):
            n = 1 << (info - 24)
            arg = int.from_bytes(d[i:i + n], "big")
            i += n
        else:
            raise AttestationError("indefinite or reserved CBOR item")
        if major == 0:
            return arg, i
        if major == 1:
            return -1 - arg, i
        if major in (2, 3):
            if i + arg > len(d):
                raise AttestationError("truncated CBOR")
            raw = d[i:i + arg]
            return (raw if major == 2 else raw.decode()), i + arg
        if major == 4:
            items = []
            for _ in range(arg):
                v, i = _cbor(d, i)
                items.append(v)
            return items, i
        if major == 5:
            m = {}
            for _ in range(arg):
                k, i = _cbor(d, i)
                v, i = _cbor(d, i)
                m[k] = v
            return m, i
        if major == 7 and info in (20, 21, 22):
            return {20: False, 21: True, 22: None}[info], i
        raise AttestationError("unsupported CBOR item")
    except (IndexError, UnicodeDecodeError):
        raise AttestationError("malformed CBOR") from None


# ------------------------------------------------------------------ certificates
def load_pem_roots(path_or_pem: str) -> list[x509.Certificate]:
    pem = path_or_pem
    if "-----BEGIN" not in pem:
        with open(pem, "rb") as f:
            pem = f.read().decode()
    roots = x509.load_pem_x509_certificates(pem.encode())
    if not roots:
        raise RuntimeError("no certificates in the attestation root file")
    return roots


def _spki(cert_or_key) -> bytes:
    key = cert_or_key.public_key() if isinstance(cert_or_key, x509.Certificate) else cert_or_key
    return key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


def verify_chain(chain: list[x509.Certificate], roots: list[x509.Certificate], now: datetime) -> None:
    """chain[0] is the leaf. Every cert must be in date and signed by the next one; the last
    must be signed by (or be) a pinned root. Roots are matched by public key, as Google
    recommends, so a re-issued root with the same key still works."""
    if not chain:
        raise AttestationError("empty certificate chain")
    for cert in chain:
        if not (cert.not_valid_before_utc <= now <= cert.not_valid_after_utc):
            raise AttestationError(f"certificate {cert.serial_number:x} is outside its validity dates")
    for child, parent in zip(chain, chain[1:]):
        try:
            child.verify_directly_issued_by(parent)
        except Exception:  # noqa: BLE001 - any signature/issuer mismatch
            raise AttestationError("certificate chain does not verify") from None
    root_keys = {_spki(r) for r in roots}
    last = chain[-1]
    if _spki(last) in root_keys:
        return
    for r in roots:
        try:
            last.verify_directly_issued_by(r)
            return
        except Exception:  # noqa: BLE001
            continue
    raise AttestationError("certificate chain does not end at a pinned root")


def _b64d(value, what: str) -> bytes:
    try:
        return base64.b64decode(value, validate=True)
    except Exception:  # noqa: BLE001
        raise AttestationError(f"{what} must be base64") from None


def _csv(name: str) -> set[str]:
    return {x.strip() for x in os.environ.get(name, "").split(",") if x.strip()}


# ------------------------------------------------------------------ Android
class RevocationList:
    """Google's attestation status list ({"entries": {"<hex serial>": {"status": ...}}}),
    fetched at most once a day. If a refresh fails the last good copy is kept."""

    def __init__(self, url: str, client: httpx.Client | None = None):
        self.url, self.client = url, client or httpx.Client(timeout=10)
        self._entries: dict | None = None
        self._fetched = 0.0
        self._lock = threading.Lock()

    def revoked(self, serials: list[int]) -> str | None:
        with self._lock:
            if self._entries is None or time.monotonic() - self._fetched > STATUS_CACHE_SECONDS:
                try:
                    r = self.client.get(self.url)
                    r.raise_for_status()
                    self._entries = {k.lower(): v for k, v in (r.json().get("entries") or {}).items()}
                    self._fetched = time.monotonic()
                except Exception as e:  # noqa: BLE001
                    log.warning("attestation status list unavailable: %s", e)
                    if self._entries is None:
                        return None
        for s in serials:
            e = self._entries.get(format(s, "x"))
            if e and str(e.get("status", "")).upper() in ("REVOKED", "SUSPENDED"):
                return format(s, "x")
        return None


def parse_key_description(ext_value: bytes) -> dict:
    cls, cons, tag, seq, _ = der_read(ext_value)
    if tag != 16 or not cons:
        raise AttestationError("KeyDescription is not a SEQUENCE")
    f = der_children(seq)
    if len(f) < 8:
        raise AttestationError("KeyDescription is too short")
    out = {"attestation_version": der_int(f[0][3]), "attestation_security_level": der_int(f[1][3]),
           "keymaster_security_level": der_int(f[3][3]), "challenge": f[4][3]}
    sw, hw = _auth_list(f[6][3]), _auth_list(f[7][3])
    rot = hw.get(704)
    if rot is not None:
        r = der_children(der_read(rot)[3])  # [704] EXPLICIT -> RootOfTrust SEQUENCE
        out["device_locked"] = len(r) > 1 and r[1][3] not in (b"", b"\x00")
        out["verified_boot_state"] = der_int(r[2][3]) if len(r) > 2 else None
    app_id = sw.get(709) or hw.get(709)
    out["packages"], out["signature_digests"] = set(), set()
    if app_id is not None:
        _, _, _, inner, _ = der_read(app_id)          # OCTET STRING -> its content
        _, _, _, aaid, _ = der_read(inner)            # AttestationApplicationId SEQUENCE
        parts = der_children(aaid)
        if parts:
            for _, _, _, pkg in der_children(parts[0][3]):
                pf = der_children(pkg)
                if pf:
                    out["packages"].add(pf[0][3].decode(errors="replace"))
        if len(parts) > 1:
            out["signature_digests"] = {d[3].hex() for d in der_children(parts[1][3])}
    return out


def _auth_list(value: bytes) -> dict[int, bytes]:
    """AuthorizationList: [tag] EXPLICIT <value>. Returns tag -> the inner TLV bytes."""
    out = {}
    for cls, _cons, tag, v in der_children(value):
        if cls == 2:  # context-specific
            out[tag] = v
    return out


class AndroidKeyAttestation:
    def __init__(self, roots: list[x509.Certificate], packages: set[str], cert_digests: set[str],
                 status: RevocationList | None = None, clock=None):
        self.roots, self.packages = roots, packages
        self.cert_digests = {d.lower().replace(":", "") for d in cert_digests}
        self.status, self.clock = status, clock

    def verify(self, device_key_der: bytes, challenge: str, evidence: dict) -> dict:
        raw = evidence.get("chain")
        if not isinstance(raw, list) or not 2 <= len(raw) <= 10:
            raise AttestationError("chain must be a list of 2-10 base64 DER certificates")
        try:
            chain = [x509.load_der_x509_certificate(_b64d(c, "chain entry")) for c in raw]
        except ValueError:
            raise AttestationError("chain entry is not a DER certificate") from None
        now = self.clock.now() if self.clock else datetime.now(timezone.utc)
        verify_chain(chain, self.roots, now)
        if self.status:
            bad = self.status.revoked([c.serial_number for c in chain])
            if bad:
                raise AttestationError(f"attestation certificate {bad} is revoked")
        leaf = chain[0]
        if _spki(leaf) != device_key_der:
            raise AttestationError("the attested key is not this device key")
        try:
            ext = leaf.extensions.get_extension_for_oid(ANDROID_KEY_DESCRIPTION_OID).value.value
        except x509.ExtensionNotFound:
            raise AttestationError("leaf certificate has no key attestation extension") from None
        kd = parse_key_description(ext)
        if kd["challenge"] != challenge.encode():
            raise AttestationError("attestation challenge does not match this sign-in")
        hardware = (kd["attestation_security_level"] in (SECURITY_TEE, SECURITY_STRONGBOX)
                    and kd["keymaster_security_level"] in (SECURITY_TEE, SECURITY_STRONGBOX)
                    and kd.get("device_locked") is True and kd.get("verified_boot_state") == BOOT_VERIFIED)
        genuine = bool(kd["packages"] & self.packages) and bool(kd["signature_digests"] & self.cert_digests)
        return {"hardware_backed": hardware, "app_genuine": genuine,
                "strongbox": kd["attestation_security_level"] == SECURITY_STRONGBOX}


# ------------------------------------------------------------------ Apple
def apple_client_data_hash(challenge: str, device_key_der: bytes) -> bytes:
    return hashlib.sha256(SIGNING_PREFIX + challenge.encode() + device_key_der).digest()


class AppleAppAttest:
    def __init__(self, root: list[x509.Certificate], app_ids: set[str], environment: str = "production",
                 clock=None):
        if environment not in ("production", "development"):
            raise RuntimeError("GR_APPLE_APP_ATTEST_ENV must be production or development")
        self.roots, self.app_ids, self.clock = root, app_ids, clock
        self.aaguid = AAGUID_PRODUCTION if environment == "production" else AAGUID_DEVELOPMENT

    def verify(self, device_key_der: bytes, challenge: str, evidence: dict) -> dict:
        key_id = _b64d(evidence.get("key_id") or "", "key_id")
        obj = cbor_decode(_b64d(evidence.get("object") or "", "object"))
        if not isinstance(obj, dict) or obj.get("fmt") != "apple-appattest":
            raise AttestationError("not an apple-appattest attestation object")
        stmt, auth = obj.get("attStmt") or {}, obj.get("authData")
        x5c = stmt.get("x5c") if isinstance(stmt, dict) else None
        if not isinstance(x5c, list) or len(x5c) < 2 or not isinstance(auth, bytes) or len(auth) < 55:
            raise AttestationError("attestation object is incomplete")
        try:
            chain = [x509.load_der_x509_certificate(c) for c in x5c]
        except ValueError:
            raise AttestationError("x5c entry is not a DER certificate") from None
        now = self.clock.now() if self.clock else datetime.now(timezone.utc)
        verify_chain(chain, self.roots, now)
        cred = chain[0]
        nonce = hashlib.sha256(auth + apple_client_data_hash(challenge, device_key_der)).digest()
        try:
            ext = cred.extensions.get_extension_for_oid(APPLE_NONCE_OID).value.value
        except x509.ExtensionNotFound:
            raise AttestationError("credential certificate has no nonce extension") from None
        _, _, _, seq, _ = der_read(ext)
        found = None
        for cls, _c, tag, v in der_children(seq):
            if cls == 2 and tag == 1:
                _, _, _, found, _ = der_read(v)
        if found != nonce:
            raise AttestationError("attestation nonce does not match this device key and challenge")
        point = cred.public_key().public_bytes(serialization.Encoding.X962,
                                               serialization.PublicFormat.UncompressedPoint)
        if hashlib.sha256(point).digest() != key_id:
            raise AttestationError("key_id is not the attested key")
        rp_hash, counter = auth[0:32], int.from_bytes(auth[33:37], "big")
        aaguid, cred_len = auth[37:53], int.from_bytes(auth[53:55], "big")
        if rp_hash not in {hashlib.sha256(a.encode()).digest() for a in self.app_ids}:
            raise AttestationError("attestation is for a different app")
        if counter != 0:
            raise AttestationError("attestation counter must be 0")
        if aaguid != self.aaguid:
            raise AttestationError("attestation is from the wrong App Attest environment")
        if auth[55:55 + cred_len] != key_id:
            raise AttestationError("credential id is not the attested key")
        return {"hardware_backed": True, "app_genuine": True}


# ------------------------------------------------------------------ dispatcher
class LocalKeyAttestor:
    """KeyAttestor that verifies Android and Apple evidence in-process (see module doc)."""

    def __init__(self, android: AndroidKeyAttestation | None = None, apple: AppleAppAttest | None = None):
        self.android, self.apple = android, apple

    def verify(self, public_key_b64: str, attestation: str, platform: str | None, challenge: str = "") -> dict:
        try:
            evidence = json.loads(attestation)
        except ValueError:
            raise AttestationError("key_attestation must be JSON") from None
        if not isinstance(evidence, dict):
            raise AttestationError("key_attestation must be a JSON object")
        key_der = _b64d(public_key_b64, "device_key")
        fmt = evidence.get("format")
        if fmt == "android-key" and self.android:
            return self.android.verify(key_der, challenge, evidence)
        if fmt == "apple-appattest" and self.apple:
            return self.apple.verify(key_der, challenge, evidence)
        raise AttestationError(f"attestation format {fmt!r} is not configured")


def local_attestor_from_env(clock=None) -> LocalKeyAttestor | None:
    android = apple = None
    if os.environ.get("GR_ANDROID_ATTESTATION_ROOTS"):
        packages, digests = _csv("GR_ANDROID_PACKAGES"), _csv("GR_ANDROID_CERT_DIGESTS")
        if not packages or not digests:
            raise RuntimeError("Android attestation needs GR_ANDROID_PACKAGES and GR_ANDROID_CERT_DIGESTS")
        url = os.environ.get("GR_ANDROID_ATTESTATION_STATUS_URL")
        android = AndroidKeyAttestation(load_pem_roots(os.environ["GR_ANDROID_ATTESTATION_ROOTS"]), packages,
                                        digests, RevocationList(url) if url else None, clock)
    if os.environ.get("GR_APPLE_ATTESTATION_ROOT"):
        app_ids = _csv("GR_APPLE_APP_IDS")
        if not app_ids:
            raise RuntimeError("App Attest needs GR_APPLE_APP_IDS (\"<team id>.<bundle id>\")")
        apple = AppleAppAttest(load_pem_roots(os.environ["GR_APPLE_ATTESTATION_ROOT"]), app_ids,
                               os.environ.get("GR_APPLE_APP_ATTEST_ENV", "production"), clock)
    return LocalKeyAttestor(android, apple) if (android or apple) else None
