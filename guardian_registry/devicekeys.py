"""Device-bound keys: prove "this is the same phone", not just "this phone says so".

A device ID is chosen by the app, so a thief can claim the victim's. Instead, the app
creates a P-256 key pair inside the phone's secure hardware (Android Keystore / StrongBox,
iOS Secure Enclave). The private key never leaves the chip. At sign-in:

  1. the app asks for a one-time challenge (POST /v1/auth/challenge, valid CHALLENGE_TTL);
  2. it signs  b"guardian-registry/v1:" + challenge  with ECDSA-SHA256;
  3. it sends the public key, the challenge and the signature with the OTP code.

What the registry does with it:
  * The person's FIRST key is trusted at once. A new key on an account that already has
    one waits NEW_KEY_PROBATION_HOURS, like any new device.
  * A sign-in signed by an already-TRUSTED key is a PROVEN device. It skips new-device
    probation and, crucially, is NOT restricted by a SIM-swap window: whoever holds that
    phone had it before the swap. So the genuine owner keeps working while the thief who
    only has the SIM stays restricted.
  * A lost-phone report, or a completed account recovery, revokes every key: the phone in
    the wrong hands must not stay "proven". A key can also be removed by its owner.
  * Optional platform attestation (KeyAttestor): Play Integrity / App Attest evidence that
    the key is hardware-backed and the app is genuine. With GR_REQUIRE_KEY_ATTESTATION=1 a
    key without good evidence is refused.

Sign-ins without a key work as before (device ID only), so older apps keep working.
"""

from __future__ import annotations

import base64
import hashlib
import os
from datetime import timedelta

import httpx
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import load_der_public_key

from .clock import iso
from .errors import Invalid, NotFound, Unauthorized
from .security import new_secret, secret_hash

CHALLENGE_TTL = timedelta(minutes=5)
NEW_KEY_PROBATION_HOURS = 24
SIGNING_PREFIX = b"guardian-registry/v1:"
MAX_KEYS = 5


class KeyAttestor:
    """Checks platform evidence for a device key."""

    def verify(self, public_key_b64: str, attestation: str, platform: str | None) -> dict:  # pragma: no cover
        """Return {"hardware_backed": bool, "app_genuine": bool}."""
        raise NotImplementedError


class HttpKeyAttestor(KeyAttestor):
    """POST {"public_key", "attestation", "platform"} to GR_KEY_ATTESTATION_URL: an adapter
    that calls Google's Play Integrity decode API or verifies an Apple App Attest object."""

    def __init__(self, url: str, token: str | None = None, client: httpx.Client | None = None):
        self.url, self.token = url, token
        self.client = client or httpx.Client(timeout=5)

    def verify(self, public_key_b64: str, attestation: str, platform: str | None) -> dict:
        r = self.client.post(self.url, json={"public_key": public_key_b64, "attestation": attestation,
                                             "platform": platform},
                             headers={"Authorization": f"Bearer {self.token}"} if self.token else {})
        r.raise_for_status()
        body = r.json()
        return {"hardware_backed": bool(body.get("hardware_backed")), "app_genuine": bool(body.get("app_genuine"))}


def key_attestor_from_env() -> KeyAttestor | None:
    url = os.environ.get("GR_KEY_ATTESTATION_URL")
    return HttpKeyAttestor(url, os.environ.get("GR_KEY_ATTESTATION_TOKEN")) if url else None


def attestation_required() -> bool:
    return os.environ.get("GR_REQUIRE_KEY_ATTESTATION", "0") == "1"


def _b64(value: str, what: str) -> bytes:
    try:
        return base64.b64decode(value, validate=True)
    except Exception:  # noqa: BLE001
        raise Invalid(f"{what} must be base64") from None


def key_id_for(public_key_b64: str) -> str:
    return hashlib.sha256(_b64(public_key_b64, "device_key")).hexdigest()


class DeviceKeyMixin:
    """Mixed into Registry. Needs self.key_attestor (KeyAttestor or None)."""

    key_attestor: KeyAttestor | None = None

    # ------------------------------------------------------------- challenges
    def new_challenge(self) -> dict:
        nonce = new_secret("chl")
        exp = self.clock.now() + CHALLENGE_TTL
        with self.db.tx() as c:
            c.execute("INSERT INTO auth_challenges (nonce_hash, expires_at) VALUES (?,?)", (secret_hash(nonce), iso(exp)))
            c.execute("DELETE FROM auth_challenges WHERE expires_at < ?", (iso(self.clock.now() - CHALLENGE_TTL),))
        return {"challenge": nonce, "expires_at": iso(exp),
                "sign": "ECDSA P-256 SHA-256 over 'guardian-registry/v1:' + challenge"}

    def _verify_proof(self, public_key_b64: str, challenge: str, signature_b64: str) -> str:
        """Check the signature and burn the challenge. Returns the key id."""
        with self.db.tx() as c:
            used = c.execute("UPDATE auth_challenges SET used_at=? WHERE nonce_hash=? AND used_at IS NULL "
                             "AND expires_at>?", (self._now(), secret_hash(challenge or ""), self._now())).rowcount
        if not used:
            raise Unauthorized("device challenge is unknown, used or expired; ask for a new one")
        try:
            key = load_der_public_key(_b64(public_key_b64, "device_key"))
        except ValueError:
            raise Invalid("device_key must be a DER SubjectPublicKeyInfo") from None
        if not isinstance(key, ec.EllipticCurvePublicKey) or key.curve.name != "secp256r1":
            raise Invalid("device_key must be an EC P-256 key")
        try:
            key.verify(_b64(signature_b64, "device_proof"), SIGNING_PREFIX + challenge.encode(),
                       ec.ECDSA(hashes.SHA256()))
        except InvalidSignature:
            raise Unauthorized("device signature does not verify") from None
        return key_id_for(public_key_b64)

    # ------------------------------------------------------------- keys
    def _key_row(self, uid: str, key_id: str):
        return self.db.one("SELECT * FROM device_keys WHERE user_id=? AND key_id=?", (uid, key_id))

    def _register_key(self, c, uid: str, key_id: str, public_key_b64: str, attestation: str | None,
                      platform: str | None, new_account: bool = False) -> tuple[bool, str | None]:
        """Returns (proven, key_probation_until). A trusted, unrevoked key proves the device."""
        now = self.clock.now()
        row = c.execute("SELECT * FROM device_keys WHERE user_id=? AND key_id=?", (uid, key_id)).fetchone()
        if row and not row["revoked_at"]:
            c.execute("UPDATE device_keys SET last_used_at=? WHERE user_id=? AND key_id=?", (iso(now), uid, key_id))
            if row["trusted_at"] <= iso(now):
                return True, None
            return False, row["trusted_at"]
        if row and row["revoked_at"]:
            raise Unauthorized("this device key was revoked; reinstall the app to create a new one")
        attested = False
        if self.key_attestor and attestation:
            try:
                verdict = self.key_attestor.verify(public_key_b64, attestation, platform)
                attested = verdict["hardware_backed"] and verdict["app_genuine"]
            except Exception:  # noqa: BLE001 - an unreachable attestor means "not attested"
                attested = False
        if attestation_required() and not attested:
            raise Unauthorized("this device key could not be verified as hardware-backed in a genuine app")
        live = c.execute("SELECT COUNT(*) n FROM device_keys WHERE user_id=? AND revoked_at IS NULL",
                         (uid,)).fetchone()["n"]
        ever = c.execute("SELECT COUNT(*) n FROM device_keys WHERE user_id=?", (uid,)).fetchone()["n"]
        if live >= MAX_KEYS:
            raise Invalid(f"at most {MAX_KEYS} devices; remove one first")
        first = ever == 0 and (new_account or not c.execute("SELECT 1 FROM sessions WHERE user_id=?",
                                                             (uid,)).fetchone())
        trusted_at = now if first else now + timedelta(hours=NEW_KEY_PROBATION_HOURS)
        c.execute("INSERT INTO device_keys (user_id, key_id, public_key, platform_attested, created_at, trusted_at, "
                  "last_used_at) VALUES (?,?,?,?,?,?,?)",
                  (uid, key_id, public_key_b64, 1 if attested else 0, iso(now), iso(trusted_at), iso(now)))
        self._audit(c, uid, "device_key.registered", uid, key_id=key_id[:16], attested=attested, first=first)
        return False, None if first else iso(trusted_at)

    def device_keys(self, uid: str) -> list[dict]:
        now = self._now()
        return [{"key_id": r["key_id"], "created_at": r["created_at"], "last_used_at": r["last_used_at"],
                 "platform_attested": bool(r["platform_attested"]),
                 "status": "revoked" if r["revoked_at"] else ("trusted" if r["trusted_at"] <= now else "probation"),
                 "trusted_at": r["trusted_at"]}
                for r in self.db.all("SELECT * FROM device_keys WHERE user_id=? ORDER BY created_at", (uid,))]

    def revoke_device_key(self, uid: str, key_id: str) -> list[dict]:
        with self.db.tx() as c:
            if not c.execute("UPDATE device_keys SET revoked_at=? WHERE user_id=? AND key_id=? AND revoked_at IS NULL",
                             (self._now(), uid, key_id)).rowcount:
                raise NotFound("device key not found")
            c.execute("UPDATE sessions SET revoked_at=? WHERE user_id=? AND device_key_id=? AND revoked_at IS NULL",
                      (self._now(), uid, key_id))
            self._audit(c, uid, "device_key.revoked", uid, key_id=key_id[:16])
        return self.device_keys(uid)

    def _revoke_all_keys(self, c, uid: str) -> int:
        return c.execute("UPDATE device_keys SET revoked_at=? WHERE user_id=? AND revoked_at IS NULL",
                         (self._now(), uid)).rowcount

    def _session_key_trusted(self, uid: str, key_id: str | None) -> bool:
        if not key_id:
            return False
        r = self._key_row(uid, key_id)
        return bool(r and not r["revoked_at"] and r["trusted_at"] <= self._now())
