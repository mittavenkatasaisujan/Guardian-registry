"""Identifier hashing, encryption and secret tokens.

Mobile numbers are kept two ways:
  * a keyed hash (HMAC with GR_PEPPER) used for every lookup, and
  * an encrypted copy (Fernet with GR_DATA_KEY) used ONLY to send SMS alerts and OTPs.
Raw numbers never sit in the database. API keys, session tokens and OTP codes are
stored only as hashes.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import re
import secrets

from cryptography.fernet import Fernet

_DEV_PEPPER = "dev-only-pepper-change-me"
_DEV_DATA_KEY = base64.urlsafe_b64encode(hashlib.sha256(b"dev-only-data-key").digest()).decode()


def is_production() -> bool:
    return os.environ.get("GR_ENV", "development").lower() == "production"


def check_production_config() -> None:
    """Refuse to start in production with development secrets or dev-only shortcuts."""
    if not is_production():
        return
    problems = []
    if os.environ.get("GR_PEPPER", _DEV_PEPPER) == _DEV_PEPPER:
        problems.append("GR_PEPPER must be set")
    if os.environ.get("GR_DATA_KEY", _DEV_DATA_KEY) == _DEV_DATA_KEY:
        problems.append("GR_DATA_KEY must be set")
    if os.environ.get("GR_OTP_DEV_ECHO") == "1":
        problems.append("GR_OTP_DEV_ECHO must not be enabled")
    if not os.environ.get("GR_SMS_URL"):
        problems.append("GR_SMS_URL must be set (otherwise alerts and sign-in codes are only logged)")
    if problems:
        raise RuntimeError("unsafe production config: " + "; ".join(problems))


def pepper() -> bytes:
    return os.environ.get("GR_PEPPER", _DEV_PEPPER).encode()


def _fernet() -> Fernet:
    return Fernet(os.environ.get("GR_DATA_KEY", _DEV_DATA_KEY).encode())


def normalize_mobile(mobile: str) -> str:
    """Accept '+91 98765-43210', '09876543210', '9876543210' -> '+919876543210'."""
    digits = re.sub(r"\D", "", mobile)
    if len(digits) == 12 and digits.startswith("91"):
        digits = digits[2:]
    elif len(digits) == 11 and digits.startswith("0"):
        digits = digits[1:]
    if len(digits) != 10 or digits[0] not in "6789":
        raise ValueError("not a valid Indian mobile number")
    return "+91" + digits


def mobile_hash(mobile: str) -> str:
    return hmac.new(pepper(), normalize_mobile(mobile).encode(), hashlib.sha256).hexdigest()


def encrypt_mobile(mobile: str) -> str:
    return _fernet().encrypt(normalize_mobile(mobile).encode()).decode()


def decrypt_mobile(token: str) -> str:
    return _fernet().decrypt(token.encode()).decode()


def mask_mobile(mobile: str) -> str:
    m = normalize_mobile(mobile)
    return m[:3] + "******" + m[-4:]


def new_secret(prefix: str) -> str:
    return f"{prefix}_{secrets.token_urlsafe(24)}"


def secret_hash(secret: str) -> str:
    return hashlib.sha256(secret.encode()).hexdigest()


def new_id(prefix: str) -> str:
    return f"{prefix}_{secrets.token_hex(8)}"


def new_otp() -> str:
    return f"{secrets.randbelow(1_000_000):06d}"


def otp_hash(mobile_h: str, code: str) -> str:
    """Bind the code to the number so a leaked hash can't be replayed for another user."""
    return hmac.new(pepper(), f"{mobile_h}:{code}".encode(), hashlib.sha256).hexdigest()


def sign_webhook(secret: str, body: bytes) -> str:
    return "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
