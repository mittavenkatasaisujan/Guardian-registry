"""Identifier hashing and secret tokens.

The registry never stores raw mobile numbers or raw API keys/tokens. A mobile
number is turned into a keyed hash (HMAC with a server-side pepper), so banks
can look a customer up by number without the registry holding a phone book.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import re
import secrets

_DEV_PEPPER = "dev-only-pepper-change-me"


def pepper() -> bytes:
    return os.environ.get("GR_PEPPER", _DEV_PEPPER).encode()


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


def new_secret(prefix: str) -> str:
    return f"{prefix}_{secrets.token_urlsafe(24)}"


def secret_hash(secret: str) -> str:
    return hashlib.sha256(secret.encode()).hexdigest()


def new_id(prefix: str) -> str:
    return f"{prefix}_{secrets.token_hex(8)}"
