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

from cryptography.fernet import Fernet, MultiFernet

_DEV_PEPPER = "dev-only-pepper-change-me"
_DEV_DATA_KEY = base64.urlsafe_b64encode(hashlib.sha256(b"dev-only-data-key").digest()).decode()


# SHA-256 of android/app/debug.keystore's certificate. That keystore is in the repository on purpose
# (test builds install over each other), so anyone can sign an app with it: it must never count as
# the genuine app.
PUBLIC_DEBUG_CERT_SHA256 = "19b1bf559a10812387cb29f90ad468d6697db7b82123806d574efe1404367f32"


def is_production() -> bool:
    return os.environ.get("GR_ENV", "development").lower() == "production"


def check_production_config() -> None:
    """Refuse to start in production with development secrets or dev-only shortcuts."""
    if not is_production():
        return
    problems = []
    if os.environ.get("GR_PEPPER", _DEV_PEPPER) == _DEV_PEPPER:
        problems.append("GR_PEPPER must be set")
    if _DEV_DATA_KEY in data_keys():
        problems.append("GR_DATA_KEY must be set (and must not include the development key)")
    if os.environ.get("GR_OTP_DEV_ECHO") == "1":
        problems.append("GR_OTP_DEV_ECHO must not be enabled")
    if not (os.environ.get("GR_SMS_URL") or os.environ.get("GR_SMS_PROVIDER")):
        problems.append("GR_SMS_PROVIDER or GR_SMS_URL must be set (otherwise alerts and sign-in codes are "
                        "only logged)")
    if os.environ.get("GR_SMS_PROVIDER", "").strip().lower() == "twilio_verify":
        problems.append("GR_SMS_PROVIDER=twilio_verify sends sign-in codes only, not alerts (a SIM-swap warning "
                        "would never be texted): use twilio or msg91 in production")
    digests = {d.strip().lower().replace(":", "") for d in os.environ.get("GR_ANDROID_CERT_DIGESTS", "").split(",")}
    if PUBLIC_DEBUG_CERT_SHA256 in digests:
        problems.append("GR_ANDROID_CERT_DIGESTS includes the public debug certificate: anyone can sign an app "
                        "with it, so it must not count as genuine")
    if problems:
        raise RuntimeError("unsafe production config: " + "; ".join(problems))


def webhook_url_problem(url: str) -> str | None:
    """Why this webhook URL can't be used, or None. Outside production, http://localhost is allowed
    for testing. In production the host must resolve only to public addresses, so a participant
    can't make the registry send requests into its own network (cloud metadata at 169.254.169.254,
    internal services, the registry itself)."""
    return pin_webhook(url)[0]


def pin_webhook(url: str) -> tuple[str | None, str, dict, dict]:
    """(problem, url to connect to, extra headers, httpx request extensions).

    In production the host is resolved once, every address is checked, and the request then goes
    to the checked address, with the original name kept for the Host header and for TLS (SNI and
    certificate check). So a name can't resolve to a public address for the check and to an
    internal one for the connection a moment later (DNS rebinding). Outside production, or for an
    IP address in the URL, the URL is used as it is."""
    from urllib.parse import urlsplit, urlunsplit
    local = url.startswith(("http://localhost", "http://127.0.0.1"))
    if not (url.startswith("https://") or (local and not is_production())):
        return "webhook url must be https:// (http://localhost allowed outside production)", url, {}, {}
    if not is_production():
        return None, url, {}, {}
    parts = urlsplit(url)
    host = parts.hostname
    if not host:
        return "webhook url must be https:// (http://localhost allowed outside production)", url, {}, {}
    ips = resolve_host(host)
    if any(not ip.is_global for ip in ips):
        return "webhook url must point to a public address, not a private or internal one", url, {}, {}
    ip = ips[0]
    if str(ip) == host.strip("[]"):
        return None, url, {}, {}          # already an address: nothing to re-resolve
    port = f":{parts.port}" if parts.port else ""
    netloc = (f"[{ip}]" if ip.version == 6 else str(ip)) + port
    return None, urlunsplit(parts._replace(netloc=netloc)), {"Host": host + port}, {"sni_hostname": host}


def resolve_host(host: str) -> list:
    """Every address a hostname resolves to (an IP literal resolves to itself). Fails closed:
    a name that doesn't resolve gives a non-global placeholder."""
    import ipaddress
    import socket
    try:
        return [ipaddress.ip_address(host)]
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(host, 443, proto=socket.IPPROTO_TCP)
    except OSError:
        return [ipaddress.IPv4Address(0)]   # the unspecified address: not global, so refused
    return [ipaddress.ip_address(i[4][0].split("%")[0]) for i in infos] or [ipaddress.IPv4Address(0)]


def log_safe(value: object) -> str:
    """For log lines: no line breaks or other control characters from user-supplied text, so
    nobody can forge an extra log entry with a crafted name, number or message."""
    text = str(value).replace("\r\n", " ").replace("\n", " ").replace("\r", " ")
    return "".join(ch if ch.isprintable() else "?" for ch in text)


def pepper() -> bytes:
    return os.environ.get("GR_PEPPER", _DEV_PEPPER).encode()


def data_keys() -> list[str]:
    """GR_DATA_KEY: one Fernet key, or several separated by commas (first encrypts, all
    decrypt) while rotating; see secrets_store.py."""
    keys = [k.strip() for k in os.environ.get("GR_DATA_KEY", _DEV_DATA_KEY).split(",") if k.strip()]
    return keys or [_DEV_DATA_KEY]


def _fernet() -> MultiFernet:
    return MultiFernet([Fernet(k.encode()) for k in data_keys()])


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


def encrypt_text(value: str) -> str:
    """Encrypt any secret we must be able to read back (push tokens)."""
    return _fernet().encrypt(value.encode()).decode()


def decrypt_text(token: str) -> str:
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
