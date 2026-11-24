"""The people-facing web app at /app: served safely, and its device-key signature format works."""

import base64
import re

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from fastapi.testclient import TestClient

from guardian_registry.api import WEB_DIR, create_app
from guardian_registry.notify import LogSmsSender
from guardian_registry.service import Registry

from .conftest import AMMA, new_db


def client(clock):
    return TestClient(create_app(Registry(new_db(), clock), admin_token="a", sms=LogSmsSender(), run_worker=False))


def test_app_is_served_with_strict_headers(clock):
    c = client(clock)
    r = c.get("/app/")
    assert r.status_code == 200 and "Guardian Registry" in r.text
    csp = r.headers["content-security-policy"]
    for part in ("default-src 'self'", "script-src 'self'", "frame-ancestors 'none'", "object-src 'none'"):
        assert part in csp
    assert "unsafe-inline" not in csp
    assert r.headers["x-frame-options"] == "DENY" and r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["cross-origin-embedder-policy"] == "require-corp"
    assert r.headers["cross-origin-opener-policy"] == "same-origin" and r.headers["cross-origin-resource-policy"] == "same-origin"
    for f in ("app.js", "app.css", "manifest.json"):
        assert c.get(f"/app/{f}").status_code == 200
    assert c.get("/", follow_redirects=False).headers["location"] == "/app/"


def test_api_responses_are_not_cached(clock):
    r = client(clock).get("/healthz")
    assert r.headers["cache-control"] == "no-store" and "content-security-policy" not in r.headers


def test_app_has_no_inline_code_or_styles():
    """The CSP forbids inline script/style; keep the sources compatible with it."""
    html = (WEB_DIR / "index.html").read_text(encoding="utf-8")
    js = (WEB_DIR / "app.js").read_text(encoding="utf-8")
    assert not re.search(r"<script(?![^>]*\bsrc=)", html)          # no inline <script>
    assert " style=" not in html and "on" + "click=" not in html
    assert not re.search(r"\bstyle:\s*\"(?!currency\")", js)          # no style attributes built in JS
    assert "innerHTML" not in js                                     # text only, never markup


def raw_to_der(raw: bytes) -> bytes:
    """Python copy of app.js rawToDer, checked against cryptography's own encoding."""
    def integer(b: bytes) -> bytes:
        b = b.lstrip(b"\x00") or b"\x00"
        if b[0] & 0x80:
            b = b"\x00" + b
        return bytes([0x02, len(b)]) + b
    r, s = integer(raw[:32]), integer(raw[32:])
    return bytes([0x30, len(r) + len(s)]) + r + s


def test_webcrypto_signature_conversion_is_accepted(clock):
    """WebCrypto signs as raw r||s; the app converts to DER. Do the same and sign in."""
    c = client(clock)
    key = ec.generate_private_key(ec.SECP256R1())
    pub = base64.b64encode(key.public_key().public_bytes(serialization.Encoding.DER,
                                                         serialization.PublicFormat.SubjectPublicKeyInfo)).decode()
    sms = c.app.state.dispatcher.sms
    c.post("/v1/auth/otp", json={"mobile": AMMA})
    code = re.search(r"code: (\d{6})", sms.sent[-1][1]).group(1)
    ch = c.post("/v1/auth/challenge").json()["challenge"]
    der = key.sign(b"guardian-registry/v1:" + ch.encode(), ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der)
    raw = r.to_bytes(32, "big") + s.to_bytes(32, "big")          # what WebCrypto returns
    assert raw_to_der(raw) == der
    out = c.post("/v1/auth/verify", json={"mobile": AMMA, "code": code, "display_name": "Amma",
                                          "device_key": pub, "challenge": ch, "platform": "web",
                                          "device_proof": base64.b64encode(raw_to_der(raw)).decode()})
    assert out.status_code == 200, out.text


def test_admin_console_follows_the_same_rules(clock):
    html = (WEB_DIR / "admin.html").read_text(encoding="utf-8")
    js = (WEB_DIR / "admin.js").read_text(encoding="utf-8")
    assert not re.search(r"<script(?![^>]*\bsrc=)", html) and " style=" not in html
    assert "innerHTML" not in js and "localStorage" not in js     # credential lives only in sessionStorage
    from guardian_registry.api import create_app
    from guardian_registry.service import Registry
    from .conftest import new_db
    with TestClient(create_app(Registry(new_db(), clock), run_worker=False)) as c:
        r = c.get("/app/admin.html")
        assert r.status_code == 200 and "frame-ancestors 'none'" in r.headers["content-security-policy"]
        assert c.get("/app/admin.js").status_code == 200


def test_every_interface_string_has_hindi():
    """Every t("...") in the web app has a Hindi entry, and no sentence is left untranslated."""
    js = (WEB_DIR / "app.js").read_text(encoding="utf-8")
    table = (WEB_DIR / "i18n.js").read_text(encoding="utf-8").split("hi: {", 1)[1]
    keys = set(re.findall(r'"((?:[^"\\]|\\.)*)":', table))
    used = set(re.findall(r'\bt\("((?:[^"\\]|\\.)*)"', js))
    assert used and not sorted(used - keys), sorted(used - keys)
    left = [m.group(1) for m in re.finditer(r'"((?:[^"\\\n]|\\.)*)"', js)
            if " " in m.group(1) and m.group(1)[:1].isupper() and js[max(0, m.start() - 2):m.start()] != "t("]
    assert not left, left
    html = (WEB_DIR / "index.html").read_text(encoding="utf-8")
    assert html.index('src="i18n.js"') < html.index('src="app.js"')   # t() exists before app.js runs
    for label in re.findall(r'data-i18n="([^"]+)"', html):
        assert label in keys, label
