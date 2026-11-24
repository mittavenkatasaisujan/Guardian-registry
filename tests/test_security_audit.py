"""Fixes from the 2026-11-25 security review (docs/reviews/security-review.md)."""

import pytest

from guardian_registry import security
from guardian_registry.errors import Invalid


@pytest.fixture
def production(monkeypatch):
    monkeypatch.setenv("GR_ENV", "production")


# SEC-1: no webhooks into the registry's own network
@pytest.mark.parametrize("url", [
    "https://169.254.169.254/latest/meta-data/", "https://10.0.0.5/hook", "https://127.0.0.1:8443/v1",
    "https://192.168.1.10/", "https://[::1]/", "https://0.0.0.0/", "https://100.64.0.1/x",
])
def test_internal_webhook_urls_are_refused_in_production(production, url):
    assert "public address" in (security.webhook_url_problem(url) or "")


def test_public_https_webhooks_are_fine(production):
    assert security.webhook_url_problem("https://8.8.8.8/hook") is None
    assert "https://" in security.webhook_url_problem("http://8.8.8.8/hook")
    assert "https://" in security.webhook_url_problem("http://localhost:9000/hook")   # not in production


def test_unresolvable_hosts_fail_closed(production, monkeypatch):
    import socket
    def boom(*a, **k):
        raise OSError("no such host")
    monkeypatch.setattr(socket, "getaddrinfo", boom)
    assert security.webhook_url_problem("https://does-not-exist.example/hook") is not None


def test_development_still_allows_local_webhooks():
    assert security.webhook_url_problem("http://localhost:9000/hook") is None
    assert security.webhook_url_problem("https://10.0.0.5/hook") is None


def test_set_webhook_refuses_metadata_address(reg, production, monkeypatch):
    bank, _ = reg.register_participant("Audit Bank")
    with pytest.raises(Invalid, match="public address"):
        reg.set_webhook(bank, "https://169.254.169.254/latest")


def test_delivery_rechecks_the_address(reg, production):
    """A URL saved earlier (or a name that now resolves inside) isn't delivered to."""
    from guardian_registry.notify import Dispatcher, LogSmsSender
    bank, _ = reg.register_participant("Audit Bank 2")
    with reg.db.tx() as c:
        c.execute("UPDATE participants SET webhook_url=?, webhook_secret='s' WHERE id=?", ("https://10.1.2.3/h", bank))
        c.execute("INSERT INTO notifications (id, recipient_type, recipient_id, kind, channel, title, body, payload, "
                  "status, attempts, next_attempt_at, created_at) VALUES ('n1','participant',?, 'check.updated', "
                  "'webhook','t','b','{}','pending',0,'2000-01-01T00:00:00+00:00','2000-01-01T00:00:00+00:00')", (bank,))

    class NoHttp:
        def post(self, *a, **k):
            raise AssertionError("must not send")

    d = Dispatcher(reg.db, reg.clock, LogSmsSender(), http=NoHttp())
    d.run_once()
    row = reg.db.one("SELECT last_error FROM notifications WHERE id='n1'")
    assert "public address" in (row["last_error"] or "")


# SEC-2, SEC-3: production configuration
def _prod_env(monkeypatch, **extra):
    monkeypatch.setenv("GR_ENV", "production")
    monkeypatch.setenv("GR_PEPPER", "p" * 32)
    from cryptography.fernet import Fernet
    monkeypatch.setenv("GR_DATA_KEY", Fernet.generate_key().decode())
    monkeypatch.setenv("GR_SMS_PROVIDER", "twilio")
    for k, v in extra.items():
        monkeypatch.setenv(k, v)


def test_production_refuses_the_public_debug_certificate(monkeypatch):
    _prod_env(monkeypatch, GR_ANDROID_CERT_DIGESTS="AB," + security.PUBLIC_DEBUG_CERT_SHA256.upper())
    with pytest.raises(RuntimeError, match="public debug certificate"):
        security.check_production_config()


def test_production_refuses_codes_only_sms(monkeypatch):
    _prod_env(monkeypatch, GR_SMS_PROVIDER="twilio_verify")
    with pytest.raises(RuntimeError, match="sign-in codes only"):
        security.check_production_config()


def test_good_production_config_passes(monkeypatch):
    _prod_env(monkeypatch)
    security.check_production_config()


# CodeQL py/log-injection
def test_log_lines_cannot_be_forged():
    assert security.log_safe("Asha\nINFO forged entry\r\nmore\x07") == "Asha INFO forged entry more?"


# CodeQL py/path-injection: only the server's own language codes become file names
def test_translation_files_only_for_known_languages():
    from guardian_registry import messages
    assert messages._catalog_table("../../etc/passwd", 1) == {}
    assert messages._catalog_table("ta", 1) is not None


# CodeQL py/stack-trace-exposure: operators get fixed messages, not Python's exception text
def test_operator_event_errors_are_fixed_messages(reg):
    op, _ = reg.register_participant("Audit Telco", kind="telecom")
    out = reg.ingest_operator_events(op, [
        {"event_id": "e1", "type": "sim_swap", "mobile": "not-a-number", "occurred_at": "2026-11-20T10:00:00+05:30"},
        {"event_id": "e2", "type": "sim_swap", "mobile": "+919800000001", "occurred_at": "yesterday-ish"},
    ])
    details = [r["detail"] for r in out["results"]]
    assert details[0] == "mobile must be a valid Indian mobile number"
    assert "ISO 8601" in details[1] and "yesterday-ish" not in details[1]


# Webhook delivery goes to the address that was checked (no DNS rebinding between check and connect)
def _resolves_to(monkeypatch, *addresses):
    import socket
    calls = []

    def fake(host, port, *a, **k):
        calls.append(host)
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (a, port)) for a in addresses]
    monkeypatch.setattr(socket, "getaddrinfo", fake)
    return calls


def test_pin_sends_to_the_checked_address_with_the_original_name(production, monkeypatch):
    calls = _resolves_to(monkeypatch, "93.184.216.34")
    problem, target, headers, ext = security.pin_webhook("https://hooks.bank.example:8443/gr?x=1")
    assert problem is None and target == "https://93.184.216.34:8443/gr?x=1"
    assert headers == {"Host": "hooks.bank.example:8443"} and ext == {"sni_hostname": "hooks.bank.example"}
    assert calls == ["hooks.bank.example"]          # resolved once


def test_pin_refuses_a_name_with_any_internal_address(production, monkeypatch):
    _resolves_to(monkeypatch, "93.184.216.34", "10.0.0.7")
    assert "public address" in security.pin_webhook("https://hooks.bank.example/gr")[0]


def test_pin_leaves_addresses_and_development_alone(production, monkeypatch):
    assert security.pin_webhook("https://8.8.8.8/h") == (None, "https://8.8.8.8/h", {}, {})
    monkeypatch.delenv("GR_ENV")
    assert security.pin_webhook("http://localhost:9000/h") == (None, "http://localhost:9000/h", {}, {})


def test_delivery_connects_to_the_pinned_address(reg, production, monkeypatch):
    import httpx

    from guardian_registry.notify import Dispatcher, LogSmsSender
    _resolves_to(monkeypatch, "93.184.216.34")
    bank, _ = reg.register_participant("Audit Bank 3")
    with reg.db.tx() as c:
        c.execute("UPDATE participants SET webhook_url=?, webhook_secret='s' WHERE id=?",
                  ("https://hooks.bank.example/gr", bank))
        c.execute("INSERT INTO notifications (id, recipient_type, recipient_id, kind, channel, title, body, payload, "
                  "status, attempts, next_attempt_at, created_at) VALUES ('n2','participant',?, 'check.updated', "
                  "'webhook','t','b','{}','pending',0,'2000-01-01T00:00:00+00:00','2000-01-01T00:00:00+00:00')", (bank,))
    seen = []

    def hook(request):
        seen.append(request)
        return httpx.Response(200)
    Dispatcher(reg.db, reg.clock, LogSmsSender(), http=httpx.Client(transport=httpx.MockTransport(hook))).run_once()
    assert len(seen) == 1
    r = seen[0]
    assert r.url.host == "93.184.216.34" and r.headers["host"] == "hooks.bank.example"
    assert r.extensions["sni_hostname"] == "hooks.bank.example" and r.headers["x-gr-signature"]
