"""The Python client library for banks, against the real API in-process."""

import hashlib
import hmac
import sys
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "sdk" / "python"))

from guardian_registry_client import (  # noqa: E402
    Client, GuardianRegistryError, WebhookError, parse_webhook, verify_webhook)

from guardian_registry.api import create_app  # noqa: E402

from .conftest import AMMA, R  # noqa: E402

# Shared with the Java library's tests (sdk/java): the same secret and body give this signature.
VECTOR_SECRET = "whsec_test_vector"
VECTOR_BODY = b'{"id":"ntf_1","event":"check.updated","data":{"check":{"status":"approved"}}}'
VECTOR_SIG = "sha256=" + hmac.new(VECTOR_SECRET.encode(), VECTOR_BODY, hashlib.sha256).hexdigest()


@pytest.fixture
def app_client(reg, family):
    _, key = reg.register_participant("SDK Bank")
    tc = TestClient(create_app(reg, run_worker=False))
    tc.__enter__()
    yield tc, key, family
    tc.__exit__(None, None, None)


def sdk(tc, key, transport=None, sleeps=None):
    http = httpx.Client(transport=transport) if transport else tc
    return Client("http://testserver", key, http=http, sleep=(sleeps.append if sleeps is not None else (lambda s: None)))


def test_allowed_then_outcome(app_client):
    tc, key, _ = app_client
    gr = sdk(tc, key)
    res = gr.check(AMMA, "T-1", 500 * R, "known@upi")
    assert res.may_execute and not res.waiting and res.status == "allowed"
    assert gr.report_outcome(res.check_id, True).raw["completed_at"]
    assert gr.report_outcome(res.check_id, True).check_id == res.check_id   # a retried report is fine


def test_held_for_a_guardian_then_approved(app_client, reg):
    tc, key, family = app_client
    gr = sdk(tc, key)
    res = gr.check(AMMA, "T-2", 20_000 * R, "known@upi")
    assert res.waiting and not res.may_execute and res.approval_expires_at
    assert any("approval threshold" in r for r in res.reasons)
    reg.approve_check(family["ravi"], res.check_id)
    final = gr.wait_for_decision(res.check_id, timeout=5, poll_every=0)
    assert final.status == "approved" and final.may_execute


def test_not_enrolled(app_client):
    tc, key, _ = app_client
    res = sdk(tc, key).check("+919800099999", "T-3", 100 * R, "x@upi")
    assert res.may_execute and not res.enrolled and res.check_id is None


def test_retries_the_same_request_and_never_double_checks(app_client, reg):
    tc, key, _ = app_client
    calls = {"n": 0}

    def flaky(request):
        calls["n"] += 1
        if calls["n"] == 1:
            raise httpx.ConnectError("connection reset")
        if calls["n"] == 2:
            return httpx.Response(503, json={"detail": "busy"})
        if calls["n"] == 3:
            return httpx.Response(429, headers={"Retry-After": "2"}, json={"detail": "rate limit exceeded"})
        r = tc.request(request.method, str(request.url), content=request.content, headers=dict(request.headers))
        return httpx.Response(r.status_code, content=r.content, headers=r.headers)

    sleeps = []
    res = sdk(tc, key, httpx.MockTransport(flaky), sleeps).check(AMMA, "T-4", 500 * R, "known@upi")
    assert res.may_execute and calls["n"] == 4
    assert sleeps[2] >= 2                       # Retry-After honoured
    again = sdk(tc, key).check(AMMA, "T-4", 500 * R, "known@upi")
    assert again.check_id == res.check_id       # same txn id: same check
    assert reg.db.one("SELECT COUNT(*) n FROM checks WHERE participant_txn_id='T-4'")["n"] == 1


def test_client_errors_are_not_retried(app_client):
    tc, key, _ = app_client
    calls = {"n": 0}

    def bad(request):
        calls["n"] += 1
        return httpx.Response(400, json={"detail": "payee is required"})

    with pytest.raises(GuardianRegistryError) as e:
        sdk(tc, key, httpx.MockTransport(bad)).check(AMMA, "T-5", 100, "x")
    assert e.value.status == 400 and calls["n"] == 1
    with pytest.raises(GuardianRegistryError) as e:
        Client("http://testserver", "wrong-key", http=tc).check(AMMA, "T-6", 100, "x@upi")
    assert e.value.status == 401


def test_amounts_must_be_paise_ints(app_client):
    tc, key, _ = app_client
    for bad in (12.5, 0, -1, True, "100"):
        with pytest.raises(ValueError):
            sdk(tc, key).check(AMMA, "T-7", bad, "x@upi")


def test_fraud_payee_report_and_status(app_client):
    tc, key, _ = app_client
    gr = sdk(tc, key)
    gr.report_fraud_payee("Mule@UPI", "confirmed digital-arrest fraud", "CASE-77")
    assert gr.payee_status("mule@upi")["status"] == "reported"
    assert gr.check(AMMA, "T-8", 100 * R, "mule@upi").waiting


def test_label_fraud(app_client, reg):
    tc, key, _ = app_client
    gr = sdk(tc, key)
    res = gr.check(AMMA, "T-9", 100 * R, "known@upi")
    assert gr.label_fraud(res.check_id, True, "complaint 9")["label"] == "fraud"
    assert reg.db.one("SELECT fraud_label FROM checks WHERE id=?", (res.check_id,))["fraud_label"] == "fraud"


def test_webhooks():
    assert verify_webhook(VECTOR_SECRET, VECTOR_BODY, VECTOR_SIG)
    assert not verify_webhook(VECTOR_SECRET, VECTOR_BODY + b" ", VECTOR_SIG)
    assert not verify_webhook("other", VECTOR_BODY, VECTOR_SIG)
    assert not verify_webhook(VECTOR_SECRET, VECTOR_BODY, None)
    assert parse_webhook(VECTOR_SECRET, VECTOR_BODY, VECTOR_SIG)["event"] == "check.updated"
    with pytest.raises(WebhookError):
        parse_webhook(VECTOR_SECRET, VECTOR_BODY, "sha256=00")


def test_the_java_test_vector_is_current():
    java = (Path(__file__).resolve().parent.parent / "sdk" / "java" / "src" / "test" / "java" /
            "guardianregistry" / "client" / "WebhookTest.java").read_text(encoding="utf-8")
    assert VECTOR_SIG in java and VECTOR_SECRET in java
