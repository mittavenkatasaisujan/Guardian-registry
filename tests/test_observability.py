"""Metrics, readiness, request IDs and JSON logs."""

import json
import logging

from fastapi.testclient import TestClient

from guardian_registry.api import create_app
from guardian_registry.observability import JsonFormatter, Metrics, clean_request_id, request_id
from guardian_registry.service import Registry

from .conftest import AMMA, new_db


def client(monkeypatch, **env):
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    reg = Registry(new_db())
    return reg, TestClient(create_app(reg, run_worker=False))


def test_metrics_use_route_templates_and_count_checks(monkeypatch):
    reg, c = client(monkeypatch, GR_ADMIN_TOKEN="dev-admin-token")
    with c:
        reg.register_user(AMMA, "Amma")
        pid, key = reg.register_participant("Bank", "bank", "RBI-1")
        h = {"X-Api-Key": key}
        out = c.post("/v1/checks", headers=h, json={"mobile": AMMA, "participant_txn_id": "t1", "amount": 100_00,
                                                     "payee": "shop@upi"}).json()
        c.get(f"/v1/checks/{out['check_id']}", headers=h)
        c.get("/v1/checks/chk_doesnotexist", headers=h)
        text = c.get("/metrics").text
    assert 'gr_checks_total{status="allowed"} 1' in text
    assert 'route="/v1/checks/{check_id}"' in text and "chk_doesnotexist" not in text
    assert 'gr_http_requests_total{method="GET",route="/v1/checks/{check_id}",status="404"} 1' in text
    assert "gr_http_request_seconds_bucket" in text and 'le="+Inf"' in text
    assert "gr_up 1" in text and 'gr_build_info{version="' in text
    assert "# TYPE gr_http_request_seconds histogram" in text


def test_metrics_token(monkeypatch):
    _, c = client(monkeypatch, GR_METRICS_TOKEN="m" * 24)
    with c:
        assert c.get("/metrics").status_code == 401
        assert c.get("/metrics", headers={"Authorization": "Bearer " + "m" * 24}).status_code == 200


def test_readyz(monkeypatch):
    reg, c = client(monkeypatch)
    with c:
        assert c.get("/readyz").json()["ready"] is True
        reg.db.conn.execute("PRAGMA user_version = 3") if reg.db.backend == "sqlite" else \
            reg.db.conn.execute("UPDATE gr_schema SET version = 3")
        r = c.get("/readyz")
        assert r.status_code == 503 and "schema v3" in r.json()["reason"]


def test_request_id_round_trip(monkeypatch):
    _, c = client(monkeypatch)
    with c:
        assert c.get("/healthz", headers={"X-Request-ID": "edge-abc-12345"}).headers["X-Request-ID"] == "edge-abc-12345"
        generated = c.get("/healthz", headers={"X-Request-ID": "bad id\nwith newline"}).headers["X-Request-ID"]
        assert generated != "bad id\nwith newline" and len(generated) == 24
    assert clean_request_id(None) != clean_request_id(None)


def test_json_log_line_carries_the_request_id():
    token = request_id.set("req-12345678")
    try:
        rec = logging.LogRecord("guardian_registry.x", logging.WARNING, __file__, 1, "sms to %s", ("+91******3210",), None)
        doc = json.loads(JsonFormatter().format(rec))
    finally:
        request_id.reset(token)
    assert doc["request_id"] == "req-12345678" and doc["message"] == "sms to +91******3210" and doc["level"] == "warning"


def test_label_escaping():
    m = Metrics()
    m.inc("x_total", {"v": 'a"b\\c\nd'})
    assert 'x_total{v="a\\"b\\\\c d"} 1' in m.render()
