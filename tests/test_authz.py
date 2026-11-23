"""Authorization matrix: every route either is deliberately public or refuses anonymous calls,
and nobody can reach another tenant's data."""

import io
import re
import zipfile

import pytest
from fastapi.testclient import TestClient

from guardian_registry.api import create_app
from guardian_registry.tables import TableError, xlsx_rows

from .conftest import AMMA, R

PUBLIC = {
    ("GET", "/"), ("GET", "/healthz"), ("GET", "/readyz"), ("GET", "/metrics"), ("GET", "/v1/presets"),
    ("GET", "/v1/privacy/notice"), ("GET", "/v1/languages"), ("POST", "/v1/auth/otp"), ("POST", "/v1/auth/challenge"),
    ("POST", "/v1/auth/verify"), ("POST", "/v1/recovery/start"), ("POST", "/v1/recovery/status"),
}


@pytest.fixture
def api(reg, family, monkeypatch):
    monkeypatch.setenv("GR_OPERATORS", "alice:tok-alice-1234567,bob:tok-bob-12345678")
    with TestClient(create_app(reg, run_worker=False)) as c:
        yield c


def _fill(path: str) -> str:
    return re.sub(r"\{[^}]+\}", "x_1", path)


def test_every_route_is_public_or_refuses_anonymous_calls(api):
    checked = 0
    for route in api.app.routes:
        methods = getattr(route, "methods", None) or set()
        path = getattr(route, "path", "")
        if not path.startswith("/v1/") and path not in ("/", "/healthz", "/readyz", "/metrics"):
            continue  # docs, static files
        for m in sorted(methods - {"HEAD", "OPTIONS"}):
            if (m, path) in PUBLIC:
                continue
            r = api.request(m, _fill(path), json={})
            assert r.status_code in (401, 403, 503), f"{m} {path} answered {r.status_code} without credentials"
            checked += 1
    assert checked > 80


def test_a_bank_cannot_see_or_touch_another_banks_checks(api, reg, family):
    _, key_a = reg.register_participant("Bank A")
    _, key_b = reg.register_participant("Bank B")
    a, b = {"X-Api-Key": key_a}, {"X-Api-Key": key_b}
    chk = api.post("/v1/checks", headers=a, json={"mobile": AMMA, "participant_txn_id": "t1", "amount": 100 * R,
                                                  "payee": "known@upi"}).json()
    cid = chk["check_id"]
    assert api.get(f"/v1/checks/{cid}", headers=b).status_code == 404
    assert api.post(f"/v1/checks/{cid}/outcome", headers=b, json={"completed": True}).status_code == 404
    assert api.post(f"/v1/checks/{cid}/fraud-label", headers=b, json={"fraud": True}).status_code == 404
    assert "principal_id" not in api.get(f"/v1/checks/{cid}", headers=a).json()   # banks never see who protects whom


def test_people_cannot_act_on_other_peoples_payments(api, reg, family):
    bank = family["bank"]
    held = reg.check(bank, AMMA, "t2", 20_000 * R, "known@upi")              # waits for Ravi
    _, stranger = reg.register_user("+919844455566", "Stranger")
    s = {"Authorization": f"Bearer {stranger}"}
    for path in (f"/v1/guardian/payments/{held['check_id']}/approve",
                 f"/v1/guardian/payments/{held['check_id']}/deny",
                 f"/v1/me/payments/{held['check_id']}/cancel"):
        assert api.post(path, headers=s).status_code in (403, 404), path
    assert reg.get_check(bank, held["check_id"])["status"] == "pending_approval"
    assert api.get(f"/v1/guardian/wards/{family['amma']}/rules", headers=s).status_code in (403, 404)


def test_operator_endpoints_need_an_operator(api, reg, family):
    _, key = reg.register_participant("Bank C")
    _, tok = reg.register_user("+919855566677", "Person")
    for h in ({"X-Api-Key": key}, {"Authorization": f"Bearer {tok}"}, {"X-Admin-Token": "wrong-token-123456"}):
        assert api.get("/v1/admin/participants", headers=h).status_code in (401, 403)


def test_spreadsheets_with_a_dtd_are_refused():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("xl/workbook.xml", '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "aaaa">]><workbook/>')
    with pytest.raises(TableError, match="DTD"):
        xlsx_rows(buf.getvalue())
