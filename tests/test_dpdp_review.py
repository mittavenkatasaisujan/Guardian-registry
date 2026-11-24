"""Fixes from the 2026-11-25 DPDP review (docs/reviews/legal-review.md)."""

import pytest

from guardian_registry.errors import Invalid
from guardian_registry.notify import Dispatcher, LogSmsSender, MINIMAL_BODY, alert_detail
from guardian_registry.privacy import NOTICE, NOTICE_VERSION

from .conftest import AMMA, RAVI, R


def test_people_can_correct_their_name(reg, family):
    assert reg.set_display_name(family["amma"], "  Amma Devi ")["display_name"] == "Amma Devi"
    assert reg.data_export(family["amma"])["profile"]["display_name"] == "Amma Devi"
    with pytest.raises(Invalid):
        reg.set_display_name(family["amma"], " ")


def test_nominee_is_set_exported_and_erased(reg, family, clock):
    amma = family["amma"]
    n = reg.set_nominee(amma, "Ravi", "son", "98765 43210")
    assert n["mobile"] == "+919876543210" and n["relation"] == "son"
    assert reg.data_export(amma)["nominee"]["name"] == "Ravi"
    with pytest.raises(Invalid):
        reg.set_nominee(amma, "Ravi", "son", "12345")
    reg.request_erasure(amma)
    clock.advance(days=8)
    reg.sweep_erasure()
    assert reg.nominee(amma) is None


def test_notice_names_outside_services_adults_and_new_rights():
    text = str(NOTICE)
    assert NOTICE_VERSION == "2026-11-25"
    assert "outside India" in text and "18 or older" in text and "nominate" in text and "PUT /v1/me/name" in text


def test_alert_detail_defaults(monkeypatch):
    monkeypatch.delenv("GR_ALERT_DETAIL", raising=False)
    assert alert_detail() == "full"
    monkeypatch.setenv("GR_ENV", "production")
    assert alert_detail() == "minimal"
    monkeypatch.setenv("GR_ALERT_DETAIL", "full")
    assert alert_detail() == "full"


def test_minimal_alerts_carry_no_payment_details_outside_the_app(reg, family, monkeypatch):
    monkeypatch.setenv("GR_ALERT_DETAIL", "minimal")
    sms = LogSmsSender()
    reg.db.conn.execute("DELETE FROM notifications")
    reg.check(family["bank"], AMMA, "dp1", 20_000 * R, "shop@upi", "upi")
    Dispatcher(reg.db, reg.clock, sms).run_once()
    assert sms.sent, "the guardian should get an SMS"
    for _, text in sms.sent:
        assert "20,000" not in text and "shop@upi" not in text and MINIMAL_BODY in text
    inapp = reg.db.all("SELECT body FROM notifications WHERE channel='inapp'")
    assert any("20,000" in r["body"] for r in inapp)          # the app still shows everything


def test_api_routes(reg):
    from fastapi.testclient import TestClient
    from guardian_registry.api import create_app
    uid, tok = reg.register_user("+919822244455", "Api Person")
    h = {"Authorization": f"Bearer {tok}"}
    with TestClient(create_app(reg, run_worker=False)) as c:
        assert c.put("/v1/me/name", headers=h, json={"display_name": "Api P"}).json()["display_name"] == "Api P"
        r = c.put("/v1/me/nominee", headers=h, json={"name": "N", "relation": "daughter", "mobile": RAVI})
        assert r.status_code == 200 and r.json()["nominee"]["relation"] == "daughter"
        assert c.get("/v1/me/nominee", headers=h).json()["nominee"]["name"] == "N"
        assert c.delete("/v1/me/nominee", headers=h).json() == {"nominee": None}
