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
    assert "outside India" in text and "18 or older" in text and "nominate" in text and "Your details" in text


def test_notice_in_hindi_has_the_same_shape_and_version():
    from guardian_registry.privacy import NOTICE_HI
    assert NOTICE_HI["version"] == NOTICE_VERSION and NOTICE_HI.keys() == NOTICE.keys()
    for k, v in NOTICE.items():
        if isinstance(v, list):
            assert len(NOTICE_HI[k]) == len(v), k
            assert all(any("\u0900" <= ch <= "\u097f" for ch in item) for item in NOTICE_HI[k]), k


def test_notice_language_follows_the_reader(reg):
    from fastapi.testclient import TestClient

    from guardian_registry.api import create_app
    with TestClient(create_app(reg, run_worker=False)) as c:
        en = c.get("/v1/privacy/notice").json()
        hi = c.get("/v1/privacy/notice", headers={"Accept-Language": "hi-IN,hi;q=0.9"}).json()
    assert en["language"] == "en" and hi["language"] == "hi" and en["version"] == hi["version"]
    assert "भारत के बाहर" in str(hi["who_sees_it"]) and hi["grievance_officer"] == en["grievance_officer"]


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


def test_sign_in_for_a_new_number_says_not_enrolled_in_any_language(reg):
    """The web app asks for a name when it sees code not_enrolled; the message itself is translated."""
    import os

    from fastapi.testclient import TestClient

    from guardian_registry.api import create_app
    os.environ["GR_OTP_DEV_ECHO"] = "1"
    try:
        with TestClient(create_app(reg, run_worker=False)) as c:
            code = c.post("/v1/auth/otp", json={"mobile": "+919811112222"}).json()["dev_code"]
            r = c.post("/v1/auth/verify", json={"mobile": "+919811112222", "code": code},
                       headers={"Accept-Language": "hi"})
    finally:
        del os.environ["GR_OTP_DEV_ECHO"]
    assert r.status_code == 422 and r.json()["code"] == "not_enrolled" and "पंजीकृत" in r.json()["detail"]



# DPDP Act s.9: the service is for adults; a new account must confirm 18 or older
def test_new_accounts_must_confirm_they_are_adults(reg):
    import os

    from fastapi.testclient import TestClient

    from guardian_registry.api import create_app
    os.environ["GR_OTP_DEV_ECHO"] = "1"
    try:
        with TestClient(create_app(reg, run_worker=False)) as c:
            m = "+919811113333"
            code = c.post("/v1/auth/otp", json={"mobile": m}).json()["dev_code"]
            r = c.post("/v1/auth/verify", json={"mobile": m, "code": code, "display_name": "Young"},
                       headers={"Accept-Language": "hi"})
            assert r.status_code == 422 and r.json()["code"] == "adult_required" and "18" in r.json()["detail"]
            # the code wasn't used up: confirming and trying again works
            r = c.post("/v1/auth/verify", json={"mobile": m, "code": code, "display_name": "Grown", "adult": True})
            assert r.status_code == 200 and r.json()["new_user"]
            h = {"Authorization": f"Bearer {r.json()['token']}"}
            assert c.get("/v1/me/data-export", headers=h).json()["profile"]["adult_confirmed_at"]
            # signing in again later doesn't ask
            code = c.post("/v1/auth/otp", json={"mobile": m}).json()["dev_code"]
            assert c.post("/v1/auth/verify", json={"mobile": m, "code": code}).status_code == 200
    finally:
        del os.environ["GR_OTP_DEV_ECHO"]


# DPDP Act s.13: complaints to the grievance officer, answered in the app within 90 days
def test_complaints_are_answered_in_the_app(reg, family, clock):
    from guardian_registry.errors import Conflict as _Conflict
    from guardian_registry.errors import Invalid as _Invalid
    amma = family["amma"]
    with pytest.raises(_Invalid, match="10 to 2000"):
        reg.raise_grievance(amma, "too short")
    g = reg.raise_grievance(amma, "  My guardian was told about a payment I never made.  ")
    assert g["status"] == "open" and g["text"] == "My guardian was told about a payment I never made."
    assert g["due_at"][:10] == "2027-02-21"                            # 90 days from 2026-11-23
    row = reg.db.one("SELECT text_enc FROM grievances WHERE id=?", (g["id"],))
    assert "guardian" not in row["text_enc"]                           # stored encrypted
    op = reg.grievances_for_operator()
    assert [x["id"] for x in op] == [g["id"]] and op[0]["person_name"] == "Amma" and not op[0]["overdue"]
    out = reg.answer_grievance("op-1", g["id"], "We checked: it was a bank test message. Sorry.")
    assert out["status"] == "answered" and out["answered_by"] == "op-1"
    with pytest.raises(_Conflict):
        reg.answer_grievance("op-1", g["id"], "again")
    mine = reg.grievances(amma)
    assert mine[0]["answer"].startswith("We checked") and "answered_by" not in mine[0]
    alerts = reg.db.all("SELECT kind FROM notifications WHERE recipient_id=? AND kind='grievance_answered'", (amma,))
    assert alerts
    assert reg.data_export(amma)["complaints"][0]["id"] == g["id"]
    for i in range(5):
        reg.raise_grievance(amma, f"complaint number {i} about something")
    with pytest.raises(_Conflict, match="5 complaints"):
        reg.raise_grievance(amma, "one complaint too many here")
    clock.advance(days=91)
    assert all(x["overdue"] for x in reg.grievances_for_operator())


def test_complaints_over_http_and_erasure(reg, family, clock):
    from fastapi.testclient import TestClient

    from guardian_registry.api import create_app
    uid, tok = reg.register_user("+919833330001", "Complainer")
    h = {"Authorization": f"Bearer {tok}"}
    with TestClient(create_app(reg, admin_token="adm", run_worker=False)) as c:
        r = c.post("/v1/me/grievances", headers={**h, "Accept-Language": "hi"}, json={"text": "short"})
        assert r.status_code == 422 and "अक्षरों" in r.json()["detail"]
        gid = c.post("/v1/me/grievances", headers=h, json={"text": "Please explain why my payment was held."}).json()["id"]
        assert c.get("/v1/admin/grievances", headers={"X-Admin-Token": "adm"}).json()[0]["id"] == gid
        assert c.get("/v1/admin/grievances", headers=h).status_code in (401, 403)       # people can't read others'
        c.post(f"/v1/admin/grievances/{gid}/answer", headers={"X-Admin-Token": "adm"}, json={"answer": "It was over your limit."})
        assert c.get("/v1/me/grievances", headers=h).json()[0]["answer"] == "It was over your limit."
    reg.request_erasure(uid)
    clock.advance(days=8)
    reg.sweep_erasure()
    assert reg.db.one("SELECT COUNT(*) n FROM grievances WHERE user_id=?", (uid,))["n"] == 0
