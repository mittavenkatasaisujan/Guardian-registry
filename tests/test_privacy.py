"""DPDP Act mechanics: notice and consent, data export, held erasure, retention."""

import pytest
from fastapi.testclient import TestClient

from guardian_registry.errors import Conflict, Invalid, NotFound
from guardian_registry.privacy import ERASURE_HOLD_DAYS, NOTICE_VERSION
from guardian_registry.security import normalize_mobile

from .conftest import AMMA, R, RAVI


class TestConsent:
    def test_notice_and_versioned_consent(self, reg, family, monkeypatch):
        monkeypatch.setenv("GR_GRIEVANCE_CONTACT", "grievance@registry.example.in")
        n = reg.privacy_notice()
        assert n["version"] == NOTICE_VERSION and n["grievance_officer"] == "grievance@registry.example.in"
        with pytest.raises(Invalid, match="current notice"):
            reg.record_consent(family["amma"], "1999-01-01")
        assert not reg.consents(family["amma"])["accepted_current"]
        reg.record_consent(family["amma"], NOTICE_VERSION)
        out = reg.record_consent(family["amma"], NOTICE_VERSION)  # once per version
        assert out["accepted_current"] and len(out["accepted"]) == 1


class TestExport:
    def test_export_has_everything_readable(self, reg, family):
        reg.check(family["bank"], AMMA, "t1", 20_000 * R, "known@upi")
        reg.add_push_token(family["amma"], "push-token-for-export", "android")
        reg.record_consent(family["amma"], NOTICE_VERSION)
        d = reg.data_export(family["amma"])
        assert d["profile"]["mobile"] == normalize_mobile(AMMA) and d["profile"]["display_name"] == "Amma"
        assert d["my_guardians"][0]["guardian"] == "Ravi" and d["payment_checks"][0]["amount"] == 20_000 * R
        assert d["push_devices"] == [{"platform": "android", "added": d["push_devices"][0]["added"]}]
        assert "push-token-for-export" not in str(d)          # secrets aren't "data about you"
        assert d["consents"][0]["notice_version"] == NOTICE_VERSION
        assert any(a["action"] == "check.decided" or a["action"].startswith("check") for a in d["audit_trail"])
        assert reg.data_export(family["ravi"])["people_i_protect"][0]["person"] == "Amma"


class TestErasure:
    def test_held_then_erased(self, reg, family, clock):
        amma, ravi = family["amma"], family["ravi"]
        reg.check(family["bank"], AMMA, "t1", 100 * R, "known@upi")
        out = reg.request_erasure(amma)
        assert out["status"] == "pending"
        with pytest.raises(Conflict):
            reg.request_erasure(amma)
        alert = reg.db.one("SELECT 1 FROM notifications WHERE recipient_id=? AND kind='erasure_requested'", (ravi,))
        assert alert, "guardians are told, so pressure to delete protection is noticed"
        clock.advance(days=ERASURE_HOLD_DAYS - 1)
        assert reg.sweep().get("accounts_erased") is None and reg.user_by_mobile(AMMA) == amma
        clock.advance(days=1, minutes=1)
        assert reg.sweep()["accounts_erased"] == 1

        assert reg.user_by_mobile(AMMA) is None
        u = reg.db.one("SELECT * FROM users WHERE id=?", (amma,))
        assert u["mobile_enc"] is None and u["display_name"] == "Erased user" and u["erased_at"]
        assert reg.db.one("SELECT COUNT(*) n FROM sessions WHERE user_id=?", (amma,))["n"] == 0
        assert reg.db.one("SELECT status FROM guardianships WHERE principal_id=?", (amma,))["status"] == "ended"
        assert reg.db.one("SELECT payee FROM checks WHERE principal_id=?", (amma,))["payee"] == "(erased)"
        assert normalize_mobile(AMMA) not in str([dict(r) for r in reg.db.all("SELECT * FROM users")])
        assert reg.verify_audit().ok  # the chain survives erasure
        # a bank asking about the number now sees someone not enrolled
        assert reg.check(family["bank"], AMMA, "t2", 100 * R, "x@upi")["may_execute"] is True
        # and the number can enrol again as a new person
        new, _ = reg.register_user(AMMA, "Amma again")
        assert new != amma

    def test_cancel(self, reg, family, clock):
        reg.request_erasure(family["amma"])
        assert reg.cancel_erasure(family["amma"])["status"] == "cancelled"
        with pytest.raises(NotFound):
            reg.cancel_erasure(family["amma"])
        clock.advance(days=ERASURE_HOLD_DAYS + 1)
        reg.sweep()
        assert reg.user_by_mobile(AMMA) == family["amma"]

    def test_erasing_a_guardian_ends_their_role(self, reg, family, clock):
        reg.request_erasure(family["ravi"])
        clock.advance(days=ERASURE_HOLD_DAYS + 1)
        reg.sweep()
        assert reg.db.one("SELECT status FROM guardianships WHERE guardian_id=?", (family["ravi"],))["status"] == "ended"
        assert reg.user_by_mobile(RAVI) is None


def test_retention(reg, family, clock, monkeypatch):
    monkeypatch.setenv("GR_RETENTION_ALERT_DAYS", "30")
    reg.check(family["bank"], AMMA, "t1", 20_000 * R, "known@upi")
    reg.db.conn.execute("UPDATE notifications SET status='sent'")
    clock.advance(days=31)
    assert reg.sweep()["purged"]["alerts"] > 0
    assert reg.db.one("SELECT COUNT(*) n FROM notifications WHERE created_at < ?",
                      (reg._now()[:10],))["n"] == 0


def test_api(reg):
    from guardian_registry.api import create_app
    uid, tok = reg.register_user("+919833333333", "Api Person")
    h = {"Authorization": f"Bearer {tok}"}
    with TestClient(create_app(reg, run_worker=False)) as c:
        assert c.get("/v1/privacy/notice").json()["version"] == NOTICE_VERSION
        assert c.post("/v1/me/consents", headers=h, json={"notice_version": NOTICE_VERSION}).json()["accepted_current"]
        r = c.get("/v1/me/data-export", headers=h)
        assert r.status_code == 200 and "attachment" in r.headers["content-disposition"]
        assert r.json()["profile"]["display_name"] == "Api Person"
        assert c.get("/v1/me/data-export").status_code == 401
        assert c.post("/v1/me/erasure", headers=h).json()["status"] == "pending"
        assert c.delete("/v1/me/erasure", headers=h).json()["status"] == "cancelled"
