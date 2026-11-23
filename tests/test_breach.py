"""Personal-data breach response (DPDP Act)."""

import pytest
from fastapi.testclient import TestClient

from guardian_registry.errors import Conflict, Invalid

from .conftest import AMMA, RAVI


def record(reg, **kw):
    args = dict(title="Backup bucket exposed", description="A misconfigured backup bucket was public for 3 hours.",
                detected_at="2026-11-23T12:00:00+05:30", occurred_from="2026-11-23T00:00:00+00:00",
                occurred_to="2026-11-23T06:00:00+00:00", categories=["mobile_numbers", "names"],
                cause="storage policy changed by a deploy script", containment="bucket made private; keys rotated")
    args.update(kw)
    return reg.record_incident("alice", **args)


class TestIncident:
    def test_record_and_affected_people(self, reg, family):
        inc = record(reg)
        assert inc["status"] == "open" and inc["affected_people"] == 3     # Amma, Ravi, Priya existed then
        assert inc["board"]["deadline"].startswith("2026-11-26") and inc["board"]["overdue"] is False
        only = record(reg, scope="users", user_ids=[family["amma"], "usr_doesnotexist"])
        assert only["affected_people"] == 1

    def test_validation(self, reg):
        with pytest.raises(Invalid, match="categories"):
            record(reg, categories=["passwords"])
        with pytest.raises(Invalid, match="timezone"):
            record(reg, detected_at="2026-11-23T06:00:00")
        with pytest.raises(Invalid, match="before"):
            record(reg, occurred_from="2026-11-24T00:00:00+00:00")
        with pytest.raises(Invalid, match="user_ids"):
            record(reg, scope="users")

    def test_four_eyes_notify_in_each_persons_language(self, reg, family, monkeypatch):
        monkeypatch.setenv("GR_GRIEVANCE_CONTACT", "grievance@registry.example.in")
        reg.set_language(family["ravi"], "hi")
        inc = record(reg)
        with pytest.raises(Conflict, match="propose"):
            reg.send_notification("bob", inc["id"])
        reg.propose_notification("alice", inc["id"])
        with pytest.raises(Conflict, match="second operator"):
            reg.send_notification("alice", inc["id"])
        out = reg.send_notification("bob", inc["id"])
        assert out["status"] == "notified" and out["notify"]["people"] == 3
        with pytest.raises(Conflict, match="already"):
            reg.send_notification("bob", inc["id"])
        amma = reg.db.one("SELECT title, body FROM notifications WHERE recipient_id=? AND kind='data_breach_notice' "
                          "AND channel='inapp'", (family["amma"],))
        assert "your mobile number, your name" in amma["body"] and "grievance@registry.example.in" in amma["body"]
        ravi = reg.db.one("SELECT title, body FROM notifications WHERE recipient_id=? AND kind='data_breach_notice' "
                          "AND channel='inapp'", (family["ravi"],))
        assert ravi["title"].startswith("एक सुरक्षा घटना") and "आपका मोबाइल नंबर, आपका नाम" in ravi["body"]
        assert reg.db.one("SELECT 1 FROM notifications WHERE recipient_id=? AND kind='data_breach_notice' "
                          "AND channel='sms'", (family["amma"],)), "urgent: goes by SMS too"
        assert reg.verify_audit().ok

    def test_board_report_and_deadline(self, reg, family, clock):
        inc = record(reg, detected_at=clock.now().isoformat())
        reg.update_incident("alice", inc["id"], remediation="policy-as-code check added to deploys")
        rep = reg.board_report(inc["id"])
        assert rep["data_principals_affected"] == 3 and rep["personal_data_affected"] == ["your mobile number", "your name"]
        assert rep["remedial_measures"].startswith("policy-as-code") and not rep["overdue"]
        clock.advance(hours=73)
        assert reg.board_report(inc["id"])["overdue"] is True
        done = reg.record_board_report("bob", inc["id"], "DPB/2026/0042")
        assert done["board"]["reference"] == "DPB/2026/0042" and done["board"]["overdue"] is False


def test_api(monkeypatch, reg, family):
    from guardian_registry.api import create_app
    monkeypatch.setenv("GR_OPERATORS", "alice:tok-alice-1234567,bob:tok-bob-12345678")
    a, b = {"X-Admin-Token": "tok-alice-1234567"}, {"X-Admin-Token": "tok-bob-12345678"}
    with TestClient(create_app(reg, run_worker=False)) as c:
        r = c.post("/v1/admin/incidents", headers=a, json={
            "title": "Leaked log file", "description": "A debug log with names was shared by mistake.",
            "detected_at": "2026-11-23T06:00:00+05:30", "occurred_from": "2026-11-22T00:00:00+05:30",
            "occurred_to": "2026-11-23T23:00:00+05:30", "categories": ["names"]})
        assert r.status_code == 201
        iid = r.json()["id"]
        assert c.post(f"/v1/admin/incidents/{iid}/notify", headers=a).json()["notify"]["proposed_by"] == "alice"
        assert c.post(f"/v1/admin/incidents/{iid}/notify/approve", headers=a).status_code == 409
        assert c.post(f"/v1/admin/incidents/{iid}/notify/approve", headers=b).json()["notify"]["people"] == 3
        assert c.get(f"/v1/admin/incidents/{iid}/board-report", headers=b).json()["incident_id"] == iid
        assert c.post("/v1/admin/incidents", headers=a, json={"title": "x"}).status_code == 422
