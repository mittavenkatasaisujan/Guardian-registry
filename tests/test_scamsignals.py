"""Shared scam signals: the cross-bank payee watchlist and coaching patterns."""

from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

from guardian_registry import messages
from guardian_registry.clock import FixedClock
from guardian_registry.errors import Forbidden, Invalid, NotFound
from guardian_registry.scamsignals import REPORT_DAYS
from guardian_registry.service import Registry

from .conftest import AMMA, PRIYA, R, new_db

MULE = "Mule.Account@upi"


@pytest.fixture
def banks(reg, family):
    b2, _ = reg.register_participant("Second Bank")
    b3, _ = reg.register_participant("Third Bank")
    return family["bank"], b2, b3


def pay(reg, family, amount_rupees, payee, txn):
    return reg.check(family["bank"], AMMA, txn, amount_rupees * R, payee)


class TestWatchlist:
    def test_one_report_holds_two_confirm_and_block(self, reg, family, banks):
        b1, b2, _ = banks
        assert pay(reg, family, 500, MULE, "t0")["status"] == "allowed"
        out = reg.report_fraud_payee(b1, MULE, "customer reported a digital-arrest scam", "CMP-1")
        assert out == {"payee": "mule.account@upi", "status": "reported", "reporting_banks": 1}
        held = pay(reg, family, 500, "mule.account@UPI", "t1")       # small amount, any case
        assert held["status"] == "pending_approval"
        assert "a bank has reported fraud involving this payee" in held["reasons"]
        reg.report_fraud_payee(b2, MULE, "second victim confirmed")
        blocked = pay(reg, family, 500, MULE, "t2")
        assert blocked["status"] == "blocked" and "banks have confirmed fraud involving this payee" in blocked["reasons"]

    def test_without_a_guardian_it_waits_a_day(self, reg, banks, clock):
        reg.register_user(PRIYA.replace("3", "9"), "Solo")
        reg.report_fraud_payee(banks[0], MULE, "confirmed fraud")
        out = reg.check(banks[0], PRIYA.replace("3", "9"), "s1", 300 * R, MULE)
        assert out["status"] == "cooling_off"
        assert out["release_at"] >= (clock.now().replace(microsecond=0)).isoformat()[:10]

    def test_withdraw_clear_confirm(self, reg, family, banks):
        b1, b2, _ = banks
        reg.report_fraud_payee(b1, MULE, "confirmed fraud")
        reg.report_fraud_payee(b2, MULE, "confirmed fraud")
        assert reg.withdraw_fraud_report(b2, MULE)["status"] == "reported"
        with pytest.raises(NotFound):
            reg.withdraw_fraud_report(b2, MULE)
        assert reg.operator_watch_decision("alice", MULE, "cleared", "merchant verified by NPCI")["status"] == "none"
        assert pay(reg, family, 500, MULE, "t1")["status"] == "allowed"
        reg.clock.advance(seconds=1)
        assert reg.report_fraud_payee(b2, MULE, "new case after clearance")["status"] == "reported"
        assert reg.operator_watch_decision("bob", MULE, "confirmed", "pattern of complaints")["status"] == "confirmed"
        assert pay(reg, family, 500, MULE, "t2")["status"] == "blocked"
        assert reg.verify_audit().ok

    def test_reports_expire_and_suspended_banks_stop_counting(self, reg, family, banks, clock):
        b1, b2, _ = banks
        reg.report_fraud_payee(b1, MULE, "confirmed fraud")
        reg.report_fraud_payee(b2, MULE, "confirmed fraud")
        reg.suspend_participant("alice", b2, "key leak")
        assert reg.payee_status(MULE)["status"] == "reported"
        clock.advance(days=REPORT_DAYS + 1)
        assert reg.payee_status(MULE)["status"] == "none"

    def test_only_banks_that_run_checks_can_report(self, reg):
        telco, _ = reg.register_participant("Telco", "telecom", "DOT-1")
        with pytest.raises(Forbidden):
            reg.report_fraud_payee(telco, MULE, "we think it is fraud")

    def test_validation(self, reg, banks):
        with pytest.raises(Invalid):
            reg.report_fraud_payee(banks[0], "   ", "x reason")
        with pytest.raises(Invalid):
            reg.operator_watch_decision("alice", MULE, "maybe", "hmm hmm")

    def test_api_shows_status_not_reporters(self, monkeypatch):
        monkeypatch.setenv("GR_ADMIN_TOKEN", "dev-admin-token")
        reg = Registry(new_db(), FixedClock())
        p1, k1 = reg.register_participant("Bank One")
        _, k2 = reg.register_participant("Bank Two")
        with TestClient(create_app(reg)) as c:
            r = c.post("/v1/signals/fraud-payees", headers={"X-Api-Key": k1},
                       json={"payee": MULE, "reason": "customer lost money", "evidence_ref": "C-9"})
            assert r.status_code == 201 and r.json()["status"] == "reported"
            st = c.get(f"/v1/signals/fraud-payees/{MULE}", headers={"X-Api-Key": k2}).json()
            assert st == {"payee": "mule.account@upi", "status": "reported", "reporting_banks": 1}
            assert "Bank One" not in str(st)
            wl = c.get("/v1/admin/watchlist", headers={"X-Admin-Token": "dev-admin-token"}).json()
            assert wl[0]["reports"][0]["name"] == "Bank One"           # operators see who and why
            r = c.post(f"/v1/admin/watchlist/{MULE}/clear", headers={"X-Admin-Token": "dev-admin-token"},
                       json={"reason": "verified merchant"})
            assert r.json()["status"] == "none"


def create_app(reg):
    from guardian_registry.api import create_app as make
    return make(reg, run_worker=False)


class TestCoachingPatterns:
    @pytest.fixture
    def signals_on(self, reg, family):
        reg.update_rules(family["amma"], {"scam_signals": True})
        return family

    def complete(self, reg, family, out):
        reg.report_outcome(family["bank"], out["check_id"], True)

    def test_off_by_default(self, reg, family):
        for i, p in enumerate(("a@upi", "b@upi", "c@upi")):
            assert pay(reg, family, 100, p, f"n{i}")["status"] == "allowed"

    def test_burst_of_new_payees(self, reg, signals_on):
        family = signals_on
        assert pay(reg, family, 100, "a@upi", "n1")["status"] == "allowed"
        assert pay(reg, family, 100, "b@upi", "n2")["status"] == "allowed"
        third = pay(reg, family, 100, "c@upi", "n3")
        assert third["status"] == "pending_approval" and "3 new payees in 24 hours" in third["reasons"]
        assert pay(reg, family, 100, "known@upi", "k1")["status"] == "allowed"     # known payees aren't counted

    def test_much_larger_than_usual(self, reg, signals_on):
        family = signals_on
        for i in range(3):
            self.complete(reg, family, pay(reg, family, 1_000, "known@upi", f"u{i}"))
        out = pay(reg, family, 6_000, "known@upi", "big")
        assert out["status"] == "pending_approval"
        assert any(r.startswith("much larger than this person's usual payments") for r in out["reasons"])

    def test_pending_loosening(self, reg, signals_on):
        family = signals_on
        reg.update_rules(family["amma"], {"daily_limit": 1_00_000 * R})          # held for 24 h
        out = pay(reg, family, 100, "known@upi", "p1")
        assert out["status"] == "pending_approval" and "a request to loosen protection is waiting" in out["reasons"]

    def test_night(self, reg, family):
        night = Registry(reg.db, FixedClock(datetime(2026, 11, 23, 20, 30, tzinfo=timezone.utc)))  # 02:00 IST
        night.update_rules(family["amma"], {"scam_signals": True})
        out = night.check(family["bank"], AMMA, "night", 6_000 * R, "known@upi")
        assert "a large payment at night (00:00 to 05:00)" in out["reasons"]

    def test_turning_it_off_is_held(self, reg, signals_on):
        out = reg.update_rules(signals_on["amma"], {"scam_signals": False})
        assert out["applied"] == {} and out["held"]["change"]["status"] == "pending"

    def test_guardian_reads_the_reasons_in_hindi(self, reg, signals_on):
        family = signals_on
        reg.set_language(family["ravi"], "hi")
        reg.update_rules(family["amma"], {"daily_limit": 1_00_000 * R})
        pay(reg, family, 100, "known@upi", "h1")
        body = reg.db.one("SELECT body FROM notifications WHERE recipient_id=? AND kind='approval_needed' "
                          "AND channel='inapp' ORDER BY created_at DESC", (family["ravi"],))["body"]
        assert "सुरक्षा ढीली करने का एक अनुरोध प्रतीक्षा में है" in body


def test_new_reasons_have_hindi():
    for reason in ("banks have confirmed fraud involving this payee", "a bank has reported fraud involving this payee",
                   "3 new payees in 24 hours", "a large payment at night (00:00 to 05:00)"):
        assert messages._value(reason, 2) != reason
