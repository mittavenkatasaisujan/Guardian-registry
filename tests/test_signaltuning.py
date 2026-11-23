"""Tuning the scam signals on outcomes: shadow features, labels, settings, the report."""

import json

import pytest
from fastapi.testclient import TestClient

from guardian_registry.errors import Conflict, Invalid, NotFound
from guardian_registry.scamsignals import DEFAULT_SETTINGS, MIN_LABELLED_FRAUD, signals_from

from .conftest import AMMA, R


def pay(reg, family, rupees, payee, txn):
    return reg.check(family["bank"], AMMA, txn, rupees * R, payee)


class TestShadowMode:
    def test_features_are_recorded_even_with_the_rule_off(self, reg, family):
        for i, p in enumerate(("a@upi", "b@upi", "c@upi")):
            out = pay(reg, family, 100, p, f"s{i}")
            assert out["status"] == "allowed"            # the rule is off: no effect on the decision
        row = reg.db.one("SELECT features, signals FROM checks WHERE participant_txn_id='s2'")
        f = json.loads(row["features"])
        assert f["new_payees_24h"] == 3 and f["new_payee"] is True and "local_hour" in f
        assert json.loads(row["signals"]) == ["payee_burst"]   # what WOULD have fired


class TestLabels:
    def test_bank_labels_its_own_checks_only(self, reg, family):
        out = pay(reg, family, 100, "a@upi", "l1")
        assert reg.label_check(family["bank"], out["check_id"], True, "customer complaint 123",
                               participant_id=family["bank"]) == {"check_id": out["check_id"], "label": "fraud"}
        other, _ = reg.register_participant("Other Bank")
        with pytest.raises(NotFound):
            reg.label_check(other, out["check_id"], False, participant_id=other)
        reg.label_check("operator:alice", out["check_id"], False)
        assert reg.db.one("SELECT fraud_label FROM checks WHERE id=?", (out["check_id"],))["fraud_label"] == "genuine"
        assert reg.verify_audit().ok


class TestSettings:
    def test_four_eyes_and_effect(self, reg, family):
        reg.update_rules(family["amma"], {"scam_signals": True})
        with pytest.raises(Invalid):
            reg.propose_signal_settings("alice", {"burst_count": 1}, "too low")
        with pytest.raises(Invalid):
            reg.propose_signal_settings("alice", {"nonsense": 1}, "x reason")
        view = reg.propose_signal_settings("alice", {"burst_count": 2}, "tuning report 2026-11")
        assert view["pending"]["settings"]["burst_count"] == 2 and view["active"]["burst_count"] == 3
        with pytest.raises(Conflict, match="second operator"):
            reg.decide_signal_settings("alice", True)
        assert reg.decide_signal_settings("bob", True)["active"]["burst_count"] == 2
        assert pay(reg, family, 100, "a@upi", "t1")["status"] == "allowed"
        second = pay(reg, family, 100, "b@upi", "t2")
        assert second["status"] == "pending_approval" and "2 new payees in 24 hours" in second["reasons"]
        assert reg.verify_audit().ok

    def test_reject(self, reg):
        reg.propose_signal_settings("alice", {"large_multiple": 2.5}, "try it")
        assert reg.decide_signal_settings("bob", False)["pending"] is None
        assert reg.active_signal_settings()["large_multiple"] == DEFAULT_SETTINGS["large_multiple"]
        with pytest.raises(Conflict):
            reg.decide_signal_settings("bob", True)


def _seed(reg, family, genuine=200, fraud=25, fraud_ratio=2.6):
    """Synthetic outcomes: fraud sits at 2.6x the usual largest payment, just under the 3x default."""
    rows = []
    base = {"prior_count": 5, "largest_prior": 10_000 * R, "new_payee": False, "new_payees_24h": 0,
            "loosen_pending": False, "local_hour": 14}
    for i in range(genuine):
        amt = 9_000 * R
        rows.append((f"g{i}", amt, {**base, "amount": amt, "ratio": 0.9}, "genuine", "allowed"))
    for i in range(fraud):
        amt = int(fraud_ratio * 10_000 * R)
        rows.append((f"f{i}", amt, {**base, "amount": amt, "ratio": fraud_ratio}, "fraud", "allowed"))
    now = reg._now()
    for txn, amt, feats, label, status in rows:
        reg.db.conn.execute(
            "INSERT INTO checks (id, principal_id, participant_id, participant_txn_id, amount, payee, channel, outcome, "
            "status, reasons, day, created_at, features, signals, fraud_label, completed_at) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (f"chk_{txn}", family["amma"], family["bank"], txn, amt, "x@upi", "upi", "allow", status, "[]",
             now[:10], now, json.dumps(feats), "[]", label, now))


class TestReport:
    def test_finds_a_better_threshold(self, reg, family):
        _seed(reg, family)
        rep = reg.tuning_report(days=30, max_hold_rate=0.2)
        assert rep["confirmed_fraud"] == 25 and rep["enough_data"]
        assert rep["per_signal"]["much_larger"]["recall"] == 0          # 3x misses every fraud here
        grid = {x["value"]: x for x in rep["what_if"]["large_multiple"]}
        assert grid[2.5]["recall"] == 1.0 and grid[2.5]["precision"] == 1.0
        sug = [s for s in rep["suggestions"] if s["setting"] == "large_multiple"]
        assert sug and sug[0]["to"] in (2.0, 2.5) and sug[0]["from"] == 3.0
        assert rep["impact"]["confirmed_fraud_that_went_through"] == 25

    def test_hold_budget_is_respected(self, reg, family):
        _seed(reg, family)
        rep = reg.tuning_report(days=30, max_hold_rate=0.05)               # catching all 25 = 11% held
        assert not [s for s in rep["suggestions"] if s["setting"] == "large_multiple"]

    def test_not_enough_labels(self, reg, family):
        _seed(reg, family, fraud=MIN_LABELLED_FRAUD - 1)
        rep = reg.tuning_report()
        assert not rep["enough_data"] and rep["suggestions"] == [] and "at least" in rep["note"]


def test_signals_from_matches_the_defaults():
    f = {"amount": 30_000 * R, "prior_count": 3, "largest_prior": 10_000 * R, "new_payee": True,
         "new_payees_24h": 3, "loosen_pending": True, "local_hour": 2}
    assert [c for c, _ in signals_from(f, DEFAULT_SETTINGS)] == ["much_larger", "payee_burst", "loosen_pending", "night"]


def test_api(monkeypatch):
    from guardian_registry.api import create_app
    from guardian_registry.clock import FixedClock
    from guardian_registry.service import Registry

    from .conftest import new_db
    monkeypatch.setenv("GR_OPERATORS", "alice:tok-alice-123456,bob:tok-bob-1234567")
    reg = Registry(new_db(), FixedClock())
    reg.register_user(AMMA, "Amma")
    pid, key = reg.register_participant("Bank")
    a, b = {"X-Admin-Token": "tok-alice-123456"}, {"X-Admin-Token": "tok-bob-1234567"}
    with TestClient(create_app(reg, run_worker=False)) as c:
        chk = c.post("/v1/checks", headers={"X-Api-Key": key}, json={
            "mobile": AMMA, "participant_txn_id": "x1", "amount": 100 * R, "payee": "a@upi"}).json()
        r = c.post(f"/v1/checks/{chk['check_id']}/fraud-label", headers={"X-Api-Key": key}, json={"fraud": True})
        assert r.json()["label"] == "fraud"
        r = c.put("/v1/admin/signals/settings", headers=a, json={"burst_count": 4, "reason": "after report"})
        assert r.json()["pending"]["settings"]["burst_count"] == 4
        assert c.post("/v1/admin/signals/settings/approve", headers=a).status_code == 409
        assert c.post("/v1/admin/signals/settings/approve", headers=b).json()["active"]["burst_count"] == 4
        rep = c.get("/v1/admin/signals/report?days=30", headers=b).json()
        assert rep["labelled"] == 1 and rep["settings"]["burst_count"] == 4
