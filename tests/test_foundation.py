import pytest

from guardian_registry.clock import FixedClock, ist_day
from guardian_registry.db import Database
from guardian_registry.models import Rules
from guardian_registry.security import mobile_hash, normalize_mobile


class TestMobile:
    @pytest.mark.parametrize("raw", ["9876543210", "+91 98765 43210", "09876543210", "91-9876543210"])
    def test_formats_normalize_to_same(self, raw):
        assert normalize_mobile(raw) == "+919876543210"
        assert mobile_hash(raw) == mobile_hash("9876543210")

    @pytest.mark.parametrize("bad", ["12345", "5876543210", "abc", "+1 415 555 0100"])
    def test_rejects_invalid(self, bad):
        with pytest.raises(ValueError):
            normalize_mobile(bad)

    def test_hash_hides_number(self):
        assert "9876543210" not in mobile_hash("9876543210")

    def test_pepper_changes_hash(self, monkeypatch):
        a = mobile_hash("9876543210")
        monkeypatch.setenv("GR_PEPPER", "other")
        assert mobile_hash("9876543210") != a


class TestClock:
    def test_ist_day_boundary(self):
        c = FixedClock()  # 04:30 UTC = 10:00 IST on 23 Nov
        assert ist_day(c.now()) == "2026-11-23"
        c.advance(hours=13, minutes=29)  # 17:59 UTC = 23:29 IST
        assert ist_day(c.now()) == "2026-11-23"
        c.advance(minutes=31)  # 18:30 UTC = 00:00 IST next day
        assert ist_day(c.now()) == "2026-11-24"


class TestRulesLoosening:
    base = Rules(per_txn_limit=50_000_00, daily_limit=1_00_000_00, approval_threshold=10_000_00,
                 new_payee_delay_threshold=5_000_00, cooling_off_minutes=60, blocked_channels=["rtgs"])

    def test_identical_is_not_loosening(self):
        assert not self.base.is_loosening(Rules.from_dict(self.base.to_dict()))

    @pytest.mark.parametrize("change", [
        {"per_txn_limit": 60_000_00}, {"per_txn_limit": None}, {"daily_limit": None},
        {"approval_threshold": 20_000_00}, {"new_payee_delay_threshold": None},
        {"cooling_off_minutes": 10}, {"approval_timeout_minutes": 120}, {"blocked_channels": []},
    ])
    def test_loosening_detected(self, change):
        new = Rules.from_dict({**self.base.to_dict(), **change})
        assert self.base.is_loosening(new)

    @pytest.mark.parametrize("change", [
        {"per_txn_limit": 40_000_00}, {"approval_threshold": 5_000_00},
        {"cooling_off_minutes": 120}, {"blocked_channels": ["rtgs", "neft"]}, {"kill_switch": True},
    ])
    def test_tightening_not_loosening(self, change):
        new = Rules.from_dict({**self.base.to_dict(), **change})
        assert not self.base.is_loosening(new)

    def test_kill_switch_off_is_loosening(self):
        on = Rules(kill_switch=True)
        assert on.is_loosening(Rules(kill_switch=False))

    def test_setting_limit_from_unlimited_is_tightening(self):
        assert not Rules().is_loosening(Rules(per_txn_limit=1000))


class TestDatabase:
    def test_schema_and_rollback(self):
        db = Database()
        with pytest.raises(RuntimeError):
            with db.tx() as c:
                c.execute("INSERT INTO participants VALUES ('p1','Bank','h','t')")
                raise RuntimeError("boom")
        assert db.one("SELECT COUNT(*) n FROM participants")["n"] == 0

    def test_nested_tx_commits_once(self):
        db = Database()
        with db.tx() as c:
            c.execute("INSERT INTO participants VALUES ('p1','Bank','h','t')")
            with db.tx() as c2:
                c2.execute("INSERT INTO participants VALUES ('p2','Bank2','h2','t')")
        assert db.one("SELECT COUNT(*) n FROM participants")["n"] == 2
