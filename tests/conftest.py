import pytest

from guardian_registry.clock import FixedClock
from guardian_registry.db import Database
from guardian_registry.service import Registry

R = 100  # paise per rupee

AMMA = "9876500001"
RAVI = "9876500002"   # son, guardian
PRIYA = "9876500003"  # daughter, guardian
STRANGER = "9876500009"


@pytest.fixture
def clock():
    return FixedClock()


@pytest.fixture
def reg(clock):
    return Registry(Database(), clock)


@pytest.fixture
def family(reg):
    """Amma is protected by Ravi (active) with typical rules; Priya is enrolled but not yet a guardian."""
    amma, _ = reg.register_user(AMMA, "Amma")
    ravi, _ = reg.register_user(RAVI, "Ravi")
    priya, _ = reg.register_user(PRIYA, "Priya")
    g = reg.invite_guardian(amma, RAVI)
    reg.respond_to_invite(ravi, g["id"], accept=True)
    reg.update_rules(amma, {
        "per_txn_limit": 50_000 * R,
        "daily_limit": 75_000 * R,
        "approval_threshold": 10_000 * R,
        "new_payee_delay_threshold": 5_000 * R,
        "cooling_off_minutes": 60,
        "approval_timeout_minutes": 30,
    })
    reg.vouch_payee(ravi, amma, "known@upi")
    bank, _ = reg.register_participant("Demo Bank")
    return {"amma": amma, "ravi": ravi, "priya": priya, "bank": bank, "ravi_link": g["id"]}
