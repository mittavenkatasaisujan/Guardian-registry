import os
import uuid

import pytest

from guardian_registry.clock import FixedClock
from guardian_registry.db import Database
from guardian_registry.service import Registry

# Set GR_TEST_DATABASE_URL=postgresql://... to run every test on Postgres (each test gets
# its own schema, dropped afterwards). Unset: in-memory SQLite.
PG_URL = os.environ.get("GR_TEST_DATABASE_URL")
_OPEN: list[Database] = []


def new_db() -> Database:
    db = Database(PG_URL, schema=f"t_{uuid.uuid4().hex[:16]}") if PG_URL else Database()
    _OPEN.append(db)
    return db


@pytest.fixture(autouse=True)
def _close_databases():
    yield
    while _OPEN:
        db = _OPEN.pop()
        try:
            if db.backend == "postgres":
                db.conn.drop_schema()
            db.close()
        except Exception:  # noqa: BLE001 - cleanup must not hide the real failure
            pass

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
    return Registry(new_db(), clock)


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
