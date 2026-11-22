import pytest

from guardian_registry.models import Outcome, Rules, Transaction
from guardian_registry.policy import evaluate

R = 100  # paise per rupee

RULES = Rules(
    per_txn_limit=50_000 * R,
    daily_limit=75_000 * R,
    approval_threshold=10_000 * R,
    new_payee_delay_threshold=5_000 * R,
    cooling_off_minutes=60,
    approval_timeout_minutes=30,
    blocked_channels=["rtgs"],
)


def ev(amount_rs, *, rules=RULES, payee_known=True, spent_rs=0, guardian=True, channel="upi"):
    return evaluate(rules, Transaction(amount=round(amount_rs * R), payee="x@upi", channel=channel),
                    spent_today=round(spent_rs * R), payee_known=payee_known, has_active_guardian=guardian)


def test_no_rules_allows_everything():
    d = ev(10_00_000, rules=Rules())
    assert d.outcome is Outcome.ALLOW and d.reasons == []


def test_small_known_payee_allowed():
    assert ev(500).outcome is Outcome.ALLOW


@pytest.mark.parametrize("amount", [0, -1])
def test_non_positive_amount_blocked(amount):
    assert evaluate(RULES, Transaction(amount, "x"), spent_today=0, payee_known=True,
                    has_active_guardian=True).outcome is Outcome.BLOCK


def test_kill_switch_blocks_even_tiny_payments():
    d = ev(1, rules=Rules(kill_switch=True))
    assert d.outcome is Outcome.BLOCK and "kill switch" in d.reasons[0]


def test_blocked_channel():
    d = ev(100, channel="rtgs")
    assert d.outcome is Outcome.BLOCK and "rtgs" in d.reasons[0]


def test_per_txn_limit_is_inclusive_at_limit():
    assert ev(50_000, payee_known=True).outcome is Outcome.NEEDS_APPROVAL   # at limit: not blocked
    assert ev(50_000.01).outcome is Outcome.BLOCK                            # one paisa over


def test_daily_limit_counts_earlier_spend():
    assert ev(4_000, spent_rs=71_000).outcome is Outcome.ALLOW   # exactly 75,000
    d = ev(4_000.01, spent_rs=71_000)
    assert d.outcome is Outcome.BLOCK and "daily limit" in d.reasons[0]


def test_all_block_reasons_are_reported():
    d = ev(60_000, spent_rs=70_000, channel="rtgs", rules=Rules(**{**RULES.to_dict(), "kill_switch": True}))
    assert d.outcome is Outcome.BLOCK
    assert len(d.reasons) == 4


def test_approval_threshold_inclusive():
    assert ev(9_999.99).outcome is Outcome.ALLOW
    d = ev(10_000)
    assert d.outcome is Outcome.NEEDS_APPROVAL and d.approval_timeout_minutes == 30


def test_new_payee_delay():
    d = ev(5_000, payee_known=False)
    assert d.outcome is Outcome.DELAY and d.delay_minutes == 60
    assert ev(4_999, payee_known=False).outcome is Outcome.ALLOW
    assert ev(5_000, payee_known=True).outcome is Outcome.ALLOW


def test_approval_beats_delay_and_both_reasons_listed():
    d = ev(20_000, payee_known=False)
    assert d.outcome is Outcome.NEEDS_APPROVAL
    assert len(d.reasons) == 2


def test_no_guardian_falls_back_to_delay():
    d = ev(20_000, guardian=False)
    assert d.outcome is Outcome.DELAY
    assert any("no active guardian" in r for r in d.reasons)


def test_block_beats_approval():
    assert ev(60_000).outcome is Outcome.BLOCK


def test_reasons_show_rupees():
    d = ev(12_345.5)
    assert "₹12,345.50" in d.reasons[0]
