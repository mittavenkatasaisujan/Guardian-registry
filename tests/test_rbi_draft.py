"""RBI draft directions, Nov 2026: the trusted person mechanism and customer-induced controls."""

import pytest

from guardian_registry.errors import Forbidden, Invalid
from guardian_registry.models import Outcome, Rules, Transaction
from guardian_registry.policy import evaluate
from guardian_registry.presets import PRESETS

from .conftest import AMMA, PRIYA, R

RBI = Rules(approval_threshold=10_000 * R, approval_scope="rbi")


def ev(rules, amount_rs, channel="imps", kind="transfer", **kw):
    return evaluate(rules, Transaction(amount=amount_rs * R, payee="x@bank", channel=channel, kind=kind),
                    spent_today=kw.pop("spent", 0), payee_known=True, has_active_guardian=True, **kw)


# ------------------------------------------------------------------ the rules engine
def test_rbi_scope_sends_only_non_upi_transfers_to_the_trusted_person():
    assert ev(RBI, 20_000, "imps").outcome is Outcome.NEEDS_APPROVAL
    assert ev(RBI, 20_000, "neft").outcome is Outcome.NEEDS_APPROVAL
    assert ev(RBI, 20_000, "upi").outcome is Outcome.ALLOW                         # UPI left out
    assert ev(RBI, 20_000, "card", kind="merchant").outcome is Outcome.ALLOW        # merchant payments left out
    assert ev(RBI, 20_000, "netbanking", kind="recurring").outcome is Outcome.ALLOW  # mandates left out
    every = Rules(approval_threshold=10_000 * R)                                     # this registry's default: all
    assert ev(every, 20_000, "upi").outcome is Outcome.NEEDS_APPROVAL


def test_stop_switch_lets_existing_recurring_mandates_run():
    paused = Rules(kill_switch=True)
    assert ev(paused, 500, kind="recurring").outcome is Outcome.ALLOW
    for kind in ("transfer", "merchant", "new_mandate"):
        assert ev(paused, 500, kind=kind).outcome is Outcome.BLOCK


def test_per_payee_and_per_channel_daily_limits():
    r = Rules(per_payee_daily_limit=20_000 * R, channel_daily_limits={"upi": 25_000 * R})
    assert ev(r, 15_000, spent_to_payee_today=5_000 * R).outcome is Outcome.ALLOW
    d = ev(r, 15_000, spent_to_payee_today=6_000 * R)
    assert d.outcome is Outcome.BLOCK and "₹20,000.00" in d.reasons[0] and "₹14,000.00 left" in d.reasons[0]
    assert ev(r, 10_000, "upi", spent_on_channel_today=15_000 * R).outcome is Outcome.ALLOW
    assert ev(r, 10_000, "upi", spent_on_channel_today=15_001 * R).outcome is Outcome.BLOCK
    assert ev(r, 10_000, "imps", spent_on_channel_today=99_000 * R).outcome is Outcome.ALLOW   # other channels unaffected


def test_loosening_the_new_rules_is_held():
    base = Rules(per_payee_daily_limit=20_000 * R, channel_daily_limits={"upi": 25_000 * R},
                 approval_scope="all", new_guardian_wait_hours=24)
    assert base.is_loosening(Rules(**{**base.to_dict(), "per_payee_daily_limit": None}))
    assert base.is_loosening(Rules(**{**base.to_dict(), "channel_daily_limits": {}}))
    assert base.is_loosening(Rules(**{**base.to_dict(), "approval_scope": "rbi"}))
    assert base.is_loosening(Rules(**{**base.to_dict(), "new_guardian_wait_hours": 0}))
    assert not base.is_loosening(Rules(**{**base.to_dict(), "per_payee_daily_limit": 10_000 * R}))


# ------------------------------------------------------------------ the registry
def test_rbi_preset_matches_the_draft(reg, family, clock):
    p = PRESETS["rbi_trusted_person"]["rules"]
    assert p["approval_timeout_minutes"] == 60 and p["new_guardian_wait_hours"] == 24 and p["approval_scope"] == "rbi"
    out = reg.apply_preset(family["amma"], "rbi_trusted_person")
    # fewer payments to the trusted person and a longer window are loosening: held 24 h, as the draft's
    # cooling period for any change also requires; the extra wait for new guardians applies at once
    assert out["held"] is not None and reg.get_rules(family["amma"]).new_guardian_wait_hours == 24
    clock.advance(hours=25)
    reg._apply_due_changes(family["amma"])
    rules = reg.get_rules(family["amma"])
    # UPI is outside the trusted person mechanism; a large IMPS transfer goes to Ravi, who has
    # been a guardian for more than the 24-hour wait by now
    bank = family["bank"]
    assert rules.approval_scope == "rbi"
    assert reg.check(bank, AMMA, "upi-big", 20_000 * R, "known@upi", "upi")["status"] == "allowed"
    held = reg.check(bank, AMMA, "imps-big", 20_000 * R, "known@upi", "imps")
    assert held["status"] == "pending_approval" and held["kind"] == "transfer"
    assert held["approval_expires_at"] > held["created_at"]


def test_a_new_guardian_approves_only_after_the_wait(reg, family, clock):
    reg.update_rules(family["amma"], {"new_guardian_wait_hours": 24})
    bank = family["bank"]
    clock.advance(hours=1)
    c = reg.check(bank, AMMA, "w1", 20_000 * R, "known@upi", "imps")
    assert c["status"] == "cooling_off"                       # Ravi accepted under an hour ago
    clock.advance(hours=24)
    c2 = reg.check(bank, AMMA, "w2", 20_000 * R, "known@upi", "imps")
    assert c2["status"] == "pending_approval"
    assert reg.approve_check(family["ravi"], c2["check_id"])["status"] == "approved"
    # a guardian added now waits again, even though Ravi can approve
    g = reg.invite_guardian(family["amma"], PRIYA)
    reg.respond_to_invite(family["priya"], g["id"], accept=True)
    c3 = reg.check(bank, AMMA, "w3", 20_000 * R, "known@upi", "imps")
    with pytest.raises(Forbidden, match="waiting period"):
        reg.approve_check(family["priya"], c3["check_id"])
    assert reg.approve_check(family["ravi"], c3["check_id"])["status"] == "approved"


def test_kind_is_validated_and_part_of_idempotency(reg, family):
    bank = family["bank"]
    with pytest.raises(Invalid, match="kind must be one of"):
        reg.check(bank, AMMA, "k1", 100 * R, "shop@upi", "upi", "gift")
    reg.check(bank, AMMA, "k2", 100 * R, "shop@upi", "upi", "merchant")
    assert reg.check(bank, AMMA, "k2", 100 * R, "shop@upi", "upi", "merchant")["kind"] == "merchant"
    with pytest.raises(Exception, match="already used for a different payment"):
        reg.check(bank, AMMA, "k2", 100 * R, "shop@upi", "upi", "transfer")


def test_rule_validation(reg, family):
    for bad in ({"approval_scope": "some"}, {"new_guardian_wait_hours": 500}, {"per_payee_daily_limit": 0},
                {"channel_daily_limits": {"fax": 100}}, {"channel_daily_limits": {"upi": -1}}):
        with pytest.raises(Invalid):
            reg.update_rules(family["amma"], bad)


# ------------------------------------------------------------------ quiet hours (chosen channels off during set hours)
NIGHT_UPI = Rules(quiet_hours={"channels": ["upi"], "start": 22, "end": 6})


def test_quiet_hours_switch_chosen_channels_off_across_midnight():
    for hour in (22, 23, 0, 5):
        d = ev(NIGHT_UPI, 100, "upi", local_hour=hour)
        assert d.outcome is Outcome.BLOCK and "from 22:00 to 06:00" in d.reasons[0]
    for hour in (6, 12, 21):
        assert ev(NIGHT_UPI, 100, "upi", local_hour=hour).outcome is Outcome.ALLOW
    assert ev(NIGHT_UPI, 100, "imps", local_hour=23).outcome is Outcome.ALLOW              # other channels run
    assert ev(NIGHT_UPI, 100, "upi", kind="recurring", local_hour=23).outcome is Outcome.ALLOW  # mandates run
    assert ev(NIGHT_UPI, 100, "upi").outcome is Outcome.ALLOW                               # no hour, no rule
    day = Rules(quiet_hours={"channels": ["card"], "start": 9, "end": 17})
    assert ev(day, 100, "card", local_hour=9).outcome is Outcome.BLOCK
    assert ev(day, 100, "card", local_hour=17).outcome is Outcome.ALLOW


def test_loosening_quiet_hours_is_held():
    q = NIGHT_UPI.quiet_hours
    def with_q(x):
        return Rules(quiet_hours=x)
    assert NIGHT_UPI.is_loosening(with_q(None))
    assert NIGHT_UPI.is_loosening(with_q({**q, "channels": ["imps"]}))           # UPI no longer off
    assert NIGHT_UPI.is_loosening(with_q({**q, "start": 23}))                     # an hour less
    assert not NIGHT_UPI.is_loosening(with_q({**q, "channels": ["upi", "imps"]}))
    assert not NIGHT_UPI.is_loosening(with_q({**q, "start": 21, "end": 7}))       # longer is stricter
    assert not Rules().is_loosening(NIGHT_UPI)


def test_quiet_hours_in_the_registry(reg, family, clock):
    # the test clock starts at 10:00 in India
    out = reg.update_rules(family["amma"], {"quiet_hours": {"channels": ["upi", "upi"], "start": 9, "end": 11}})
    assert out["held"] is None and reg.get_rules(family["amma"]).quiet_hours == {"channels": ["upi"], "start": 9, "end": 11}
    bank = family["bank"]
    blocked = reg.check(bank, AMMA, "q1", 100 * R, "known@upi", "upi")
    assert blocked["status"] == "blocked" and "from 09:00 to 11:00" in blocked["reasons"][0]
    assert reg.check(bank, AMMA, "q2", 100 * R, "known@upi", "imps")["status"] == "allowed"
    clock.advance(hours=1)
    assert reg.check(bank, AMMA, "q3", 100 * R, "known@upi", "upi")["status"] == "allowed"
    # switching it off is a loosening: held for 24 hours
    assert reg.update_rules(family["amma"], {"quiet_hours": None})["held"] is not None
    for bad in ({"channels": [], "start": 1, "end": 2}, {"channels": ["fax"], "start": 1, "end": 2},
                {"channels": ["upi"], "start": 5, "end": 5}, {"channels": ["upi"], "start": 24, "end": 2},
                {"channels": ["upi"], "start": 1}, "night"):
        with pytest.raises(Invalid, match="quiet_hours"):
            reg.update_rules(family["amma"], {"quiet_hours": bad})



# ------------------------------------------------------------------ narration: the trusted person sees the payment's note
def test_guardian_sees_the_narration(reg, family):
    bank = family["bank"]
    c = reg.check(bank, AMMA, "n1", 20_000 * R, "known@upi", "imps", narration="  Rent for\nNovember ")
    assert c["narration"] == "Rent for November"           # one line, trimmed
    held = reg.inbox(family["ravi"])["held_payments"]
    assert any(h["check_id"] == c["check_id"] and h["narration"] == "Rent for November" for h in held)
    assert reg.check(bank, AMMA, "n2", 100 * R, "x@upi")["narration"] is None
    with pytest.raises(Invalid, match="140"):
        reg.check(bank, AMMA, "n3", 100 * R, "x@upi", narration="x" * 141)


def test_erasure_removes_narrations(reg, family, clock):
    bank = family["bank"]
    reg.check(bank, AMMA, "n4", 100 * R, "x@upi", narration="for Kumar's fees")
    reg.request_erasure(family["amma"])
    clock.advance(days=8)
    reg.sweep_erasure()
    assert reg.db.one("SELECT COUNT(*) n FROM checks WHERE narration IS NOT NULL")["n"] == 0
