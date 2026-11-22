import pytest

from guardian_registry.errors import Conflict, Forbidden, Invalid, NotFound
from guardian_registry.service import LOOSENING_DELAY_HOURS, MAX_GUARDIANS

from .conftest import AMMA, PRIYA, RAVI, STRANGER, R

_txn = iter(range(1, 10_000))


def pay(reg, f, rupees, payee="known@upi", channel="upi", txn=None):
    return reg.check(f["bank"], AMMA, txn or f"t{next(_txn)}", round(rupees * R), payee, channel)


def complete(reg, f, rupees, payee):
    c = pay(reg, f, rupees, payee)
    assert c["may_execute"], c
    reg.report_outcome(f["bank"], c["check_id"], completed=True)
    return c


# --------------------------------------------------------------- enrolment
class TestEnrolment:
    def test_duplicate_mobile_rejected_in_any_format(self, reg):
        reg.register_user(AMMA, "Amma")
        with pytest.raises(Conflict):
            reg.register_user("+91 " + AMMA, "Someone")

    def test_invalid_mobile(self, reg):
        with pytest.raises(Invalid):
            reg.register_user("123", "X")

    def test_token_and_lookup(self, reg):
        uid, token = reg.register_user(AMMA, "Amma")
        assert reg.user_by_token(token) == uid
        assert reg.user_by_token("nope") is None
        assert reg.user_by_mobile("0" + AMMA) == uid

    def test_no_raw_mobile_stored(self, reg):
        reg.register_user(AMMA, "Amma")
        dump = "\n".join(reg.db.conn.iterdump())
        assert AMMA not in dump

    def test_participant_key(self, reg):
        pid, key = reg.register_participant("Bank A")
        assert reg.participant_by_key(key) == pid
        with pytest.raises(Conflict):
            reg.register_participant("Bank A")


# ---------------------------------------------------------------- consent
class TestGuardianConsent:
    def test_invite_is_not_active_until_accepted(self, reg, family):
        g = reg.invite_guardian(family["amma"], PRIYA)
        assert g["status"] == "invited"
        with pytest.raises(Forbidden):
            reg.engage_kill_switch(family["amma"], family["priya"])
        reg.respond_to_invite(family["priya"], g["id"], accept=True)
        reg.engage_kill_switch(family["amma"], family["priya"])

    def test_decline(self, reg, family):
        g = reg.invite_guardian(family["amma"], PRIYA)
        assert reg.respond_to_invite(family["priya"], g["id"], accept=False)["status"] == "declined"
        with pytest.raises(Conflict):
            reg.respond_to_invite(family["priya"], g["id"], accept=True)

    def test_only_invitee_can_respond(self, reg, family):
        g = reg.invite_guardian(family["amma"], PRIYA)
        with pytest.raises(NotFound):
            reg.respond_to_invite(family["ravi"], g["id"], accept=True)

    def test_invitee_must_be_enrolled(self, reg, family):
        with pytest.raises(NotFound):
            reg.invite_guardian(family["amma"], STRANGER)

    def test_no_self_or_duplicate(self, reg, family):
        with pytest.raises(Invalid):
            reg.invite_guardian(family["amma"], AMMA)
        with pytest.raises(Conflict):
            reg.invite_guardian(family["amma"], RAVI)

    def test_guardian_cap(self, reg, family):
        for i in range(MAX_GUARDIANS - 1):
            reg.register_user(f"98765111{i:02d}", f"G{i}")
            reg.invite_guardian(family["amma"], f"98765111{i:02d}")
        reg.register_user("9876511199", "Extra")
        with pytest.raises(Conflict):
            reg.invite_guardian(family["amma"], "9876511199")

    def test_guardian_can_resign_immediately(self, reg, family):
        assert reg.resign(family["ravi"], family["ravi_link"])["status"] == "ended"
        with pytest.raises(Forbidden):
            reg.engage_kill_switch(family["amma"], family["ravi"])

    def test_cancel_unaccepted_invite_is_immediate(self, reg, family):
        g = reg.invite_guardian(family["amma"], PRIYA)
        assert reg.remove_guardian(family["amma"], g["id"])["applied"] is True

    def test_wards_listing(self, reg, family):
        wards = reg.wards_of(family["ravi"])
        assert [w["principal_name"] for w in wards] == ["Amma"]


# ------------------------------------------------------------------ rules
class TestRuleChanges:
    def test_tightening_applies_now(self, reg, family):
        out = reg.update_rules(family["amma"], {"per_txn_limit": 20_000 * R})
        assert out["applied"] == {"per_txn_limit": 20_000 * R} and out["held"] is None
        assert reg.get_rules(family["amma"]).per_txn_limit == 20_000 * R

    def test_loosening_is_held_for_delay(self, reg, family, clock):
        out = reg.update_rules(family["amma"], {"approval_threshold": 40_000 * R})
        assert out["applied"] == {} and out["held"]["applied"] is False
        assert reg.get_rules(family["amma"]).approval_threshold == 10_000 * R
        clock.advance(hours=LOOSENING_DELAY_HOURS - 1)
        assert reg.get_rules(family["amma"]).approval_threshold == 10_000 * R
        clock.advance(hours=1)
        assert reg.get_rules(family["amma"]).approval_threshold == 40_000 * R

    def test_mixed_change_splits(self, reg, family):
        out = reg.update_rules(family["amma"], {"per_txn_limit": 30_000 * R, "daily_limit": None})
        assert out["applied"] == {"per_txn_limit": 30_000 * R}
        assert out["held"]["change"]["payload"] == {"changes": {"daily_limit": None}}

    def test_guardian_can_veto_loosening(self, reg, family, clock):
        cid = reg.update_rules(family["amma"], {"per_txn_limit": None})["held"]["change"]["id"]
        assert reg.veto_change(family["ravi"], cid)["status"] == "vetoed"
        clock.advance(hours=LOOSENING_DELAY_HOURS + 1)
        assert reg.get_rules(family["amma"]).per_txn_limit == 50_000 * R

    def test_guardian_can_approve_early(self, reg, family):
        cid = reg.update_rules(family["amma"], {"per_txn_limit": None})["held"]["change"]["id"]
        reg.approve_change(family["ravi"], cid)
        assert reg.get_rules(family["amma"]).per_txn_limit is None
        with pytest.raises(Conflict):
            reg.veto_change(family["ravi"], cid)

    def test_held_change_does_not_undo_later_tightening(self, reg, family, clock):
        reg.update_rules(family["amma"], {"daily_limit": None})            # held
        reg.update_rules(family["amma"], {"per_txn_limit": 1_000 * R})     # applied now
        clock.advance(hours=LOOSENING_DELAY_HOURS)
        r = reg.get_rules(family["amma"])
        assert r.daily_limit is None and r.per_txn_limit == 1_000 * R

    def test_validation(self, reg, family):
        for bad in ({"per_txn_limit": -5}, {"per_txn_limit": 1.5}, {"per_txn_limit": True},
                    {"blocked_channels": ["pigeon"]}, {"cooling_off_minutes": -1},
                    {"approval_timeout_minutes": 0}, {"nonsense": 1}, {"kill_switch": False}):
            with pytest.raises(Invalid):
                reg.update_rules(family["amma"], bad)

    def test_outsider_cannot_act(self, reg, family):
        with pytest.raises(Forbidden):
            reg.engage_kill_switch(family["amma"], family["priya"])
        cid = reg.update_rules(family["amma"], {"per_txn_limit": None})["held"]["change"]["id"]
        with pytest.raises(Forbidden):
            reg.approve_change(family["priya"], cid)


# ------------------------------------------------------------ kill switch
class TestKillSwitch:
    def test_principal_on_is_instant_off_is_held(self, reg, family, clock):
        reg.engage_kill_switch(family["amma"], family["amma"])
        assert pay(reg, family, 10)["outcome"] == "block"
        out = reg.release_kill_switch(family["amma"], family["amma"])
        assert out["applied"] is False
        assert pay(reg, family, 10)["outcome"] == "block"
        clock.advance(hours=LOOSENING_DELAY_HOURS)
        assert pay(reg, family, 10)["outcome"] == "allow"

    def test_guardian_can_switch_back_on_instantly(self, reg, family):
        reg.engage_kill_switch(family["amma"], family["ravi"])
        assert reg.release_kill_switch(family["amma"], family["ravi"])["applied"] is True
        assert pay(reg, family, 10)["outcome"] == "allow"

    def test_guardian_vetoes_principal_switch_off(self, reg, family, clock):
        reg.engage_kill_switch(family["amma"], family["ravi"])
        cid = reg.release_kill_switch(family["amma"], family["amma"])["change"]["id"]
        reg.veto_change(family["ravi"], cid)
        clock.advance(hours=LOOSENING_DELAY_HOURS * 2)
        assert reg.get_rules(family["amma"]).kill_switch is True


# --------------------------------------------------------- guardian removal
class TestGuardianRemoval:
    def test_removal_is_held(self, reg, family, clock):
        out = reg.remove_guardian(family["amma"], family["ravi_link"])
        assert out["applied"] is False
        reg.engage_kill_switch(family["amma"], family["ravi"])  # still active during hold
        clock.advance(hours=LOOSENING_DELAY_HOURS)
        reg.get_rules(family["amma"])
        assert reg.guardianship(family["ravi_link"])["status"] == "ended"

    def test_removed_guardian_cannot_veto_own_removal(self, reg, family):
        cid = reg.remove_guardian(family["amma"], family["ravi_link"])["change"]["id"]
        with pytest.raises(Forbidden):
            reg.veto_change(family["ravi"], cid)

    def test_other_guardian_can_veto_removal(self, reg, family, clock):
        g = reg.invite_guardian(family["amma"], PRIYA)
        reg.respond_to_invite(family["priya"], g["id"], accept=True)
        cid = reg.remove_guardian(family["amma"], family["ravi_link"])["change"]["id"]
        reg.veto_change(family["priya"], cid)
        clock.advance(hours=LOOSENING_DELAY_HOURS + 1)
        reg.get_rules(family["amma"])
        assert reg.guardianship(family["ravi_link"])["status"] == "active"


# ----------------------------------------------------------------- checks
class TestChecks:
    def test_not_enrolled(self, reg, family):
        out = reg.check(family["bank"], STRANGER, "x1", 999_999 * R, "a@upi")
        assert out == {"enrolled": False, "outcome": "allow", "may_execute": True,
                       "reasons": ["customer is not enrolled in the registry"]}

    def test_small_payment_allowed(self, reg, family):
        c = pay(reg, family, 500)
        assert c["outcome"] == "allow" and c["may_execute"] and "principal_id" not in c

    def test_idempotent(self, reg, family):
        a = pay(reg, family, 500, txn="same")
        b = pay(reg, family, 500, txn="same")
        assert a["check_id"] == b["check_id"]
        with pytest.raises(Conflict):
            pay(reg, family, 600, txn="same")

    def test_same_txn_id_different_banks_are_separate(self, reg, family):
        bank2, _ = reg.register_participant("Other App")
        a = pay(reg, family, 500, txn="dup")
        b = reg.check(bank2, AMMA, "dup", 500 * R, "known@upi")
        assert a["check_id"] != b["check_id"]

    def test_other_bank_cannot_read_check(self, reg, family):
        bank2, _ = reg.register_participant("Other App")
        c = pay(reg, family, 500)
        with pytest.raises(NotFound):
            reg.get_check(bank2, c["check_id"])

    def test_input_validation(self, reg, family):
        with pytest.raises(Invalid):
            reg.check(family["bank"], AMMA, "v1", 100, "a@upi", channel="pigeon")
        with pytest.raises(Invalid):
            reg.check(family["bank"], AMMA, "v2", 1.5, "a@upi")
        with pytest.raises(Invalid):
            reg.check(family["bank"], AMMA, " ", 100, "a@upi")
        with pytest.raises(Invalid):
            reg.check(family["bank"], "123", "v3", 100, "a@upi")


class TestDailyLimitAcrossBanks:
    def test_limit_is_shared_across_banks(self, reg, family):
        """The whole point: three banks, one daily limit."""
        bank2, _ = reg.register_participant("Second Bank")
        bank3, _ = reg.register_participant("UPI App")
        assert reg.check(family["bank"], AMMA, "a", 9_000 * R, "known@upi")["may_execute"]
        assert reg.check(bank2, AMMA, "b", 9_000 * R, "known@upi")["may_execute"]
        # simulate many small payments spread across banks
        for i in range(6):
            reg.check(bank3, AMMA, f"c{i}", 9_000 * R, "known@upi")
        # 8 x 9,000 = 72,000 spent; 4,000 more would cross 75,000
        out = reg.check(bank3, AMMA, "d", 4_000 * R, "known@upi")
        assert out["outcome"] == "block" and "daily limit" in out["reasons"][0]

    def test_failed_payment_frees_limit(self, reg, family):
        ids = [pay(reg, family, 9_000)["check_id"] for _ in range(8)]  # 72,000
        assert pay(reg, family, 4_000)["outcome"] == "block"
        reg.report_outcome(family["bank"], ids[0], completed=False)
        assert pay(reg, family, 4_000)["outcome"] == "allow"

    def test_limit_resets_at_ist_midnight(self, reg, family, clock):
        for _ in range(8):
            pay(reg, family, 9_000)
        assert pay(reg, family, 4_000)["outcome"] == "block"
        clock.advance(hours=14)  # 10:00 IST -> 00:00 IST next day
        assert pay(reg, family, 4_000)["outcome"] == "allow"

    def test_blocked_and_denied_do_not_count(self, reg, family):
        pay(reg, family, 60_000)  # blocked, over per-txn
        c = pay(reg, family, 20_000)
        reg.deny_check(family["ravi"], c["check_id"])
        for _ in range(8):
            assert pay(reg, family, 9_000)["outcome"] == "allow"


class TestCoolingOff:
    def test_new_payee_delay_then_release(self, reg, family, clock):
        c = pay(reg, family, 6_000, payee="new@upi")
        assert c["outcome"] == "delay" and c["status"] == "cooling_off" and not c["may_execute"]
        clock.advance(minutes=59)
        assert reg.get_check(family["bank"], c["check_id"])["status"] == "cooling_off"
        clock.advance(minutes=1)
        c2 = reg.get_check(family["bank"], c["check_id"])
        assert c2["status"] == "released" and c2["may_execute"]

    def test_cancel_during_cooling_off(self, reg, family, clock):
        c = pay(reg, family, 6_000, payee="scam@upi")
        reg.cancel_check(family["ravi"], c["check_id"])
        clock.advance(hours=2)
        assert reg.get_check(family["bank"], c["check_id"])["status"] == "cancelled"
        with pytest.raises(Conflict):
            reg.cancel_check(family["amma"], c["check_id"])

    def test_principal_can_cancel_own(self, reg, family):
        c = pay(reg, family, 6_000, payee="new2@upi")
        assert reg.cancel_check(family["amma"], c["check_id"])["status"] == "cancelled"

    def test_payee_becomes_known_after_completion(self, reg, family, clock):
        c = pay(reg, family, 6_000, payee="landlord@upi")
        clock.advance(minutes=60)
        reg.get_check(family["bank"], c["check_id"])
        reg.report_outcome(family["bank"], c["check_id"], completed=True)
        assert pay(reg, family, 6_000, payee="landlord@upi")["outcome"] == "allow"

    def test_guardian_vouched_payee_skips_delay(self, reg, family):
        reg.vouch_payee(family["ravi"], family["amma"], "Hospital@UPI")
        assert pay(reg, family, 6_000, payee="hospital@upi")["outcome"] == "allow"
        assert "hospital@upi" in reg.trusted_payees(family["amma"])

    def test_non_guardian_cannot_vouch(self, reg, family):
        with pytest.raises(Forbidden):
            reg.vouch_payee(family["priya"], family["amma"], "x@upi")
        with pytest.raises(Forbidden):
            reg.vouch_payee(family["amma"], family["amma"], "x@upi")

    def test_report_before_release_rejected(self, reg, family):
        c = pay(reg, family, 6_000, payee="new3@upi")
        with pytest.raises(Conflict):
            reg.report_outcome(family["bank"], c["check_id"], completed=True)


class TestApprovals:
    def test_approve(self, reg, family):
        c = pay(reg, family, 20_000)
        assert c["status"] == "pending_approval" and not c["may_execute"]
        reg.approve_check(family["ravi"], c["check_id"])
        out = reg.get_check(family["bank"], c["check_id"])
        assert out["status"] == "approved" and out["may_execute"]
        assert out["decided_by"] == family["ravi"]

    def test_deny(self, reg, family):
        c = pay(reg, family, 20_000)
        reg.deny_check(family["ravi"], c["check_id"])
        assert not reg.get_check(family["bank"], c["check_id"])["may_execute"]

    def test_principal_cannot_self_approve(self, reg, family):
        c = pay(reg, family, 20_000)
        with pytest.raises(Forbidden):
            reg.approve_check(family["amma"], c["check_id"])

    def test_expiry(self, reg, family, clock):
        c = pay(reg, family, 20_000)
        clock.advance(minutes=30)
        with pytest.raises(Conflict):
            reg.approve_check(family["ravi"], c["check_id"])
        assert reg.get_check(family["bank"], c["check_id"])["status"] == "expired"

    def test_no_double_decision(self, reg, family):
        c = pay(reg, family, 20_000)
        reg.approve_check(family["ravi"], c["check_id"])
        with pytest.raises(Conflict):
            reg.deny_check(family["ravi"], c["check_id"])

    def test_no_guardian_means_delay_not_lockout(self, reg, family):
        reg.resign(family["ravi"], family["ravi_link"])
        c = pay(reg, family, 20_000)
        assert c["outcome"] == "delay"

    def test_double_completion_rejected(self, reg, family):
        c = pay(reg, family, 100)
        reg.report_outcome(family["bank"], c["check_id"], completed=True)
        with pytest.raises(Conflict):
            reg.report_outcome(family["bank"], c["check_id"], completed=True)


class TestInboxAndHistory:
    def test_inbox(self, reg, family):
        pay(reg, family, 20_000)
        pay(reg, family, 6_000, payee="fresh@upi")
        reg.update_rules(family["amma"], {"daily_limit": None})
        g = reg.invite_guardian(family["amma"], PRIYA)
        box = reg.inbox(family["ravi"])
        assert {c["status"] for c in box["held_payments"]} == {"pending_approval", "cooling_off"}
        assert len(box["pending_changes"]) == 1
        assert reg.inbox(family["priya"])["invitations"][0]["id"] == g["id"]

    def test_history_access(self, reg, family):
        pay(reg, family, 100)
        assert len(reg.history(family["amma"], family["amma"])) == 1
        assert len(reg.history(family["ravi"], family["amma"])) == 1
        with pytest.raises(Forbidden):
            reg.history(family["priya"], family["amma"])
