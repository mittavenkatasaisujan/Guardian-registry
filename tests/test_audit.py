import pytest

from guardian_registry.errors import Forbidden

from .conftest import AMMA, R


def _activity(reg, family):
    c = reg.check(family["bank"], AMMA, "a1", 20_000 * R, "x@upi")
    reg.approve_check(family["ravi"], c["check_id"])
    reg.engage_kill_switch(family["amma"], family["ravi"])


def test_chain_verifies(reg, family):
    _activity(reg, family)
    v = reg.verify_audit()
    assert v.ok and v.entries > 5 and v.first_bad_seq is None


def test_every_action_is_recorded(reg, family):
    _activity(reg, family)
    actions = [e["action"] for e in reg.audit_trail(family["amma"], family["amma"])]
    for expected in ("user.enrolled", "guardian.invited", "guardian.accepted", "rules.tightened",
                     "payee.vouched", "check.decided", "check.approved", "kill_switch.on"):
        assert expected in actions


def test_edit_is_detected(reg, family):
    _activity(reg, family)
    reg.db.conn.execute("UPDATE audit_log SET data='{\"amount\": 1}' WHERE action='check.decided'")
    bad = reg.db.one("SELECT seq FROM audit_log WHERE action='check.decided'")["seq"]
    v = reg.verify_audit()
    assert not v.ok and v.first_bad_seq == bad


def test_deletion_is_detected(reg, family):
    _activity(reg, family)
    reg.db.conn.execute("DELETE FROM audit_log WHERE action='check.approved'")
    assert not reg.verify_audit().ok


def test_rewriting_actor_is_detected(reg, family):
    _activity(reg, family)
    reg.db.conn.execute("UPDATE audit_log SET actor='someone_else' WHERE action='check.approved'")
    assert not reg.verify_audit().ok


def test_rolled_back_action_leaves_no_entry(reg, family):
    before = reg.verify_audit().entries
    with pytest.raises(Exception):
        reg.invite_guardian(family["amma"], "9876500002")  # already guardian -> Conflict
    assert reg.verify_audit().entries == before


def test_audit_trail_access(reg, family):
    with pytest.raises(Forbidden):
        reg.audit_trail(family["priya"], family["amma"])
    assert reg.audit_trail(family["ravi"], family["amma"])


def test_no_raw_mobile_in_audit(reg, family):
    _activity(reg, family)
    blob = " ".join(r["data"] for r in reg.db.all("SELECT data FROM audit_log"))
    assert AMMA not in blob
