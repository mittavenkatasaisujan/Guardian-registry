import json

import httpx
import pytest

from guardian_registry.notify import BACKOFF_SECONDS, MAX_ATTEMPTS, Dispatcher, LogSmsSender
from guardian_registry.security import sign_webhook

from .conftest import AMMA, PRIYA, RAVI, R


@pytest.fixture
def sms():
    return LogSmsSender()


class Hook:
    """Fake bank webhook endpoint."""

    def __init__(self, status=200):
        self.status = status
        self.calls: list[httpx.Request] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.calls.append(request)
        return httpx.Response(self.status)


@pytest.fixture
def hook():
    return Hook()


@pytest.fixture
def dispatcher(reg, clock, sms, hook):
    return Dispatcher(reg.db, clock, sms=sms, http=httpx.Client(transport=httpx.MockTransport(hook)))


def kinds(reg, uid):
    return [n["kind"] for n in reg.notifications(uid)]


def pay(reg, f, rupees, payee="known@upi", txn=None):
    pay.n = getattr(pay, "n", 0) + 1
    return reg.check(f["bank"], AMMA, txn or f"n{pay.n}", rupees * R, payee)


class TestAlerts:
    def test_approval_needed_reaches_guardian_by_sms(self, reg, family, dispatcher, sms):
        c = pay(reg, family, 20_000)
        assert "approval_needed" in kinds(reg, family["ravi"])
        assert "payment_waiting" in kinds(reg, family["amma"])
        dispatcher.run_once()
        to, text = sms.sent[-1]
        assert to == "+91" + RAVI and "₹20,000.00" in text and "Amma" in text
        note = reg.notifications(family["ravi"])[0]
        assert note["data"]["check_id"] == c["check_id"]

    def test_inapp_only_events_send_no_sms(self, reg, family, dispatcher, sms):
        dispatcher.run_once()                  # drain the fixture's invite SMS
        before = len(sms.sent)
        pay(reg, family, 100)                  # allowed -> no alert
        assert dispatcher.run_once().sent == 0
        assert len(sms.sent) == before

    def test_cooling_off_alerts_guardian(self, reg, family):
        pay(reg, family, 6_000, payee="new@upi")
        assert "payment_held" in kinds(reg, family["ravi"])

    def test_blocked_alerts_principal_only(self, reg, family):
        pay(reg, family, 60_000)
        assert "payment_blocked" in kinds(reg, family["amma"])
        assert "payment_blocked" not in kinds(reg, family["ravi"])

    def test_loosening_alerts_guardians(self, reg, family, dispatcher, sms):
        reg.update_rules(family["amma"], {"per_txn_limit": None})
        assert "change_proposed" in kinds(reg, family["ravi"])
        assert "change_held" in kinds(reg, family["amma"])
        dispatcher.run_once()
        assert any("veto" in t for to, t in sms.sent if to == "+91" + RAVI)

    def test_removal_alerts_target_guardian_urgently(self, reg, family):
        g = reg.invite_guardian(family["amma"], PRIYA)
        reg.respond_to_invite(family["priya"], g["id"], accept=True)
        reg.remove_guardian(family["amma"], family["ravi_link"])
        assert "guardian_removal_proposed" in kinds(reg, family["ravi"])
        assert "change_proposed" not in kinds(reg, family["ravi"])
        assert "change_proposed" in kinds(reg, family["priya"])

    def test_invite_and_acceptance_alerts(self, reg, family):
        g = reg.invite_guardian(family["amma"], PRIYA)
        assert "guardian_invited" in kinds(reg, family["priya"])
        reg.respond_to_invite(family["priya"], g["id"], accept=True)
        assert "guardian_accepted" in kinds(reg, family["amma"])

    def test_kill_switch_alerts_everyone(self, reg, family):
        reg.engage_kill_switch(family["amma"], family["ravi"])
        assert "kill_switch_on" in kinds(reg, family["amma"])
        assert "kill_switch_on" in kinds(reg, family["ravi"])

    def test_decision_alerts(self, reg, family):
        c = pay(reg, family, 20_000)
        reg.deny_check(family["ravi"], c["check_id"])
        assert "payment_denied" in kinds(reg, family["amma"])

    def test_rolled_back_event_sends_nothing(self, reg, family):
        before = reg.db.one("SELECT COUNT(*) n FROM notifications")["n"]
        with pytest.raises(Exception):
            reg.invite_guardian(family["amma"], RAVI)  # duplicate -> Conflict
        assert reg.db.one("SELECT COUNT(*) n FROM notifications")["n"] == before

    def test_mark_read(self, reg, family):
        pay(reg, family, 20_000)
        assert reg.notifications(family["ravi"], unread_only=True)
        assert reg.mark_read(family["ravi"]) >= 1
        assert reg.notifications(family["ravi"], unread_only=True) == []

    def test_sms_never_contains_other_numbers(self, reg, family, dispatcher, sms):
        pay(reg, family, 20_000)
        dispatcher.run_once()
        for _, text in sms.sent:
            assert AMMA not in text


class TestSweeper:
    def test_sweep_releases_and_expires_without_reads(self, reg, family, clock):
        held = pay(reg, family, 6_000, payee="new@upi")
        pending = pay(reg, family, 20_000)
        clock.advance(minutes=61)
        out = reg.sweep()
        assert out["principals_refreshed"] == 1
        statuses = {r["id"]: r["status"] for r in reg.db.all("SELECT id, status FROM checks")}
        assert statuses[held["check_id"]] == "released"
        assert statuses[pending["check_id"]] == "expired"
        assert {"payment_released", "payment_expired"} <= set(kinds(reg, family["amma"]))

    def test_sweep_applies_due_changes(self, reg, family, clock):
        reg.update_rules(family["amma"], {"per_txn_limit": None})
        clock.advance(hours=24)
        assert reg.sweep()["principals_with_changes"] == 1
        row = reg.db.one("SELECT status FROM pending_changes")
        assert row["status"] == "applied"
        assert "change_applied" in kinds(reg, family["ravi"])

    def test_sweep_is_idempotent(self, reg, family, clock):
        pay(reg, family, 6_000, payee="new@upi")
        clock.advance(minutes=61)
        reg.sweep()
        assert reg.sweep() == {"principals_refreshed": 0, "principals_with_changes": 0}


class TestWebhooks:
    def test_no_webhook_means_no_rows(self, reg, family):
        c = pay(reg, family, 20_000)
        reg.approve_check(family["ravi"], c["check_id"])
        assert reg.db.one("SELECT COUNT(*) n FROM notifications WHERE channel='webhook'")["n"] == 0

    def test_signed_webhook_on_approval(self, reg, family, dispatcher, hook):
        secret = reg.set_webhook(family["bank"], "https://bank.example/hooks/gr")["webhook_secret"]
        c = pay(reg, family, 20_000)
        reg.approve_check(family["ravi"], c["check_id"])
        dispatcher.run_once()
        req = hook.calls[-1]
        assert str(req.url) == "https://bank.example/hooks/gr"
        assert req.headers["X-GR-Signature"] == sign_webhook(secret, req.content)
        body = json.loads(req.content)
        assert body["event"] == "check.updated"
        assert body["data"]["check"]["status"] == "approved" and body["data"]["check"]["may_execute"]
        assert "principal_id" not in body["data"]["check"]

    def test_webhook_on_release_via_sweep(self, reg, family, dispatcher, hook, clock):
        reg.set_webhook(family["bank"], "https://bank.example/h")
        pay(reg, family, 6_000, payee="new@upi")
        clock.advance(minutes=60)
        reg.sweep()
        dispatcher.run_once()
        assert json.loads(hook.calls[-1].content)["data"]["check"]["status"] == "released"

    def test_retry_with_backoff_then_fail(self, reg, family, clock, sms):
        failing = Hook(status=500)
        d = Dispatcher(reg.db, clock, sms=sms, http=httpx.Client(transport=httpx.MockTransport(failing)))
        reg.set_webhook(family["bank"], "https://bank.example/h")
        c = pay(reg, family, 20_000)
        reg.approve_check(family["ravi"], c["check_id"])
        d.run_once()
        row = reg.db.one("SELECT * FROM notifications WHERE channel='webhook'")
        assert row["status"] == "pending" and row["attempts"] == 1 and "HTTP 500" in row["last_error"]
        assert d.run_once().retried == 0                # not due yet
        for wait in BACKOFF_SECONDS:
            clock.advance(seconds=wait)
            d.run_once()
        row = reg.db.one("SELECT * FROM notifications WHERE channel='webhook'")
        assert row["status"] == "failed" and row["attempts"] == MAX_ATTEMPTS

    def test_webhook_url_validation(self, reg, family):
        with pytest.raises(Exception):
            reg.set_webhook(family["bank"], "ftp://x")
        assert reg.set_webhook(family["bank"], "http://localhost:9000/h")["webhook_url"]
        assert reg.set_webhook(family["bank"], None) == {"webhook_url": None, "webhook_secret": None}

    def test_http_not_allowed_in_production(self, reg, family, monkeypatch):
        monkeypatch.setenv("GR_ENV", "production")
        with pytest.raises(Exception):
            reg.set_webhook(family["bank"], "http://localhost:9000/h")


class TestSmsFallbacks:
    def test_user_without_number_is_skipped(self, reg, family, dispatcher):
        reg.db.conn.execute("UPDATE users SET mobile_enc=NULL WHERE id=?", (family["ravi"],))
        pay(reg, family, 20_000)
        stats = dispatcher.run_once()
        assert stats.skipped >= 1
