"""Mobile-operator SIM feed: push events, number disconnection, live SIM-swap lookup."""

import re
from datetime import timedelta

import httpx
import pytest
from fastapi.testclient import TestClient

from guardian_registry.api import create_app
from guardian_registry.clock import FixedClock, iso
from guardian_registry.db import Database
from guardian_registry.errors import Forbidden, Invalid
from guardian_registry.notify import LogSmsSender
from guardian_registry.service import LOOSENING_DELAY_HOURS, OTP_RESEND_SECONDS, Registry
from guardian_registry.simfeed import (
    LOOKUP_CACHE_MINUTES, MAX_EVENTS_PER_BATCH, HttpSimLookup, SimLookup, SimLookupError,
)
from guardian_registry.simswap import SIM_SWAP_WINDOW_HOURS

from .conftest import AMMA, R, RAVI, STRANGER, new_db

NEW_NUMBER = "9876500077"


class FakeLookup(SimLookup):
    def __init__(self):
        self.changes: dict[str, object] = {}
        self.calls = 0
        self.down = False

    def latest_sim_change(self, mobile):
        self.calls += 1
        if self.down:
            raise SimLookupError("operator API down")
        return self.changes.get(mobile[-10:])


@pytest.fixture
def telco(reg):
    pid, _ = reg.register_participant("Telco", "telecom", "DOT-UL-1")
    return pid


def ev(event_id, etype, mobile, when):
    return {"event_id": event_id, "type": etype, "mobile": mobile, "occurred_at": iso(when)}


# ------------------------------------------------------------------ telecom kind
class TestTelecomKind:
    def test_telecom_capabilities(self, reg, telco):
        v = reg.participant_view(telco)
        assert v["capabilities"] == ["sim_signals", "number_lifecycle"]

    def test_telecom_cannot_check_or_vouch(self, reg, family, telco):
        with pytest.raises(Forbidden):
            reg.check(telco, AMMA, "t1", 100 * R, "known@upi")
        with pytest.raises(Forbidden):
            reg.attest(telco, AMMA, "full", "C", "2025-01-15")

    def test_banks_cannot_report_disconnections(self, reg, family, clock):
        out = reg.ingest_operator_events(family["bank"], [ev("e1", "disconnected", AMMA, clock.now())])
        assert out["results"][0]["result"] == "forbidden"
        assert reg.user_by_mobile(AMMA) == family["amma"]


# ------------------------------------------------------------------ push feed
class TestPushFeed:
    def test_sim_swap_opens_window(self, reg, family, telco, clock):
        out = reg.ingest_operator_events(telco, [ev("e1", "sim_swap", RAVI, clock.now())])
        assert out["counts"] == {"window_opened": 1}
        assert reg.sim_swap_active(family["ravi"])
        n = [n for n in reg.notifications(family["amma"]) if n["kind"] == "guardian_sim_changed"]
        assert n
        g = [n for n in reg.notifications(family["ravi"]) if n["kind"] == "sim_changed_self"]
        assert g

    def test_port_out_message(self, reg, family, telco, clock):
        reg.ingest_operator_events(telco, [ev("e1", "port_out", AMMA, clock.now())])
        msg = [n for n in reg.notifications(family["ravi"]) if n["kind"] == "sim_changed"][0]["body"]
        assert "another mobile operator" in msg

    def test_idempotent_on_event_id(self, reg, family, telco, clock):
        reg.ingest_operator_events(telco, [ev("e1", "sim_swap", RAVI, clock.now())])
        out = reg.ingest_operator_events(telco, [ev("e1", "sim_swap", RAVI, clock.now())])
        assert out["results"][0] == {"event_id": "e1", "result": "duplicate", "original_result": "window_opened"}
        assert reg.db.one("SELECT COUNT(*) n FROM sim_events")["n"] == 1

    def test_same_change_from_bank_and_operator_counted_once(self, reg, family, telco, clock):
        reg.report_sim_change(family["bank"], RAVI)
        out = reg.ingest_operator_events(telco, [ev("e1", "sim_swap", RAVI, clock.now() + timedelta(minutes=2))])
        assert out["results"][0]["result"] == "already_known"

    def test_mixed_batch_reports_each_event(self, reg, family, telco, clock):
        now = clock.now()
        out = reg.ingest_operator_events(telco, [
            ev("a", "sim_swap", RAVI, now),
            ev("b", "sim_swap", STRANGER, now),
            ev("c", "sim_swap", AMMA, now - timedelta(hours=SIM_SWAP_WINDOW_HOURS + 1)),
            {"event_id": "d", "type": "teleport", "mobile": AMMA, "occurred_at": iso(now)},
            ev("e", "sim_swap", "12345", now),
            ev("f", "sim_swap", AMMA, now + timedelta(hours=1)),
            {"type": "sim_swap", "mobile": AMMA, "occurred_at": iso(now)},
        ])
        assert [r["result"] for r in out["results"]] == [
            "window_opened", "not_enrolled", "stale", "invalid", "invalid", "invalid", "invalid"]
        # nothing about the unenrolled number is kept beyond the event id and outcome
        row = reg.db.one("SELECT * FROM operator_events WHERE event_id='b'")
        assert dict(row).keys() == {"participant_id", "event_id", "type", "occurred_at", "received_at", "outcome"}

    def test_batch_limits(self, reg, telco, clock):
        with pytest.raises(Invalid):
            reg.ingest_operator_events(telco, [])
        with pytest.raises(Invalid):
            reg.ingest_operator_events(telco, [ev(str(i), "sim_swap", AMMA, clock.now())
                                               for i in range(MAX_EVENTS_PER_BATCH + 1)])

    def test_pending_operator_cannot_send(self, reg, family, clock):
        pid, _ = reg.register_participant("T2", "telecom", "DOT-2", operator="alice", activate=False)
        with pytest.raises(Forbidden):
            reg.ingest_operator_events(pid, [ev("e1", "sim_swap", RAVI, clock.now())])


# ------------------------------------------------------------------ disconnection
class TestDisconnection:
    def test_recycled_number_gets_a_fresh_account(self, reg, family, telco, clock):
        bank = family["bank"]
        a = reg.attest(bank, RAVI, "full", "C-2", "2025-01-15")
        reg.respond_to_attestation(family["ravi"], a["attestation_id"], True)
        clock.advance(minutes=1)
        out = reg.ingest_operator_events(telco, [ev("d1", "disconnected", RAVI, clock.now())])
        assert out["results"][0]["result"] == "number_detached"
        assert reg.user_by_mobile(RAVI) is None
        assert reg.profile(family["ravi"])["number_status"] == "disconnected"
        assert reg.identity_level(family["ravi"]) == "otp"  # KYC vouched for the old number
        # someone new gets the number and signs in: a new, empty account
        new_uid, _ = reg.register_user(RAVI, "New Owner")
        assert new_uid != family["ravi"]
        assert reg.wards_of(new_uid) == []
        # Ravi's own (already signed-in) account still guards Amma
        assert family["ravi"] in reg._active_guardian_ids(family["amma"])

    def test_alerts(self, reg, family, telco, clock):
        reg.ingest_operator_events(telco, [ev("d1", "disconnected", RAVI, clock.now())])
        kinds = {n["kind"] for n in reg.notifications(family["amma"])}
        assert "guardian_number_disconnected" in kinds
        mine = [n for n in reg.notifications(family["ravi"]) if n["kind"] == "number_disconnected"][0]
        assert "Change number" in mine["body"] and RAVI not in mine["body"]  # masked

    def test_old_disconnection_does_not_hit_the_new_owner(self, reg, family, telco, clock):
        # the number was disconnected (and recycled) before Amma enrolled; the operator sends it late
        out = reg.ingest_operator_events(telco, [ev("d0", "disconnected", AMMA, clock.now() - timedelta(days=30))])
        assert out["results"][0]["result"] == "predates_enrolment"
        assert reg.user_by_mobile(AMMA) == family["amma"]

    def test_owner_can_add_new_number_from_signed_in_phone(self, reg, family, telco, clock):
        reg.ingest_operator_events(telco, [ev("d1", "disconnected", AMMA, clock.now())])
        sms = LogSmsSender()
        reg.request_mobile_change(family["amma"], NEW_NUMBER, sms)
        otp = re.search(r"(\d{6})", sms.sent[-1][1]).group(1)
        reg.confirm_mobile_change(family["amma"], NEW_NUMBER, otp)
        clock.advance(hours=LOOSENING_DELAY_HOURS, minutes=1)
        reg.sweep()
        assert reg.user_by_mobile(NEW_NUMBER) == family["amma"]
        assert reg.profile(family["amma"])["number_status"] == "active"
        # and a later disconnection of the OLD number no longer matters
        out = reg.ingest_operator_events(telco, [ev("d2", "disconnected", AMMA, clock.now())])
        assert out["results"][0]["result"] == "not_enrolled"


# ------------------------------------------------------------------ live lookup
@pytest.fixture
def lookup(reg):
    reg.sim_lookup = FakeLookup()
    return reg.sim_lookup


class TestLiveLookup:
    def test_recent_change_opens_window(self, reg, family, lookup, clock):
        lookup.changes[RAVI] = clock.now() - timedelta(hours=1)
        assert reg.refresh_sim_status(family["ravi"]) == {"checked": True, "opened": True, "unavailable": False}
        assert reg.sim_swap_active(family["ravi"])
        ev_ = reg.db.one("SELECT source FROM sim_events")
        assert ev_["source"] == "operator_lookup"

    def test_old_change_or_none_is_fine(self, reg, family, lookup, clock):
        lookup.changes[RAVI] = clock.now() - timedelta(hours=SIM_SWAP_WINDOW_HOURS + 1)
        assert reg.refresh_sim_status(family["ravi"])["opened"] is False
        assert reg.refresh_sim_status(family["amma"])["opened"] is False

    def test_cached(self, reg, family, lookup, clock):
        reg.refresh_sim_status(family["ravi"])
        reg.refresh_sim_status(family["ravi"])
        assert lookup.calls == 1
        clock.advance(minutes=LOOKUP_CACHE_MINUTES + 1)
        reg.refresh_sim_status(family["ravi"])
        assert lookup.calls == 2

    def test_confirmed_change_is_not_reopened(self, reg, family, lookup, clock):
        lookup.changes[RAVI] = clock.now() - timedelta(hours=1)
        reg.refresh_sim_status(family["ravi"])
        reg.confirm_sim_change(family["ravi"], family["ravi"])
        clock.advance(minutes=LOOKUP_CACHE_MINUTES + 1)
        assert reg.refresh_sim_status(family["ravi"])["opened"] is False
        assert not reg.sim_swap_active(family["ravi"])

    def test_outage_is_recorded_and_retried_soon(self, reg, family, lookup, clock):
        lookup.down = True
        assert reg.refresh_sim_status(family["ravi"])["unavailable"] is True
        assert reg.refresh_sim_status(family["ravi"])["unavailable"] is True  # cached failure
        assert lookup.calls == 1
        lookup.down = False
        clock.advance(minutes=2)
        assert reg.refresh_sim_status(family["ravi"])["unavailable"] is False

    def test_fail_closed_blocks_trust(self, reg, family, lookup, monkeypatch):
        lookup.down = True
        assert reg.lookup_blocks_trust(family["ravi"]) is False
        monkeypatch.setenv("GR_SIM_LOOKUP_FAIL", "closed")
        assert reg.lookup_blocks_trust(family["ravi"]) is True

    def test_off_by_default(self, reg, family):
        assert reg.refresh_sim_status(family["ravi"]) == {"checked": False, "opened": False, "unavailable": False}


class TestHttpLookup:
    def make(self, handler):
        return HttpSimLookup("https://op.example/sim-swap/retrieve-date", "tok",
                             client=httpx.Client(transport=httpx.MockTransport(handler)))

    def test_request_and_parse(self):
        seen = {}

        def handler(req):
            seen["body"], seen["auth"] = req.content, req.headers["authorization"]
            return httpx.Response(200, json={"latestSimChange": "2026-11-23T01:00:00Z"})
        when = self.make(handler).latest_sim_change(RAVI)
        assert when.isoformat() == "2026-11-23T01:00:00+00:00"
        assert seen["body"] == b'{"phoneNumber":"+919876500002"}' and seen["auth"] == "Bearer tok"

    @pytest.mark.parametrize("resp,expect", [
        (httpx.Response(200, json={"latestSimChange": None}), None),
        (httpx.Response(404), None),
    ])
    def test_no_info(self, resp, expect):
        assert self.make(lambda req: resp).latest_sim_change(RAVI) is expect

    @pytest.mark.parametrize("resp", [
        httpx.Response(500), httpx.Response(200, json={"latestSimChange": "yesterday"}),
        httpx.Response(200, json={"latestSimChange": "2026-11-23T01:00:00"}),
    ])
    def test_errors(self, resp):
        with pytest.raises(SimLookupError):
            self.make(lambda req: resp).latest_sim_change(RAVI)

    def test_network_error(self):
        def handler(req):
            raise httpx.ConnectError("boom")
        with pytest.raises(SimLookupError):
            self.make(handler).latest_sim_change(RAVI)


# ------------------------------------------------------------------ HTTP end to end
@pytest.fixture
def http():
    clock = FixedClock()
    sms = LogSmsSender()
    fake = FakeLookup()
    c = TestClient(create_app(Registry(new_db(), clock), admin_token="adm", sms=sms, run_worker=False,
                              sim_lookup=fake))

    def sign_in(mobile, name, device):
        c.post("/v1/auth/otp", json={"mobile": mobile})
        code = re.search(r"code: (\d{6})", sms.sent[-1][1]).group(1)
        return c.post("/v1/auth/verify", json={"mobile": mobile, "code": code, "display_name": name, "adult": True,
                                               "device_id": device}).json()

    amma, ravi = sign_in(AMMA, "Amma", "a-phone"), sign_in(RAVI, "Ravi", "r-phone")
    A, G = {"Authorization": f"Bearer {amma['token']}"}, {"Authorization": f"Bearer {ravi['token']}"}
    gid = c.post("/v1/me/guardians", json={"mobile": RAVI}, headers=A).json()["id"]
    c.post(f"/v1/guardian/invitations/{gid}/accept", headers=G)
    adm = {"X-Admin-Token": "adm"}
    bank = {"X-Api-Key": c.post("/v1/admin/participants", headers=adm,
                                json={"name": "B", "regulator_ref": "RBI-1"}).json()["api_key"]}
    telco = {"X-Api-Key": c.post("/v1/admin/participants", headers=adm,
                                 json={"name": "T", "kind": "telecom", "regulator_ref": "DOT-1"}).json()["api_key"]}
    c.patch("/v1/me/rules", headers=A, json={"approval_threshold": 10_000 * R})
    return {"c": c, "clock": clock, "fake": fake, "sign_in": sign_in, "A": A, "G": G, "bank": bank,
            "telco": telco, "amma": amma, "ravi": ravi}


class TestHttp:
    def test_sign_in_after_live_detected_swap_is_restricted(self, http):
        c, clock = http["c"], http["clock"]
        clock.advance(minutes=20)
        http["fake"].changes[RAVI] = clock.now() - timedelta(minutes=5)
        clock.advance(seconds=OTP_RESEND_SECONDS)
        thief = http["sign_in"](RAVI, "Ravi", "r-phone")  # even claiming Ravi's own device id
        assert thief["restricted"] is True
        chk = c.post("/v1/checks", headers=http["bank"], json={
            "mobile": AMMA, "participant_txn_id": "x", "amount": 40_000 * R, "payee": "mule@upi"}).json()
        r = c.post(f"/v1/guardian/payments/{chk['check_id']}/approve",
                   headers={"Authorization": f"Bearer {thief['token']}"})
        assert r.status_code == 403 and r.json()["error"] == "RestrictedSession"

    def test_trusted_action_triggers_lookup(self, http):
        c, clock = http["c"], http["clock"]
        chk = c.post("/v1/checks", headers=http["bank"], json={
            "mobile": AMMA, "participant_txn_id": "x", "amount": 40_000 * R, "payee": "mule@upi"}).json()
        # Ravi's own phone, signed in before the swap: still trusted after the lookup finds it
        clock.advance(minutes=LOOKUP_CACHE_MINUTES + 1)
        http["fake"].changes[RAVI] = clock.now() - timedelta(minutes=1)
        r = c.post(f"/v1/guardian/payments/{chk['check_id']}/approve", headers=http["G"])
        assert r.status_code == 200
        assert c.get("/v1/me/security", headers=http["G"]).json()["sim_swap_window_open"] is True

    def test_fail_closed(self, http, monkeypatch):
        c, clock = http["c"], http["clock"]
        monkeypatch.setenv("GR_SIM_LOOKUP_FAIL", "closed")
        clock.advance(minutes=LOOKUP_CACHE_MINUTES + 1)
        http["fake"].down = True
        r = c.post("/v1/me/kill-switch/off", headers=http["A"])
        assert r.status_code == 403 and "mobile operator" in r.json()["detail"]
        assert c.post("/v1/me/kill-switch/on", headers=http["A"]).status_code == 200  # protective: allowed

    def test_operator_push_endpoint(self, http):
        c, clock = http["c"], http["clock"]
        body = {"events": [{"event_id": "e1", "type": "disconnected", "mobile": RAVI, "occurred_at": iso(clock.now())},
                           {"event_id": "e2", "type": "sim_swap", "mobile": AMMA, "occurred_at": iso(clock.now())}]}
        out = c.post("/v1/signals/operator-events", headers=http["telco"], json=body).json()
        assert out["counts"] == {"number_detached": 1, "window_opened": 1}
        assert c.get("/v1/me", headers=http["G"]).json()["number_status"] == "disconnected"
        assert c.post("/v1/signals/operator-events", headers=http["telco"],
                      json={"events": [{**body["events"][0], "type": "bogus"}]}).status_code == 422
        assert c.post("/v1/checks", headers=http["telco"], json={
            "mobile": AMMA, "participant_txn_id": "y", "amount": 100, "payee": "a@upi"}).status_code == 403
