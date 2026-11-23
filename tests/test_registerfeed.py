"""Automatic refresh of the official registers."""

import base64
import json

import httpx
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from guardian_registry.errors import Conflict, Invalid
from guardian_registry.registerfeed import FeedError, parse_feed

URL = "https://lists.example.in/rbi-banks.csv"


def csv_of(n, skip=()):
    rows = ["licence,bank_name"] + [f"RBI-{i:03d},Bank {i}" for i in range(n) if i not in skip]
    return ("\n".join(rows) + "\n").encode()


class Site:
    """A fake web server for the list (and its .sig)."""

    def __init__(self):
        self.files, self.gets = {}, 0

    def __call__(self, request):
        self.gets += 1
        body = self.files.get(str(request.url))
        if body is None:
            return httpx.Response(404)
        return httpx.Response(200, content=body)


@pytest.fixture
def site(reg):
    s = Site()
    reg.feed_http = httpx.Client(transport=httpx.MockTransport(s))
    return s


def feed(reg, site, body=None, **kw):
    site.files[URL] = body if body is not None else csv_of(40)
    reg.configure_feed("alice", "bank", URL, "csv", "licence", "bank_name", **kw)
    return reg.approve_feed("bob", "bank")


def test_parse_formats():
    ents, as_of = parse_feed(json.dumps({"as_of": "2026-11-01", "entities": [
        {"ref": "A", "n": "Alpha"}, {"ref": "A", "n": "dup"}, {"ref": "B", "n": "Beta"}]}).encode(), "json", "ref", "n")
    assert ents == [{"regulator_ref": "A", "name": "Alpha"}, {"regulator_ref": "B", "name": "Beta"}]
    assert as_of == "2026-11-01"
    assert len(parse_feed(b"\xef\xbb\xbflicence,bank_name\nX,Y\n,\n", "csv", "licence", "bank_name")[0]) == 1
    with pytest.raises(FeedError, match="row 2 has a reference but no name"):
        parse_feed(b"licence,bank_name\nX,\n", "csv", "licence", "bank_name")


class TestConfig:
    def test_needs_a_second_operator(self, reg, site):
        site.files[URL] = csv_of(3)
        reg.configure_feed("alice", "bank", URL, "csv", "licence", "bank_name")
        with pytest.raises(Conflict, match="second operator"):
            reg.approve_feed("alice", "bank")
        assert reg.refresh_registers() == {}  # pending feeds are never fetched
        assert site.gets == 0

    def test_validation(self, reg):
        with pytest.raises(Invalid, match="https"):
            reg.configure_feed("alice", "bank", "http://lists.example.in/x.csv")
        with pytest.raises(Invalid, match="kind"):
            reg.configure_feed("alice", "casino", URL)
        with pytest.raises(Invalid, match="Ed25519"):
            reg.configure_feed("alice", "bank", URL, public_key="bm90LWEta2V5")

    def test_changing_a_feed_needs_approval_again(self, reg, site):
        feed(reg, site)
        reg.configure_feed("mallory", "bank", "https://evil.example/list.csv", "csv", "licence", "bank_name")
        assert reg.feed_view("bank")["status"] == "pending"
        assert reg.refresh_registers(force=True) == {}


class TestRefresh:
    def test_first_load_and_unchanged(self, reg, site, clock):
        feed(reg, site)
        assert reg.refresh_registers() == {"bank": "updated"}
        assert reg.register_status()[0]["entities"] == 40
        assert reg.refresh_registers() == {}  # not due yet
        clock.advance(hours=25)
        assert reg.refresh_registers() == {"bank": "unchanged"}
        assert reg.verify_audit().ok

    def test_runs_from_the_sweep(self, reg, site):
        feed(reg, site)
        assert reg.sweep()["registers"] == {"bank": "updated"}

    def test_removed_licence_suspends_the_participant(self, reg, site, clock):
        feed(reg, site)
        reg.refresh_registers()
        gone, _ = reg.register_participant("Bank 7", "bank", "RBI-007")
        kept, _ = reg.register_participant("Bank 8", "bank", "RBI-008")
        reg.db.conn.execute("UPDATE participants SET webhook_url='https://bank7.example/hook' WHERE id=?", (gone,))
        site.files[URL] = csv_of(40, skip={7})
        clock.advance(hours=25)
        assert reg.refresh_registers() == {"bank": "updated"}
        v = reg.participant_view(gone)
        assert v["status"] == "suspended" and "no longer on the official bank register" in v["status_reason"]
        assert reg.participant_view(kept)["status"] == "active"
        hook = reg.db.one("SELECT 1 FROM notifications WHERE recipient_id=? AND kind='participant.updated' "
                          "AND payload LIKE ?", (gone, "%suspended%"))
        assert hook
        assert reg.verify_audit().ok

    def test_auto_suspend_off(self, reg, site, clock):
        feed(reg, site, auto_suspend=False)
        reg.refresh_registers()
        pid, _ = reg.register_participant("Bank 7", "bank", "RBI-007")
        site.files[URL] = csv_of(40, skip={7})
        clock.advance(hours=25)
        reg.refresh_registers()
        assert reg.participant_view(pid)["status"] == "active"

    def test_truncated_download_is_held(self, reg, site, clock):
        feed(reg, site)
        reg.refresh_registers()
        pid, _ = reg.register_participant("Bank 30", "bank", "RBI-030")
        site.files[URL] = csv_of(20)  # half the list vanished: a broken export, not 20 closures
        clock.advance(hours=25)
        assert reg.refresh_registers() == {"bank": "held"}
        assert reg.register_status()[0]["entities"] == 40
        held = reg.feed_view("bank")["held"]
        assert held["removes"][:2] == ["RBI-020", "RBI-021"] and "more than 5%" in held["reason"]
        assert reg.participant_view(pid)["status"] == "active"
        # an operator looks and decides it's real
        out = reg.apply_held_feed("alice", "bank")
        assert out["entities"] == 20 and out["suspended"] == [pid]
        assert reg.feed_view("bank")["held"] is None

    def test_discarded_file_is_not_held_again(self, reg, site, clock):
        feed(reg, site)
        reg.refresh_registers()
        site.files[URL] = csv_of(1)
        clock.advance(hours=25)
        assert reg.refresh_registers() == {"bank": "held"}
        reg.discard_held_feed("alice", "bank")
        clock.advance(hours=25)
        assert reg.refresh_registers() == {"bank": "unchanged"}
        assert reg.register_status()[0]["entities"] == 40

    def test_empty_list_is_held_and_cannot_be_applied(self, reg, site, clock):
        feed(reg, site)
        reg.refresh_registers()
        site.files[URL] = b"licence,bank_name\n"
        clock.advance(hours=25)
        assert reg.refresh_registers() == {"bank": "held"}
        with pytest.raises(Conflict, match="empty"):
            reg.apply_held_feed("alice", "bank")

    def test_download_errors_are_recorded(self, reg, site, clock):
        feed(reg, site)
        del site.files[URL]
        assert reg.refresh_registers() == {"bank": "error"}
        assert "HTTP 404" in reg.feed_view("bank")["last_error"]


class TestSigned:
    @pytest.fixture
    def key(self):
        k = Ed25519PrivateKey.generate()
        pub = k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        return k, base64.b64encode(pub).decode()

    def test_good_signature(self, reg, site, key):
        k, pub = key
        body = csv_of(5)
        site.files[URL + ".sig"] = base64.b64encode(k.sign(body))
        feed(reg, site, body, public_key=pub)
        assert reg.refresh_registers() == {"bank": "updated"}

    def test_bad_or_missing_signature(self, reg, site, key):
        k, pub = key
        body = csv_of(5)
        site.files[URL + ".sig"] = base64.b64encode(k.sign(b"something else"))
        feed(reg, site, body, public_key=pub)
        assert reg.refresh_registers() == {"bank": "error"}
        assert "signature does not verify" in reg.feed_view("bank")["last_error"]
        del site.files[URL + ".sig"]
        assert reg.refresh_registers(force=True) == {"bank": "error"}
        assert "never used unsigned" in reg.feed_view("bank")["last_error"]
        assert reg.register_status() == []


def test_admin_api(site, monkeypatch, tmp_path):
    from fastapi.testclient import TestClient

    from guardian_registry.api import create_app
    from guardian_registry.clock import FixedClock
    from guardian_registry.service import Registry

    from .conftest import new_db
    monkeypatch.setenv("GR_OPERATORS", "alice:tok-a,bob:tok-b")
    reg = Registry(new_db(), FixedClock())
    reg.feed_http = httpx.Client(transport=httpx.MockTransport(site))
    site.files[URL] = csv_of(4)
    with TestClient(create_app(reg, run_worker=False)) as c:
        a, b = {"X-Admin-Token": "tok-a"}, {"X-Admin-Token": "tok-b"}
        r = c.put("/v1/admin/register-feeds/bank", headers=a,
                  json={"url": URL, "ref_field": "licence", "name_field": "bank_name"})
        assert r.status_code == 200 and r.json()["status"] == "pending"
        assert c.post("/v1/admin/register-feeds/bank/approve", headers=a).status_code == 409
        assert c.post("/v1/admin/register-feeds/bank/approve", headers=b).json()["status"] == "active"
        r = c.post("/v1/admin/register-feeds/bank/refresh", headers=a)
        assert r.json()["last_changed_at"] and c.get("/v1/admin/register", headers=a).json()[0]["entities"] == 4
        assert [f["kind"] for f in c.get("/v1/admin/register-feeds", headers=b).json()] == ["bank"]
