"""Per-person lock scopes and per-person audit chains."""

import json
import threading
import time
import uuid

import pytest

from guardian_registry import audit
from guardian_registry.db import Database, ScopeError

from .conftest import AMMA, PG_URL, R, RAVI, new_db


class TestScopes:
    def test_nested_tx_cannot_widen_scope(self):
        db = new_db()
        with db.tx("p1"):
            with db.tx("p1"):
                pass                      # same scope: fine
            with db.tx(shared=True):
                pass                      # narrower: fine
            with pytest.raises(ScopeError):
                with db.tx():             # global inside per-person: refused
                    pass
        with db.tx("p1"):
            with pytest.raises(ScopeError):
                with db.tx("p2"):
                    pass
        with db.tx():
            with db.tx("p1"), db.tx(shared=True):
                pass                      # anything inside a global tx

    def test_audit_only_for_locked_people(self, reg, family):
        with reg.db.tx(family["amma"]) as c:
            reg._audit(c, "x", "test.ok", family["amma"])
            with pytest.raises(ScopeError):
                reg._audit(c, "x", "test.bad", family["ravi"])
            with pytest.raises(ScopeError):
                reg._audit(c, "x", "test.bad", None)  # "system" stream needs a global tx
        with reg.db.tx(shared=True) as c:
            with pytest.raises(ScopeError):
                reg._audit(c, "x", "test.bad", family["amma"])

    def test_scope_resets_after_error(self):
        db = new_db()
        with pytest.raises(RuntimeError):
            with db.tx("p1"):
                raise RuntimeError("boom")
        with db.tx():             # would raise ScopeError if the old scope leaked
            pass

    def test_payment_paths_stay_in_scope(self, reg, family, clock):
        """The whole check/approve/outcome/sweep path for one person writes only that person."""
        bank = family["bank"]
        c1 = reg.check(bank, AMMA, "t1", 20_000 * R, "known@upi")
        reg.approve_check(family["ravi"], c1["check_id"])
        reg.report_outcome(bank, c1["check_id"], True)
        c2 = reg.check(bank, AMMA, "t2", 6_000 * R, "new@upi")       # cooling-off
        clock.advance(hours=2)
        reg.sweep()
        assert reg.get_check(bank, c2["check_id"])["status"] == "released"
        assert reg.verify_audit().ok


class TestStreams:
    def test_each_person_has_a_chain(self, reg, family):
        reg.check(family["bank"], AMMA, "t1", 100 * R, "known@upi")
        rows = reg.db.all("SELECT stream, stream_seq FROM audit_log ORDER BY seq")
        streams = {r["stream"] for r in rows}
        assert {family["amma"], family["ravi"], "system"} <= streams
        for s in streams:
            seqs = [r["stream_seq"] for r in rows if r["stream"] == s]
            assert seqs == list(range(1, len(seqs) + 1))
        v = reg.verify_audit()
        assert v.ok and v.streams == len(streams)

    def test_moving_an_entry_between_streams_is_detected(self, reg, family):
        row = reg.db.one("SELECT seq FROM audit_log WHERE stream=? ORDER BY stream_seq DESC LIMIT 1", (family["amma"],))
        reg.db.conn.execute("UPDATE audit_log SET principal_id=? WHERE seq=?", (family["ravi"], row["seq"]))
        v = reg.verify_audit()
        assert not v.ok and v.first_bad_seq == row["seq"]

    def test_head_changes_with_any_stream(self, reg, family):
        before = reg.verify_audit().head
        reg.check(family["bank"], AMMA, "t9", 100 * R, "known@upi")
        assert reg.verify_audit().head != before

    def test_entries_from_before_streams_still_verify(self):
        """Simulate a v10 database: legacy single-chain rows, then new stream rows."""
        db = new_db()
        prev = audit.GENESIS
        with db.tx() as c:
            for seq in (1, 2, 3):
                data = {"n": seq}
                h = audit._digest_legacy(prev, seq, "2026-01-01T00:00:00+00:00", "old", "legacy.event", None, data)
                c.execute("INSERT INTO audit_log (seq, ts, actor, action, principal_id, data, prev_hash, hash) "
                          "VALUES (?,?,?,?,?,?,?,?)", (seq, "2026-01-01T00:00:00+00:00", "old", "legacy.event",
                                                       None, json.dumps(data), prev, h))
                prev = h
            audit.append(c, "2026-11-23T00:00:00+00:00", "new", "new.event", "usr_1", {})
        with db.tx() as c:
            v = audit.verify(c)
        assert v.ok and v.entries == 4 and v.streams == 2
        db.conn.execute("UPDATE audit_log SET actor='forged' WHERE seq=2")
        with db.tx() as c:
            v = audit.verify(c)
        assert not v.ok and v.first_bad_seq == 2


# ------------------------------------------------------------------ Postgres: real parallelism
needs_pg = pytest.mark.skipif(not PG_URL, reason="set GR_TEST_DATABASE_URL to run against Postgres")


@needs_pg
class TestParallelOnPostgres:
    @pytest.fixture
    def nodes(self):
        schema = f"t_{uuid.uuid4().hex[:16]}"
        a, b = Database(PG_URL, schema=schema), Database(PG_URL, schema=schema)
        yield a, b
        a.conn.drop_schema()
        a.close()
        b.close()

    def _hold(self, db, keys, ready, release):
        with db.tx(*keys) as c:
            c.execute("INSERT INTO rate_counters (bucket, count, window_end) VALUES (?, 1, 0)", (f"hold-{keys}",))
            ready.set()
            release.wait(5)

    def test_different_people_write_in_parallel(self, nodes):
        a, b = nodes
        ready, release = threading.Event(), threading.Event()
        t = threading.Thread(target=self._hold, args=(a, ("p1",), ready, release))
        t.start()
        ready.wait(5)
        started = time.monotonic()
        with b.tx("p2") as c:  # must NOT wait for p1's open transaction
            c.execute("INSERT INTO rate_counters (bucket, count, window_end) VALUES ('p2', 1, 0)")
        assert time.monotonic() - started < 1.0
        release.set()
        t.join()

    def test_same_person_and_global_writes_wait(self, nodes):
        a, b = nodes
        for keys in (("p1",), ()):
            ready, release = threading.Event(), threading.Event()
            t = threading.Thread(target=self._hold, args=(a, ("p1",), ready, release))
            t.start()
            ready.wait(5)
            done = threading.Event()

            def write():
                with b.tx(*keys) as c:
                    c.execute("SELECT 1")
                done.set()

            w = threading.Thread(target=write)
            w.start()
            time.sleep(0.5)
            assert not done.is_set(), f"tx{keys} should wait for the open per-person transaction"
            release.set()
            t.join()
            w.join(5)
            assert done.is_set()

    def test_audit_seq_comes_from_a_sequence(self, nodes):
        a, b = nodes
        with a.tx("p1") as c1:
            audit.append(c1, "t", "x", "a", "p1", {})
        with b.tx("p2") as c2:
            audit.append(c2, "t", "x", "a", "p2", {})
        seqs = [r["seq"] for r in a.all("SELECT seq FROM audit_log ORDER BY seq")]
        assert len(seqs) == len(set(seqs)) == 2
