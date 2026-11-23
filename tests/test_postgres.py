"""Postgres backend: derived schema everywhere; multi-node behaviour when GR_TEST_DATABASE_URL is set."""

import threading
import uuid

import pytest

from guardian_registry.db import MIGRATIONS, Database, postgres_baseline
from guardian_registry.service import Registry

from .conftest import AMMA, PG_URL, R, RAVI

needs_pg = pytest.mark.skipif(not PG_URL, reason="set GR_TEST_DATABASE_URL to run against Postgres")


def test_baseline_has_every_table_in_dependency_order():
    ddl = postgres_baseline()
    import sqlite3
    mem = sqlite3.connect(":memory:")
    for m in MIGRATIONS:
        mem.executescript(m)
    tables = {r[0] for r in mem.execute("SELECT name FROM sqlite_master WHERE type='table' "
                                        "AND name NOT LIKE 'sqlite_%'")}
    for t in tables:
        assert f"CREATE TABLE IF NOT EXISTS {t} (" in ddl or f'CREATE TABLE IF NOT EXISTS "{t}" (' in ddl, t
    assert ddl.index('"users"') < ddl.index("TABLE IF NOT EXISTS sessions")  # referenced first
    assert "rowid BIGSERIAL" in ddl.split("TABLE IF NOT EXISTS notifications")[1].split(";")[0]
    assert "--" not in ddl


@pytest.fixture
def two_nodes(clock):
    """Two API nodes: separate connections, one shared Postgres schema."""
    schema = f"t_{uuid.uuid4().hex[:16]}"
    a, b = Database(PG_URL, schema=schema), Database(PG_URL, schema=schema)
    yield Registry(a, clock), Registry(b, clock)
    a.conn.drop_schema()
    a.close()
    b.close()


@needs_pg
class TestMultiNode:
    def test_nodes_see_each_others_writes(self, two_nodes):
        node_a, node_b = two_nodes
        amma, _ = node_a.register_user(AMMA, "Amma")
        assert node_b.user_by_mobile(AMMA) == amma
        assert node_b.verify_audit().ok

    def test_daily_limit_holds_under_concurrent_checks_on_two_nodes(self, two_nodes):
        node_a, node_b = two_nodes
        amma, _ = node_a.register_user(AMMA, "Amma")
        node_a.update_rules(amma, {"daily_limit": 60_000 * R})
        bank, _ = node_a.register_participant("Bank", "bank", "RBI-1")
        results, errors = [], []

        def pay(node, i):
            try:
                results.append(node.check(bank, AMMA, f"t{i}", 9_000 * R, "shop@upi")["status"])
            except Exception as e:  # noqa: BLE001
                errors.append(e)

        threads = [threading.Thread(target=pay, args=(node_a if i % 2 else node_b, i)) for i in range(16)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert not errors
        spent = node_a.db.one("SELECT COALESCE(SUM(amount),0) s FROM checks WHERE status IN "
                              "('allowed','cooling_off','pending_approval','approved')")["s"]
        assert spent <= 60_000 * R
        assert results.count("blocked") >= 16 - 6
        assert node_b.verify_audit().ok  # one unbroken hash chain across both nodes

    def test_same_retry_on_two_nodes_gives_one_check(self, two_nodes):
        node_a, node_b = two_nodes
        node_a.register_user(AMMA, "Amma")
        bank, _ = node_a.register_participant("Bank", "bank", "RBI-1")
        out = []
        threads = [threading.Thread(target=lambda n=n: out.append(n.check(bank, AMMA, "same", 100 * R, "x@upi")))
                   for n in (node_a, node_b, node_a, node_b)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert len({o["check_id"] for o in out}) == 1

    def test_schema_versions_out_of_range_are_refused(self, two_nodes):
        node_a, _ = two_nodes
        schema = node_a.db.conn.execute("SELECT current_schema() AS s").fetchone()["s"]
        node_a.db.conn.execute("UPDATE gr_schema SET version = 1")
        with pytest.raises(RuntimeError, match="predates portable migrations"):
            Database(PG_URL, schema=schema)
        node_a.db.conn.execute("UPDATE gr_schema SET version = 999")
        with pytest.raises(RuntimeError, match="newer than this code"):
            Database(PG_URL, schema=schema)

    def test_upgrade_from_v8_applies_portable_migrations(self, two_nodes):
        node_a, _ = two_nodes
        c = node_a.db.conn
        schema = c.execute("SELECT current_schema() AS s").fetchone()["s"]
        # make this database look like one created by v0.9.0 (schema v8): drop what v9+ added
        c.execute("DROP TABLE participant_certs")
        c.execute("DROP TABLE device_keys")
        c.execute("DROP TABLE auth_challenges")
        c.execute("ALTER TABLE sessions DROP COLUMN device_key_id")
        c.execute("UPDATE gr_schema SET version = 8")
        upgraded = Database(PG_URL, schema=schema)
        assert upgraded.one("SELECT version FROM gr_schema")["version"] == len(MIGRATIONS)
        assert upgraded.one("SELECT COUNT(*) n FROM device_keys")["n"] == 0
        upgraded.one("SELECT device_key_id FROM sessions LIMIT 1")
        upgraded.close()

    def test_privacy_dump_works(self, two_nodes):
        node_a, _ = two_nodes
        node_a.register_user(RAVI, "Ravi")
        dump = "\n".join(node_a.db.conn.iterdump())
        assert "users:" in dump and RAVI not in dump
