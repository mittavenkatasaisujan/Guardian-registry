"""SQLite storage. One connection guarded by a lock; fine for a pilot-scale registry."""

from __future__ import annotations

import sqlite3
import threading
from contextlib import contextmanager

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id           TEXT PRIMARY KEY,
    mobile_hash  TEXT NOT NULL UNIQUE,
    display_name TEXT NOT NULL,
    token_hash   TEXT NOT NULL UNIQUE,
    created_at   TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS participants (
    id         TEXT PRIMARY KEY,
    name       TEXT NOT NULL UNIQUE,
    key_hash   TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS rules (
    principal_id TEXT PRIMARY KEY REFERENCES users(id),
    body         TEXT NOT NULL,          -- JSON of models.Rules
    updated_at   TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS guardianships (
    id           TEXT PRIMARY KEY,
    principal_id TEXT NOT NULL REFERENCES users(id),
    guardian_id  TEXT NOT NULL REFERENCES users(id),
    status       TEXT NOT NULL,
    invited_at   TEXT NOT NULL,
    accepted_at  TEXT,
    ended_at     TEXT
);
CREATE INDEX IF NOT EXISTS ix_g_principal ON guardianships(principal_id, status);
CREATE INDEX IF NOT EXISTS ix_g_guardian  ON guardianships(guardian_id, status);

CREATE TABLE IF NOT EXISTS trusted_payees (
    principal_id TEXT NOT NULL REFERENCES users(id),
    payee        TEXT NOT NULL,
    added_by     TEXT NOT NULL,
    added_at     TEXT NOT NULL,
    PRIMARY KEY (principal_id, payee)
);

CREATE TABLE IF NOT EXISTS checks (
    id                 TEXT PRIMARY KEY,
    principal_id       TEXT NOT NULL REFERENCES users(id),
    participant_id     TEXT NOT NULL REFERENCES participants(id),
    participant_txn_id TEXT NOT NULL,
    amount             INTEGER NOT NULL,
    payee              TEXT NOT NULL,
    channel            TEXT NOT NULL,
    outcome            TEXT NOT NULL,
    status             TEXT NOT NULL,
    reasons            TEXT NOT NULL,     -- JSON list
    day                TEXT NOT NULL,     -- IST date, for daily limits
    created_at         TEXT NOT NULL,
    release_at         TEXT,
    expires_at         TEXT,
    decided_by         TEXT,
    decided_at         TEXT,
    UNIQUE (participant_id, participant_txn_id)
);
CREATE INDEX IF NOT EXISTS ix_checks_day ON checks(principal_id, day);

CREATE TABLE IF NOT EXISTS pending_changes (
    id           TEXT PRIMARY KEY,
    principal_id TEXT NOT NULL REFERENCES users(id),
    kind         TEXT NOT NULL,
    payload      TEXT NOT NULL,           -- JSON
    status       TEXT NOT NULL,
    requested_by TEXT NOT NULL,
    created_at   TEXT NOT NULL,
    effective_at TEXT NOT NULL,
    decided_by   TEXT,
    decided_at   TEXT
);
CREATE INDEX IF NOT EXISTS ix_pc_principal ON pending_changes(principal_id, status);

CREATE TABLE IF NOT EXISTS audit_log (
    seq          INTEGER PRIMARY KEY,
    ts           TEXT NOT NULL,
    actor        TEXT NOT NULL,
    action       TEXT NOT NULL,
    principal_id TEXT,
    data         TEXT NOT NULL,           -- JSON
    prev_hash    TEXT NOT NULL,
    hash         TEXT NOT NULL
);
"""


class Database:
    def __init__(self, path: str = ":memory:"):
        self.conn = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys = ON")
        if path != ":memory:":
            self.conn.execute("PRAGMA journal_mode = WAL")
        self.conn.executescript(SCHEMA)
        self._lock = threading.RLock()
        self._depth = 0

    @contextmanager
    def tx(self):
        """Serialized, atomic unit of work. Nested calls join the outer transaction."""
        with self._lock:
            outer = self._depth == 0
            if outer:
                self.conn.execute("BEGIN IMMEDIATE")
            self._depth += 1
            try:
                yield self.conn
            except BaseException:
                self._depth -= 1
                if outer:
                    self.conn.execute("ROLLBACK")
                raise
            else:
                self._depth -= 1
                if outer:
                    self.conn.execute("COMMIT")

    def one(self, sql: str, params=()) -> sqlite3.Row | None:
        with self._lock:
            return self.conn.execute(sql, params).fetchone()

    def all(self, sql: str, params=()) -> list[sqlite3.Row]:
        with self._lock:
            return self.conn.execute(sql, params).fetchall()

    def close(self) -> None:
        self.conn.close()
