"""SQLite storage. One connection guarded by a lock; fine for a pilot-scale registry."""

from __future__ import annotations

import sqlite3
import threading
from contextlib import contextmanager

SCHEMA_V1 = """
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
    completed_at       TEXT,               -- bank confirmed money moved
    UNIQUE (participant_id, participant_txn_id)
);
CREATE INDEX IF NOT EXISTS ix_checks_day ON checks(principal_id, day);
CREATE INDEX IF NOT EXISTS ix_checks_payee ON checks(principal_id, payee);

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

# v2: OTP sign-in with expiring sessions (token moves off users), encrypted mobile for
# alerts, notification outbox, participant webhooks and key rotation.
SCHEMA_V2 = """
CREATE TABLE users_v2 (
    id           TEXT PRIMARY KEY,
    mobile_hash  TEXT NOT NULL UNIQUE,
    mobile_enc   TEXT,                    -- Fernet-encrypted, only for sending SMS
    display_name TEXT NOT NULL,
    created_at   TEXT NOT NULL
);
INSERT INTO users_v2 (id, mobile_hash, display_name, created_at)
    SELECT id, mobile_hash, display_name, created_at FROM users;

CREATE TABLE sessions (
    token_hash TEXT PRIMARY KEY,
    user_id    TEXT NOT NULL REFERENCES users(id),
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    revoked_at TEXT
);
INSERT INTO sessions (token_hash, user_id, created_at, expires_at)
    SELECT token_hash, id, created_at, '2099-01-01T00:00:00+00:00' FROM users;

DROP TABLE users;
ALTER TABLE users_v2 RENAME TO users;
CREATE INDEX ix_sessions_user ON sessions(user_id);

CREATE TABLE otps (
    mobile_hash  TEXT PRIMARY KEY,
    code_hash    TEXT NOT NULL,
    expires_at   TEXT NOT NULL,
    attempts     INTEGER NOT NULL DEFAULT 0,
    window_start TEXT NOT NULL,           -- for per-number send rate limit
    sends        INTEGER NOT NULL,
    last_sent_at TEXT NOT NULL
);

CREATE TABLE notifications (
    id              TEXT PRIMARY KEY,
    recipient_type  TEXT NOT NULL,        -- 'user' | 'participant'
    recipient_id    TEXT NOT NULL,
    principal_id    TEXT,
    kind            TEXT NOT NULL,
    channel         TEXT NOT NULL,        -- 'inapp' | 'sms' | 'webhook'
    title           TEXT NOT NULL,
    body            TEXT NOT NULL,
    payload         TEXT NOT NULL,        -- JSON
    status          TEXT NOT NULL,        -- 'pending' | 'sent' | 'failed' | 'skipped'
    attempts        INTEGER NOT NULL DEFAULT 0,
    next_attempt_at TEXT NOT NULL,
    last_error      TEXT,
    created_at      TEXT NOT NULL,
    sent_at         TEXT,
    read_at         TEXT
);
CREATE INDEX ix_notif_due ON notifications(status, next_attempt_at);
CREATE INDEX ix_notif_recipient ON notifications(recipient_type, recipient_id, created_at);

ALTER TABLE participants ADD COLUMN webhook_url TEXT;
ALTER TABLE participants ADD COLUMN webhook_secret TEXT;
ALTER TABLE participants ADD COLUMN prev_key_hash TEXT;
ALTER TABLE participants ADD COLUMN prev_key_expires_at TEXT;
"""

# v3: bank-vouched KYC. A bank asserts it has KYC'd its customer; the customer consents.
# Date of birth (optional) is encrypted and only ever used to compute a yes/no senior flag.
SCHEMA_V3 = """
CREATE TABLE kyc_attestations (
    id                 TEXT PRIMARY KEY,
    user_id            TEXT NOT NULL REFERENCES users(id),
    participant_id     TEXT NOT NULL REFERENCES participants(id),
    kyc_level          TEXT NOT NULL,     -- 'full' | 'minimum'
    dob_enc            TEXT,              -- Fernet-encrypted YYYY-MM-DD, optional
    customer_ref_hash  TEXT NOT NULL,     -- HMAC of the bank's own customer id
    verified_on        TEXT NOT NULL,     -- date the bank completed KYC
    status             TEXT NOT NULL,     -- pending_consent|active|rejected|lapsed|withdrawn|revoked|expired|superseded
    created_at         TEXT NOT NULL,
    consent_expires_at TEXT NOT NULL,
    decided_at         TEXT,
    expires_at         TEXT NOT NULL,
    ended_by           TEXT
);
CREATE INDEX ix_kyc_user ON kyc_attestations(user_id, status);
CREATE INDEX ix_kyc_participant ON kyc_attestations(participant_id, status);
"""

# v4: SIM-swap protection. A reported SIM change (or lost phone) opens a risk window;
# sign-ins from new devices start on probation until the device is trusted.
SCHEMA_V4 = """
CREATE TABLE sim_events (
    id             TEXT PRIMARY KEY,
    user_id        TEXT NOT NULL REFERENCES users(id),
    source         TEXT NOT NULL,         -- 'participant' | 'self' | 'guardian'
    reported_by    TEXT NOT NULL,
    changed_at     TEXT NOT NULL,         -- when the SIM changed (or the phone was lost)
    created_at     TEXT NOT NULL,
    window_ends_at TEXT NOT NULL,
    cleared_at     TEXT,
    cleared_by     TEXT
);
CREATE INDEX ix_sim_user ON sim_events(user_id, window_ends_at);

CREATE TABLE devices (
    user_id     TEXT NOT NULL REFERENCES users(id),
    device_hash TEXT NOT NULL,
    first_seen  TEXT NOT NULL,
    last_seen   TEXT NOT NULL,
    trusted_at  TEXT NOT NULL,           -- a new device is trusted only after its probation
    PRIMARY KEY (user_id, device_hash)
);

ALTER TABLE sessions ADD COLUMN device_hash TEXT;
ALTER TABLE sessions ADD COLUMN probation_until TEXT;
"""

# v5: participant trust. Each participant has a kind (bank, NBFC, UPI app...), a regulator
# reference, a status and the capabilities it was granted. Loosening requests wait for a
# second operator in the pending_* columns. Participants from before v5 stay active banks.
SCHEMA_V5 = """
ALTER TABLE participants ADD COLUMN kind TEXT NOT NULL DEFAULT 'bank';
ALTER TABLE participants ADD COLUMN regulator_ref TEXT;
ALTER TABLE participants ADD COLUMN status TEXT NOT NULL DEFAULT 'active';
ALTER TABLE participants ADD COLUMN capabilities TEXT NOT NULL
    DEFAULT '["checks", "kyc_full", "kyc_minimum", "sim_signals"]';
ALTER TABLE participants ADD COLUMN status_reason TEXT;
ALTER TABLE participants ADD COLUMN status_changed_at TEXT;
ALTER TABLE participants ADD COLUMN created_by TEXT;
ALTER TABLE participants ADD COLUMN pending_action TEXT;       -- activate | reinstate | grant
ALTER TABLE participants ADD COLUMN pending_capabilities TEXT; -- JSON list, for grant
ALTER TABLE participants ADD COLUMN pending_by TEXT;
ALTER TABLE participants ADD COLUMN pending_at TEXT;
CREATE UNIQUE INDEX ux_participant_regref ON participants(regulator_ref) WHERE regulator_ref IS NOT NULL;
"""

# v6: mobile-operator SIM feed. Operator events are kept only as (event id, type, outcome)
# for idempotency; no number. A disconnected number is detached from its account.
SCHEMA_V6 = """
ALTER TABLE users ADD COLUMN number_status TEXT NOT NULL DEFAULT 'active';  -- active | disconnected
ALTER TABLE users ADD COLUMN mobile_since TEXT;          -- when this number was linked (NULL = created_at)
ALTER TABLE users ADD COLUMN number_detached_at TEXT;

CREATE TABLE operator_events (
    participant_id TEXT NOT NULL REFERENCES participants(id),
    event_id       TEXT NOT NULL,
    type           TEXT NOT NULL,
    occurred_at    TEXT NOT NULL,
    received_at    TEXT NOT NULL,
    outcome        TEXT NOT NULL,
    PRIMARY KEY (participant_id, event_id)
);

CREATE TABLE sim_lookups (
    user_id       TEXT PRIMARY KEY REFERENCES users(id),
    checked_at    TEXT NOT NULL,
    ok            INTEGER NOT NULL,
    latest_change TEXT,
    error         TEXT
);
"""

# v7: account recovery for people whose number was disconnected and who have no phone
# still signed in. prev_mobile_hash lets them name their old number to find the account.
SCHEMA_V7 = """
ALTER TABLE users ADD COLUMN prev_mobile_hash TEXT;
CREATE INDEX ix_users_prev_mobile ON users(prev_mobile_hash);

CREATE TABLE recoveries (
    id                TEXT PRIMARY KEY,
    token_hash        TEXT NOT NULL UNIQUE,
    user_id           TEXT REFERENCES users(id),   -- NULL when nothing matched (answer looks the same)
    new_mobile_hash   TEXT NOT NULL,
    new_mobile_enc    TEXT NOT NULL,
    new_mobile_masked TEXT NOT NULL,
    needed            INTEGER NOT NULL,            -- contact vouches required
    status            TEXT NOT NULL,               -- pending|held|completed|denied|cancelled|expired
    created_at        TEXT NOT NULL,
    expires_at        TEXT NOT NULL,
    effective_at      TEXT,
    bank_vouched_by   TEXT,
    decided_at        TEXT,
    ended_by          TEXT
);
CREATE INDEX ix_recoveries_user ON recoveries(user_id, status);
CREATE INDEX ix_recoveries_new ON recoveries(new_mobile_hash, status);

CREATE TABLE recovery_vouches (
    recovery_id TEXT NOT NULL REFERENCES recoveries(id),
    voucher_id  TEXT NOT NULL REFERENCES users(id),
    vote        TEXT NOT NULL,                     -- approve | deny
    at          TEXT NOT NULL,
    PRIMARY KEY (recovery_id, voucher_id)
);
"""

MIGRATIONS = [SCHEMA_V1, SCHEMA_V2, SCHEMA_V3, SCHEMA_V4, SCHEMA_V5, SCHEMA_V6, SCHEMA_V7]


class Database:
    def __init__(self, path: str = ":memory:"):
        self.conn = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys = ON")
        if path != ":memory:":
            self.conn.execute("PRAGMA journal_mode = WAL")
        self._lock = threading.RLock()
        self._depth = 0
        self.migrate()

    def migrate(self) -> int:
        """Apply pending migrations in order. PRAGMA user_version records the schema version."""
        version = self.conn.execute("PRAGMA user_version").fetchone()[0]
        for target, script in enumerate(MIGRATIONS, start=1):
            if version >= target:
                continue
            self.conn.execute("PRAGMA foreign_keys = OFF")  # table rebuilds need this off
            try:
                self.conn.executescript(f"BEGIN;\n{script}\nPRAGMA user_version = {target};\nCOMMIT;")
            except BaseException:
                if self.conn.in_transaction:
                    self.conn.execute("ROLLBACK")
                raise
            finally:
                self.conn.execute("PRAGMA foreign_keys = ON")
            version = target
        return version

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
