"""Storage: SQLite for a single node, Postgres for several.

`Database(path)` opens SQLite (a file path, or ":memory:"). `Database("postgresql://...")`
opens Postgres. Both use one connection guarded by a lock per process.

Schema: the SQLite migrations below are the single source of truth. For Postgres the
registry builds the same final schema from them (postgres_baseline) and records the
version, so there is only one schema to maintain.

Multi-node safety on Postgres: lock scopes.
  * `tx()` (no keys) is a GLOBAL write: it takes the database-wide advisory lock exclusively,
    so it runs alone, exactly as SQLite serializes writes. Rare operations use it: rules,
    guardians, onboarding, recovery, KYC, sweeps of held changes.
  * `tx(person_id)` is a PER-PERSON write: it takes the database-wide lock SHARED plus an
    exclusive lock for that person. Payment checks, approvals, outcomes and the per-person
    sweep use it, so checks for different people run in parallel on every node, while each
    person's daily limit stays exact. A global write still waits for all of them.
  * `tx(shared=True)` takes only the shared lock: for row-level work that touches no
    person's state (claiming an alert to send).
  The audit log keeps one hash chain per person (plus "system"), so per-person writes never
  contend on it. A transaction may only write audit entries for the people it locked; a
  nested tx may not widen the scope. Both are checked on SQLite too (ScopeError), so the
  test suite catches a lock-scope mistake before it can race on Postgres.
"""

from __future__ import annotations

import re
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

# v8: assisted recovery flag; register of regulated entities; shared rate-limit counters;
# alert channel choice and push tokens.
SCHEMA_V8 = """
ALTER TABLE recoveries ADD COLUMN assisted INTEGER NOT NULL DEFAULT 0;

CREATE TABLE regulated_entities (
    kind          TEXT NOT NULL,
    regulator_ref TEXT NOT NULL,
    name          TEXT NOT NULL,
    source        TEXT NOT NULL,
    as_of         TEXT NOT NULL,
    PRIMARY KEY (kind, regulator_ref)
);

CREATE TABLE rate_counters (
    bucket       TEXT PRIMARY KEY,         -- limiter name + key + window number
    count        INTEGER NOT NULL,
    window_end   REAL NOT NULL
);

ALTER TABLE users ADD COLUMN urgent_channel TEXT NOT NULL DEFAULT 'sms';   -- sms | whatsapp

CREATE TABLE push_tokens (
    id          TEXT PRIMARY KEY,
    user_id     TEXT NOT NULL REFERENCES users(id),
    token_hash  TEXT NOT NULL UNIQUE,
    token_enc   TEXT NOT NULL,
    platform    TEXT NOT NULL,
    created_at  TEXT NOT NULL
);
CREATE INDEX ix_push_user ON push_tokens(user_id);
"""

# v9 (first portable migration, see PORTABLE_FROM): device-bound keys. The app keeps a
# private key in secure hardware and signs a one-time server challenge at sign-in.
SCHEMA_V9 = """
CREATE TABLE device_keys (
    user_id           TEXT NOT NULL REFERENCES users(id),
    key_id            TEXT NOT NULL,              -- SHA-256 of the public key (DER)
    public_key        TEXT NOT NULL,              -- base64 DER SubjectPublicKeyInfo, P-256
    platform_attested INTEGER NOT NULL DEFAULT 0, -- Play Integrity / App Attest said hardware + genuine app
    created_at        TEXT NOT NULL,
    trusted_at        TEXT NOT NULL,              -- after probation (first key: at once)
    last_used_at      TEXT,
    revoked_at        TEXT,
    PRIMARY KEY (user_id, key_id)
);
CREATE TABLE auth_challenges (
    nonce_hash TEXT PRIMARY KEY,
    expires_at TEXT NOT NULL,
    used_at    TEXT
);
ALTER TABLE sessions ADD COLUMN device_key_id TEXT;
"""

# v10 (portable): mutual TLS for participants. Client certificates are pinned by SHA-256
# fingerprint; a pending row waits for a second operator.
SCHEMA_V10 = """
CREATE TABLE participant_certs (
    participant_id TEXT NOT NULL REFERENCES participants(id),
    fingerprint    TEXT NOT NULL,          -- SHA-256 of the certificate (DER), hex
    subject        TEXT NOT NULL,
    not_after      TEXT NOT NULL,
    status         TEXT NOT NULL,          -- pending | active | removed
    added_by       TEXT NOT NULL,
    added_at       TEXT NOT NULL,
    decided_by     TEXT,
    decided_at     TEXT,
    PRIMARY KEY (participant_id, fingerprint)
);
CREATE INDEX ix_certs_fp ON participant_certs(fingerprint, status);
"""

# v11 (portable): the audit log becomes one hash chain per person ("stream"), plus "system"
# for entries about no one, so writes for different people don't contend on one chain.
# Entries written before v11 keep stream NULL and stay verifiable as the original chain.
SCHEMA_V11 = """
ALTER TABLE audit_log ADD COLUMN stream TEXT;
ALTER TABLE audit_log ADD COLUMN stream_seq INTEGER;
CREATE UNIQUE INDEX ux_audit_stream ON audit_log(stream, stream_seq);
"""

# v12: automatic refresh of the official registers (registerfeed.py)
SCHEMA_V12 = """
CREATE TABLE register_feeds (
    kind            TEXT PRIMARY KEY,
    url             TEXT NOT NULL,
    format          TEXT NOT NULL,
    ref_field       TEXT NOT NULL,
    name_field      TEXT NOT NULL,
    public_key      TEXT,
    max_drop_pct    INTEGER NOT NULL,
    auto_suspend    INTEGER NOT NULL,
    status          TEXT NOT NULL,
    configured_by   TEXT NOT NULL,
    configured_at   TEXT NOT NULL,
    approved_by     TEXT,
    last_checked_at TEXT,
    last_changed_at TEXT,
    last_hash       TEXT,
    last_error      TEXT,
    held_json       TEXT,
    held_reason     TEXT,
    held_at         TEXT,
    held_hash       TEXT
);
"""

# v13: which worksheet of an .xlsx register to read
SCHEMA_V13 = """
ALTER TABLE register_feeds ADD COLUMN sheet TEXT;
"""

# v14: privacy (privacy.py): consent records, held erasure requests, erased accounts
SCHEMA_V14 = """
CREATE TABLE consents (
    id             TEXT PRIMARY KEY,
    user_id        TEXT NOT NULL REFERENCES users(id),
    notice_version TEXT NOT NULL,
    accepted_at    TEXT NOT NULL
);
CREATE INDEX ix_consents_user ON consents(user_id);
CREATE TABLE erasure_requests (
    id           TEXT PRIMARY KEY,
    user_id      TEXT NOT NULL REFERENCES users(id),
    status       TEXT NOT NULL,
    requested_at TEXT NOT NULL,
    erase_at     TEXT NOT NULL,
    decided_at   TEXT
);
CREATE INDEX ix_erasure_due ON erasure_requests(status, erase_at);
ALTER TABLE users ADD COLUMN erased_at TEXT;
"""

# v15: each person's language for alerts, SMS and messages (messages.py)
SCHEMA_V15 = """
ALTER TABLE users ADD COLUMN language TEXT;
"""

# v16: shared scam signals (scamsignals.py): banks' fraud reports and operators' decisions
SCHEMA_V16 = """
CREATE TABLE payee_reports (
    id             TEXT PRIMARY KEY,
    payee          TEXT NOT NULL,
    participant_id TEXT NOT NULL REFERENCES participants(id),
    reason         TEXT NOT NULL,
    evidence_ref   TEXT,
    reported_at    TEXT NOT NULL,
    expires_at     TEXT NOT NULL,
    withdrawn_at   TEXT
);
CREATE INDEX ix_payee_reports ON payee_reports(payee);
CREATE TABLE payee_decisions (
    payee      TEXT PRIMARY KEY,
    decision   TEXT NOT NULL,
    operator   TEXT NOT NULL,
    reason     TEXT NOT NULL,
    decided_at TEXT NOT NULL
);
"""

MIGRATIONS = [SCHEMA_V1, SCHEMA_V2, SCHEMA_V3, SCHEMA_V4, SCHEMA_V5, SCHEMA_V6, SCHEMA_V7, SCHEMA_V8, SCHEMA_V9,
              SCHEMA_V10, SCHEMA_V11, SCHEMA_V12, SCHEMA_V13, SCHEMA_V14, SCHEMA_V15, SCHEMA_V16]

# Postgres-only follow-ups, run after the baseline or after the portable migration of the
# same version. v11: audit rows get their global seq from a sequence (SQLite's INTEGER
# PRIMARY KEY does this by itself), since per-person writers can't share MAX(seq)+1.
PG_EXTRAS = {
    11: """
CREATE SEQUENCE IF NOT EXISTS audit_log_seq;
SELECT setval('audit_log_seq', COALESCE((SELECT MAX(seq) FROM audit_log), 0) + 1, false);
ALTER TABLE audit_log ALTER COLUMN seq SET DEFAULT nextval('audit_log_seq');
""",
}


# From this migration on (1-based), every script must be plain SQL that runs on SQLite AND
# Postgres (CREATE TABLE / INDEX, ALTER TABLE ... ADD COLUMN, UPDATE ...). Postgres applies
# them as they are. Earlier ones (with SQLite table rebuilds) reach Postgres only through
# postgres_baseline().
PORTABLE_FROM = 9

PG_WRITE_LOCK = 7_240_001        # advisory lock: exclusive = global write, shared = scoped write
PG_PERSON_LOCK = 7_240_002       # advisory lock namespace for per-person writes
PG_ROWID_TABLES = ("checks", "notifications")  # code orders by SQLite's rowid on these


def _strip_comments(sql: str) -> str:
    return re.sub(r"--[^\n]*", "", sql)


def postgres_baseline() -> str:
    """The final schema as Postgres DDL, derived by running every SQLite migration."""
    mem = sqlite3.connect(":memory:")
    for script in MIGRATIONS:
        mem.executescript(script)
    rows = mem.execute("SELECT type, name, sql FROM sqlite_master WHERE sql IS NOT NULL "
                       "AND name NOT LIKE 'sqlite_%' ORDER BY rowid").fetchall()
    mem.close()
    tables = {name: _strip_comments(sql) for kind, name, sql in rows if kind == "table"}
    indexes = [_strip_comments(sql) for kind, name, sql in rows if kind == "index"]
    order, done = [], set()

    def visit(name: str, path=()):  # referenced tables must exist first
        if name in done:
            return
        if name in path:
            raise RuntimeError(f"foreign-key cycle at {name}")
        for ref in re.findall(r'REFERENCES\s+"?(\w+)', tables[name]):
            if ref != name and ref in tables:
                visit(ref, path + (name,))
        done.add(name)
        order.append(name)

    for name in tables:
        visit(name)
    ddl = []
    for name in order:
        sql = tables[name].strip()
        sql = re.sub(r"^CREATE TABLE\s+(IF NOT EXISTS\s+)?", "CREATE TABLE IF NOT EXISTS ", sql)
        if name in PG_ROWID_TABLES:
            sql = sql[: sql.rindex(")")].rstrip() + ",\n    rowid BIGSERIAL\n)"
        ddl.append(sql + ";")
    for sql in indexes:
        sql = re.sub(r"^CREATE (UNIQUE )?INDEX\s+(IF NOT EXISTS\s+)?",
                     lambda m: f"CREATE {m.group(1) or ''}INDEX IF NOT EXISTS ", sql.strip())
        ddl.append(sql + ";")
    return "\n".join(ddl)


class PgConnection:
    """Makes a psycopg connection look like the sqlite3 one the code uses: `?` placeholders,
    rows readable by column name, execute / executemany / executescript."""

    def __init__(self, url: str, schema: str | None = None):
        import psycopg  # optional dependency: only needed for Postgres
        from psycopg.rows import dict_row
        self._pg = psycopg
        self._c = psycopg.connect(url, autocommit=True, row_factory=dict_row)
        if schema:
            if not re.fullmatch(r"[a-z_][a-z0-9_]{0,62}", schema):
                raise ValueError("bad schema name")
            self._c.execute(f"CREATE SCHEMA IF NOT EXISTS {schema}")
            self._c.execute(f"SET search_path TO {schema}")

    @staticmethod
    def _sql(sql: str) -> str:
        return sql.replace("?", "%s")

    def execute(self, sql: str, params=()):
        return self._c.execute(self._sql(sql), tuple(params) if params else None)

    def executemany(self, sql: str, seq):
        cur = self._c.cursor()
        cur.executemany(self._sql(sql), [tuple(p) for p in seq])
        return cur

    def executescript(self, script: str) -> None:
        self._c.execute(script)

    def iterdump(self):
        """Every row of every table as text, like sqlite3's iterdump (for privacy checks)."""
        tables = self._c.execute("SELECT table_name FROM information_schema.tables "
                                 "WHERE table_schema = current_schema() ORDER BY table_name").fetchall()
        for t in tables:
            for row in self._c.execute(f'SELECT * FROM "{t["table_name"]}"').fetchall():
                yield f"{t['table_name']}: {row!r}"

    def drop_schema(self) -> None:
        schema = self._c.execute("SELECT current_schema() AS s").fetchone()["s"]
        if schema and schema != "public":
            self._c.execute(f"DROP SCHEMA {schema} CASCADE")

    @property
    def in_transaction(self) -> bool:
        return self._c.info.transaction_status != self._pg.pq.TransactionStatus.IDLE

    def close(self) -> None:
        self._c.close()


class ScopeError(RuntimeError):
    """Code tried to write outside the lock scope of its transaction (a bug)."""


class Database:
    def __init__(self, path: str = ":memory:", schema: str | None = None):
        self.backend = "postgres" if path.startswith(("postgres://", "postgresql://")) else "sqlite"
        self._lock = threading.RLock()
        self._depth = 0
        self._scope: frozenset | None = None  # None = global; otherwise the locked person ids
        if self.backend == "postgres":
            self.conn = PgConnection(path, schema)
        else:
            self.conn = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
            self.conn.row_factory = sqlite3.Row
            self.conn.execute("PRAGMA foreign_keys = ON")
            if path != ":memory:":
                self.conn.execute("PRAGMA journal_mode = WAL")
        self.migrate()

    def migrate(self) -> int:
        """Apply pending migrations in order."""
        if self.backend == "postgres":
            return self._migrate_postgres()
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

    def _migrate_postgres(self) -> int:
        """First start: create the full schema. Later starts: apply the portable migrations
        added since, in order, in one transaction."""
        with self.tx() as c:  # the write lock also stops two nodes migrating at once
            c.execute("CREATE TABLE IF NOT EXISTS gr_schema (version INTEGER NOT NULL)")
            row = c.execute("SELECT version FROM gr_schema").fetchone()
            if row is None:
                c.executescript(postgres_baseline())
                for v in sorted(PG_EXTRAS):
                    c.executescript(PG_EXTRAS[v])
                c.execute("INSERT INTO gr_schema (version) VALUES (?)", (len(MIGRATIONS),))
                return len(MIGRATIONS)
            version = row["version"]
            if version > len(MIGRATIONS):
                raise RuntimeError(f"Postgres schema is v{version}, newer than this code (v{len(MIGRATIONS)})")
            if version < PORTABLE_FROM - 1:
                raise RuntimeError(f"Postgres schema v{version} predates portable migrations; rebuild it")
            for target in range(version + 1, len(MIGRATIONS) + 1):
                c.executescript(_strip_comments(MIGRATIONS[target - 1]))
                if target in PG_EXTRAS:
                    c.executescript(PG_EXTRAS[target])
                c.execute("UPDATE gr_schema SET version=?", (target,))
            return len(MIGRATIONS)

    @contextmanager
    def tx(self, *keys: str, shared: bool = False):
        """Atomic unit of work; see the module notes on lock scopes.

        tx()            global write (runs alone)
        tx(person, ...) per-person write (parallel with other people's)
        tx(shared=True) neither: row-level work that touches no person's state
        Nested calls join the outer transaction and may not widen its scope."""
        scope = frozenset(k for k in keys if k) if (keys or shared) else None
        with self._lock:
            outer = self._depth == 0
            if outer:
                if self.backend == "postgres":
                    self.conn.execute("BEGIN")
                    if scope is None:
                        self.conn.execute("SELECT pg_advisory_xact_lock(?)", (PG_WRITE_LOCK,))
                    else:
                        self.conn.execute("SELECT pg_advisory_xact_lock_shared(?)", (PG_WRITE_LOCK,))
                        for k in sorted(scope):  # fixed order: no deadlocks between multi-key txs
                            self.conn.execute("SELECT pg_advisory_xact_lock(?, hashtext(?))", (PG_PERSON_LOCK, k))
                else:
                    self.conn.execute("BEGIN IMMEDIATE")
                self._scope = scope
            elif self._scope is not None and (scope is None or not scope <= self._scope):
                raise ScopeError(f"nested transaction widens the lock scope {sorted(self._scope)} -> "
                                 f"{'GLOBAL' if scope is None else sorted(scope)}")
            self._depth += 1
            try:
                yield self.conn
            except BaseException:
                self._depth -= 1
                if outer:
                    self._scope = None
                    self.conn.execute("ROLLBACK")
                raise
            else:
                self._depth -= 1
                if outer:
                    self._scope = None
                    self.conn.execute("COMMIT")

    def schema_version(self) -> int:
        if self.backend == "postgres":
            return self.one("SELECT version FROM gr_schema")["version"]
        return self.conn.execute("PRAGMA user_version").fetchone()[0]

    def require_scope(self, key: str) -> None:
        """Raise unless the current transaction may write state belonging to `key`."""
        if self._depth and self._scope is not None and key not in self._scope:
            raise ScopeError(f"writing {key!r} inside a transaction locked for {sorted(self._scope)}")

    def one(self, sql: str, params=()):
        with self._lock:
            return self.conn.execute(sql, params).fetchone()

    def all(self, sql: str, params=()):
        with self._lock:
            return self.conn.execute(sql, params).fetchall()

    def close(self) -> None:
        self.conn.close()
