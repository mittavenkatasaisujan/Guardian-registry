"""Tamper-evident audit log.

Each entry stores the hash of the previous entry, so editing or deleting any
past row breaks every hash after it. `verify` walks the chain and reports the
first broken row. This lets a bank, a family or a regulator check afterwards
who approved what, and that nobody quietly rewrote it.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from dataclasses import dataclass

GENESIS = "0" * 64


def _digest(prev_hash: str, seq: int, ts: str, actor: str, action: str,
            principal_id: str | None, data: dict) -> str:
    body = json.dumps(
        {"seq": seq, "ts": ts, "actor": actor, "action": action,
         "principal_id": principal_id, "data": data},
        sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    )
    return hashlib.sha256((prev_hash + body).encode()).hexdigest()


def append(conn: sqlite3.Connection, ts: str, actor: str, action: str,
           principal_id: str | None, data: dict) -> str:
    """Append one entry. Call inside the same transaction as the change it records."""
    last = conn.execute("SELECT seq, hash FROM audit_log ORDER BY seq DESC LIMIT 1").fetchone()
    seq, prev = (last["seq"] + 1, last["hash"]) if last else (1, GENESIS)
    h = _digest(prev, seq, ts, actor, action, principal_id, data)
    conn.execute(
        "INSERT INTO audit_log (seq, ts, actor, action, principal_id, data, prev_hash, hash) "
        "VALUES (?,?,?,?,?,?,?,?)",
        (seq, ts, actor, action, principal_id, json.dumps(data, sort_keys=True, ensure_ascii=False), prev, h),
    )
    return h


@dataclass
class VerifyResult:
    ok: bool
    entries: int
    first_bad_seq: int | None = None
    head: str = GENESIS


def verify(conn: sqlite3.Connection) -> VerifyResult:
    prev = GENESIS
    expected_seq = 1
    n = 0
    for row in conn.execute("SELECT * FROM audit_log ORDER BY seq"):
        n += 1
        if row["seq"] != expected_seq or row["prev_hash"] != prev:
            return VerifyResult(False, n, row["seq"], prev)
        h = _digest(prev, row["seq"], row["ts"], row["actor"], row["action"],
                    row["principal_id"], json.loads(row["data"]))
        if h != row["hash"]:
            return VerifyResult(False, n, row["seq"], prev)
        prev = h
        expected_seq += 1
    return VerifyResult(True, n, None, prev)
