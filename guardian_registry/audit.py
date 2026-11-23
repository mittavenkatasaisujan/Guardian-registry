"""Tamper-evident audit log.

Each entry stores the hash of the previous entry IN ITS STREAM, so editing or deleting a
past row breaks every later hash in that stream. `verify` walks every chain and reports the
first broken row. This lets a bank, a family or a regulator check afterwards who approved
what, and that nobody quietly rewrote it.

Streams: one per person (their principal id) plus "system" for entries about no one
(participants, operators, registers). Per-person streams let payment checks for different
people be written in parallel without contending on one chain (see db.py lock scopes).
Entries written before streams existed (stream NULL) form the original single chain and are
verified as before. `head` is a hash over every stream's latest hash, so a single value
still pins the whole log.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from dataclasses import dataclass

GENESIS = "0" * 64
SYSTEM_STREAM = "system"


def _body(fields: dict) -> str:
    return json.dumps(fields, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _digest_legacy(prev_hash: str, seq: int, ts: str, actor: str, action: str,
                   principal_id: str | None, data: dict) -> str:
    body = _body({"seq": seq, "ts": ts, "actor": actor, "action": action, "principal_id": principal_id, "data": data})
    return hashlib.sha256((prev_hash + body).encode()).hexdigest()


def _digest(prev_hash: str, stream: str, stream_seq: int, ts: str, actor: str, action: str,
            principal_id: str | None, data: dict) -> str:
    body = _body({"stream": stream, "stream_seq": stream_seq, "ts": ts, "actor": actor, "action": action,
                  "principal_id": principal_id, "data": data})
    return hashlib.sha256((prev_hash + body).encode()).hexdigest()


def stream_for(principal_id: str | None) -> str:
    return principal_id or SYSTEM_STREAM


def append(conn: sqlite3.Connection, ts: str, actor: str, action: str,
           principal_id: str | None, data: dict) -> str:
    """Append one entry to its stream. Call inside the same transaction as the change it records."""
    stream = stream_for(principal_id)
    last = conn.execute("SELECT stream_seq, hash FROM audit_log WHERE stream=? ORDER BY stream_seq DESC LIMIT 1",
                        (stream,)).fetchone()
    n, prev = (last["stream_seq"] + 1, last["hash"]) if last else (1, GENESIS)
    h = _digest(prev, stream, n, ts, actor, action, principal_id, data)
    conn.execute(
        "INSERT INTO audit_log (ts, actor, action, principal_id, data, prev_hash, hash, stream, stream_seq) "
        "VALUES (?,?,?,?,?,?,?,?,?)",
        (ts, actor, action, principal_id, json.dumps(data, sort_keys=True, ensure_ascii=False), prev, h,
         stream, n),
    )
    return h


@dataclass
class VerifyResult:
    ok: bool
    entries: int
    first_bad_seq: int | None = None
    head: str = GENESIS
    streams: int = 0


def verify(conn: sqlite3.Connection) -> VerifyResult:
    n = 0
    # the original single chain (entries written before per-person streams)
    prev, expected = GENESIS, 1
    for row in conn.execute("SELECT * FROM audit_log WHERE stream IS NULL ORDER BY seq").fetchall():
        n += 1
        if row["seq"] != expected or row["prev_hash"] != prev:
            return VerifyResult(False, n, row["seq"], prev)
        h = _digest_legacy(prev, row["seq"], row["ts"], row["actor"], row["action"], row["principal_id"],
                           json.loads(row["data"]))
        if h != row["hash"]:
            return VerifyResult(False, n, row["seq"], prev)
        prev, expected = h, expected + 1
    heads = {"(original)": prev} if n else {}
    # one chain per stream
    current, prev, expected = None, GENESIS, 1
    for row in conn.execute("SELECT * FROM audit_log WHERE stream IS NOT NULL ORDER BY stream, stream_seq").fetchall():
        if row["stream"] != current:
            if current is not None:
                heads[current] = prev
            current, prev, expected = row["stream"], GENESIS, 1
        n += 1
        if row["stream_seq"] != expected or row["prev_hash"] != prev:
            return VerifyResult(False, n, row["seq"], prev)
        if row["stream"] != stream_for(row["principal_id"]):  # an entry moved between streams
            return VerifyResult(False, n, row["seq"], prev)
        h = _digest(prev, row["stream"], row["stream_seq"], row["ts"], row["actor"], row["action"],
                    row["principal_id"], json.loads(row["data"]))
        if h != row["hash"]:
            return VerifyResult(False, n, row["seq"], prev)
        prev, expected = h, expected + 1
    if current is not None:
        heads[current] = prev
    head = hashlib.sha256(_body(heads).encode()).hexdigest() if heads else GENESIS
    return VerifyResult(True, n, None, head, len(heads))
