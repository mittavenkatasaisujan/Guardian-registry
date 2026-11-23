"""Secrets without putting them in environment variables, and data-key rotation.

Secrets from files
------------------
For any setting GR_X, setting GR_X_FILE=/run/secrets/x reads the value from that file
(trailing newline stripped). This is how Docker / Kubernetes secrets and most vault agents
(HashiCorp Vault Agent, AWS / GCP secret-manager CSI drivers) deliver secrets, so the
values never appear in `docker inspect`, process listings or crash dumps of the environment.
If both GR_X and GR_X_FILE are set, startup fails rather than guessing.

Data-key rotation
-----------------
GR_DATA_KEY may hold several Fernet keys separated by commas: the FIRST encrypts, all of
them decrypt. To rotate: put a new key first and keep the old one after it, restart, run
`POST /v1/admin/data-key/rotate` (or rotate_data_key below) until it reports nothing left,
then drop the old key. Every encrypted column is covered: mobile numbers, dates of birth,
recovery numbers, push tokens and numbers inside held number-change requests.
"""

from __future__ import annotations

import json
import os

from cryptography.fernet import Fernet, InvalidToken

# (table, key column, encrypted column, json key inside the column or None)
ENCRYPTED = [
    ("users", "id", "mobile_enc", None),
    ("kyc_attestations", "id", "dob_enc", None),
    ("recoveries", "id", "new_mobile_enc", None),
    ("push_tokens", "id", "token_enc", None),
    ("pending_changes", "id", "payload", "new_mobile_enc"),
]


def load_secret_files(environ=os.environ) -> list[str]:
    """Fill GR_X from GR_X_FILE. Returns the names loaded (never the values)."""
    loaded = []
    for name in sorted(k for k in environ if k.startswith("GR_") and k.endswith("_FILE")):
        target = name[:-5]
        path = environ[name]
        if environ.get(target):
            raise RuntimeError(f"both {target} and {name} are set; use one")
        try:
            with open(path, encoding="utf-8") as f:
                value = f.read().rstrip("\r\n")
        except OSError as e:
            raise RuntimeError(f"{name}: can't read {path}: {e.strerror}") from None
        if not value:
            raise RuntimeError(f"{name}: {path} is empty")
        environ[target] = value
        loaded.append(target)
    return loaded


def _primary_only() -> Fernet:
    from .security import data_keys
    return Fernet(data_keys()[0].encode())


def _needs_rotation(primary: Fernet, token: str) -> bool:
    try:
        primary.decrypt(token.encode())
        return False
    except InvalidToken:
        return True


def rotate_data_key(db, limit: int = 1000) -> dict:
    """Re-encrypt up to `limit` values that aren't under the primary key yet. Returns per-table
    counts and how many are left; call until remaining is 0."""
    from .security import _fernet
    multi, primary = _fernet(), _primary_only()
    done: dict[str, int] = {}
    budget = limit
    for table, pk, col, json_key in ENCRYPTED:
        rows = db.all(f"SELECT {pk} AS pk, {col} AS v FROM {table} WHERE {col} IS NOT NULL")  # nosec B608: only fixed SQL fragments / '?' placeholders are spliced in; values are parameters
        n = 0
        for r in rows:
            if budget <= 0:
                break
            if json_key:
                doc = json.loads(r["v"])
                tok = doc.get(json_key) if isinstance(doc, dict) else None
                if not tok or not _needs_rotation(primary, tok):
                    continue
                doc[json_key] = multi.rotate(tok.encode()).decode()
                new = json.dumps(doc)
            else:
                if not _needs_rotation(primary, r["v"]):
                    continue
                new = multi.rotate(r["v"].encode()).decode()
            with db.tx(shared=True) as c:  # value-for-value swap: compare-and-set, no person's state changes
                c.execute(f"UPDATE {table} SET {col}=? WHERE {pk}=? AND {col}=?", (new, r["pk"], r["v"]))  # nosec B608: only fixed SQL fragments / '?' placeholders are spliced in; values are parameters
            n += 1
            budget -= 1
        if n:
            done[table] = n
    remaining = count_unrotated(db)
    return {"rotated": done, "remaining": remaining}


def count_unrotated(db) -> int:
    primary = _primary_only()
    left = 0
    for table, _pk, col, json_key in ENCRYPTED:
        for r in db.all(f"SELECT {col} AS v FROM {table} WHERE {col} IS NOT NULL"):  # nosec B608: only fixed SQL fragments / '?' placeholders are spliced in; values are parameters
            tok = r["v"]
            if json_key:
                doc = json.loads(tok)
                tok = doc.get(json_key) if isinstance(doc, dict) else None
                if not tok:
                    continue
            if _needs_rotation(primary, tok):
                left += 1
    return left
