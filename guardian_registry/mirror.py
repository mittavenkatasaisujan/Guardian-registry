"""Make a clean, signed mirror of a regulator's published list, for a register feed to read.

RBI, NPCI and DoT publish their lists as spreadsheets (and some as PDFs), with title rows,
odd headers and the occasional footnote. A mirror is that list reduced to what the registry
needs, as JSON, plus an Ed25519 signature:

    {"source": "<where it came from>", "as_of": "<date of the list>",
     "entities": [{"regulator_ref": "...", "name": "..."}, ...]}      (sorted by ref)

The output is byte-for-byte deterministic, so republishing an unchanged list gives the same
hash and the registry's refresh costs nothing. Publish <name>.json and <name>.json.sig
side by side (any static host), then point the feed at the .json with format "json" and the
public key; the registry refuses the file if the signature doesn't match.

Where a list is only a PDF, export or copy its table into a spreadsheet or CSV first: PDF
tables can't be read reliably, and a silently mis-read licence would suspend a bank.

Command line: scripts/mirror_register.py (keygen, build).
"""

from __future__ import annotations

import base64
import json
import os

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from . import tables
from .registerfeed import parse_feed


def keygen() -> tuple[bytes, str]:
    """(private key PEM, public key as the registry wants it: base64 of the raw 32 bytes)."""
    k = Ed25519PrivateKey.generate()
    pem = k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                          serialization.NoEncryption())
    return pem, public_key_b64(k)


def public_key_b64(k: Ed25519PrivateKey) -> str:
    raw = k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return base64.b64encode(raw).decode()


def load_private_key(pem: bytes) -> Ed25519PrivateKey:
    k = serialization.load_pem_private_key(pem, password=None)
    if not isinstance(k, Ed25519PrivateKey):
        raise ValueError("the signing key must be Ed25519 (make one with: mirror_register.py keygen)")
    return k


def build(raw: bytes, fmt: str, ref_field: str, name_field: str, source: str, as_of: str,
          sheet: str | None = None) -> tuple[bytes, list[dict]]:
    """Returns (mirror JSON bytes, entities)."""
    if not source.strip() or not as_of.strip():
        raise ValueError("source and as_of are required: say where the list came from and its date")
    entities, _ = parse_feed(raw, fmt, ref_field, name_field, sheet)
    if not entities:
        raise ValueError("the list has no entities; refusing to publish an empty register")
    entities = sorted(entities, key=lambda e: e["regulator_ref"])
    doc = {"source": source.strip(), "as_of": as_of.strip(), "entities": entities}
    return (json.dumps(doc, ensure_ascii=False, sort_keys=True, indent=1) + "\n").encode(), entities


def sign(body: bytes, key: Ed25519PrivateKey) -> bytes:
    return base64.b64encode(key.sign(body)) + b"\n"


def diff(previous: bytes | None, entities: list[dict]) -> dict:
    """What changes against the last published mirror, to review before publishing."""
    if not previous:
        return {"added": [e["regulator_ref"] for e in entities], "removed": [], "renamed": []}
    old = {e["regulator_ref"]: e["name"] for e in json.loads(previous)["entities"]}
    new = {e["regulator_ref"]: e["name"] for e in entities}
    return {"added": sorted(new.keys() - old.keys()), "removed": sorted(old.keys() - new.keys()),
            "renamed": sorted(r for r in new.keys() & old.keys() if new[r] != old[r])}


def write_private_key(path: str, pem: bytes) -> None:
    if os.path.exists(path):
        raise FileExistsError(f"{path} already exists; refusing to overwrite a signing key")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(pem)


__all__ = ["keygen", "build", "sign", "diff", "load_private_key", "write_private_key", "tables"]
