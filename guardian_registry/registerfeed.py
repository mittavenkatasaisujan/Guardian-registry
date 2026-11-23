"""Automatic refresh of the official registers (RBI / NPCI / DoT lists).

An operator points a kind at a published list once; the worker re-reads it every
GR_REGISTER_REFRESH_HOURS (default 24) and keeps the register current:

  * Four-eyes. A feed can suspend banks, so a new or changed feed is only used after a
    second operator approves it.
  * Signed lists. With a public key (Ed25519, base64 of the raw 32 bytes) the list must
    come with a detached signature at <url>.sig (base64), or it is refused. Use this when
    the list is a mirror you or an industry body publish.
  * Unchanged lists cost nothing: the content hash is compared first.
  * A safety valve against a broken or truncated download: if a refresh would remove more
    than max_drop_pct of the entities (or all of them), it is HELD, not applied, until an
    operator applies or discards it.
  * When an entity leaves the list (licence cancelled, merged), every active participant
    registered with that regulator_ref is suspended at once, with the reason recorded and
    its webhook told, unless the feed has auto_suspend off. Reinstating needs the usual
    second operator.

Formats: CSV with a header row, or JSON (a list of objects, or {"as_of": ..., "entities":
[...]}). ref_field and name_field say which columns hold the licence number and the name.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
from datetime import timedelta

import httpx
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from . import tables
from .clock import iso
from .errors import Conflict, Invalid, NotFound

log = logging.getLogger("guardian_registry.registerfeed")

MAX_FEED_BYTES = 20 * 1024 * 1024
FORMATS = ("csv", "xlsx", "json")
ACTOR = "system:register-feed"


def refresh_hours() -> float:
    return float(os.environ.get("GR_REGISTER_REFRESH_HOURS", "24"))


class FeedError(Exception):
    pass


def parse_feed(raw: bytes, fmt: str, ref_field: str, name_field: str,
               sheet: str | None = None) -> tuple[list[dict], str | None]:
    """Returns (entities, as_of from the file if it has one). CSV and .xlsx go through
    tables.py, which finds the header row and matches messy headers; JSON keys are exact."""
    if fmt in ("csv", "xlsx"):
        try:
            return tables.records(tables.rows(raw, fmt, sheet), ref_field, name_field), None
        except tables.TableError as e:
            raise FeedError(str(e)) from None
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        raise FeedError("list is not UTF-8") from None
    as_of = None
    try:
        doc = json.loads(text)
    except ValueError:
        raise FeedError("list is not valid JSON") from None
    if isinstance(doc, dict):
        as_of = doc.get("as_of")
        doc = doc.get("entities")
    if not isinstance(doc, list):
        raise FeedError("JSON list must be an array or {\"entities\": [...]}")
    rows = doc
    out, seen = [], set()
    for r in rows:
        if not isinstance(r, dict):
            raise FeedError("every entry must be an object")
        ref, name = str(r.get(ref_field) or "").strip(), str(r.get(name_field) or "").strip()
        if not ref and not name:
            continue  # blank line
        if not ref or not name:
            raise FeedError(f"an entry is missing {ref_field!r} or {name_field!r}")
        if ref in seen:
            continue  # published lists repeat rows; first one wins
        seen.add(ref)
        out.append({"regulator_ref": ref, "name": name})
    return out, (str(as_of) if as_of else None)


class RegisterFeedMixin:
    """Mixed into Registry (with ParticipantMixin)."""

    feed_http: httpx.Client | None = None

    # ------------------------------------------------------------- configuration
    def configure_feed(self, operator: str, kind: str, url: str, fmt: str = "csv", ref_field: str = "regulator_ref",
                       name_field: str = "name", public_key: str | None = None, max_drop_pct: int = 5,
                       auto_suspend: bool = True, sheet: str | None = None) -> dict:
        from .participants import PARTICIPANT_KINDS
        if kind not in PARTICIPANT_KINDS:
            raise Invalid(f"kind must be one of {list(PARTICIPANT_KINDS)}")
        url = (url or "").strip()
        if not url.startswith("https://") and not url.startswith("http://localhost") \
                and not url.startswith("http://127.0.0.1"):
            raise Invalid("url must be https")
        if fmt not in FORMATS:
            raise Invalid(f"format must be one of {list(FORMATS)}")
        if not 0 <= int(max_drop_pct) <= 100:
            raise Invalid("max_drop_pct must be 0-100")
        if public_key:
            try:
                raw = base64.b64decode(public_key, validate=True)
                Ed25519PublicKey.from_public_bytes(raw)
            except Exception:  # noqa: BLE001
                raise Invalid("public_key must be base64 of a raw 32-byte Ed25519 key") from None
        now = self._now()
        with self.db.tx() as c:
            c.execute(
                "INSERT INTO register_feeds (kind, url, format, ref_field, name_field, public_key, max_drop_pct, "
                "auto_suspend, sheet, status, configured_by, configured_at) VALUES (?,?,?,?,?,?,?,?,?,'pending',?,?) "
                "ON CONFLICT(kind) DO UPDATE SET url=excluded.url, format=excluded.format, "
                "ref_field=excluded.ref_field, name_field=excluded.name_field, public_key=excluded.public_key, "
                "max_drop_pct=excluded.max_drop_pct, auto_suspend=excluded.auto_suspend, sheet=excluded.sheet, "
                "status='pending', "
                "configured_by=excluded.configured_by, configured_at=excluded.configured_at, approved_by=NULL, "
                "last_hash=NULL, held_json=NULL, held_reason=NULL, held_at=NULL",
                (kind, url, fmt, ref_field, name_field, public_key or None, int(max_drop_pct),
                 1 if auto_suspend else 0, (sheet or "").strip() or None, operator, now))
            self._audit(c, f"operator:{operator}", "register_feed.configured", None, kind=kind, url=url,
                        format=fmt, signed=bool(public_key), max_drop_pct=int(max_drop_pct),
                        auto_suspend=bool(auto_suspend))
        return self.feed_view(kind)

    def approve_feed(self, operator: str, kind: str, allow_self: bool = False) -> dict:
        r = self._feed_row(kind)
        if r["status"] != "pending":
            raise Conflict("this feed is not waiting for approval")
        if r["configured_by"] == operator and not allow_self:
            raise Conflict("a second operator must approve a feed (four-eyes)")
        with self.db.tx() as c:
            c.execute("UPDATE register_feeds SET status='active', approved_by=? WHERE kind=? AND status='pending'",
                      (operator, kind))
            self._audit(c, f"operator:{operator}", "register_feed.approved", None, kind=kind,
                        configured_by=r["configured_by"])
        return self.feed_view(kind)

    def remove_feed(self, operator: str, kind: str) -> dict:
        self._feed_row(kind)
        with self.db.tx() as c:
            c.execute("DELETE FROM register_feeds WHERE kind=?", (kind,))
            self._audit(c, f"operator:{operator}", "register_feed.removed", None, kind=kind)
        return {"kind": kind, "removed": True}

    def _feed_row(self, kind: str):
        r = self.db.one("SELECT * FROM register_feeds WHERE kind=?", (kind,))
        if not r:
            raise NotFound("no feed is configured for this kind")
        return r

    def feed_view(self, kind: str) -> dict:
        r = self._feed_row(kind)
        held = json.loads(r["held_json"]) if r["held_json"] else None
        return {"kind": r["kind"], "url": r["url"], "format": r["format"], "sheet": r["sheet"],
                "ref_field": r["ref_field"],
                "name_field": r["name_field"], "signed": bool(r["public_key"]), "max_drop_pct": r["max_drop_pct"],
                "auto_suspend": bool(r["auto_suspend"]), "status": r["status"],
                "configured_by": r["configured_by"], "approved_by": r["approved_by"],
                "last_checked_at": r["last_checked_at"], "last_changed_at": r["last_changed_at"],
                "last_error": r["last_error"],
                "held": None if not held else {"reason": r["held_reason"], "at": r["held_at"],
                                               "entities": len(held["entities"]), "removes": held["removes"],
                                               "adds": held["adds"]}}

    def feeds(self) -> list[dict]:
        return [self.feed_view(r["kind"]) for r in self.db.all("SELECT kind FROM register_feeds ORDER BY kind")]

    # ------------------------------------------------------------- refresh
    def _http(self) -> httpx.Client:
        if self.feed_http is None:
            self.feed_http = httpx.Client(timeout=30, follow_redirects=True)
        return self.feed_http

    def _fetch(self, r) -> bytes:
        resp = self._http().get(r["url"])
        if resp.status_code != 200:
            raise FeedError(f"list download returned HTTP {resp.status_code}")
        raw = resp.content
        if len(raw) > MAX_FEED_BYTES:
            raise FeedError("list is larger than 20 MB")
        if r["public_key"]:
            sig = self._http().get(r["url"] + ".sig")
            if sig.status_code != 200:
                raise FeedError("signature download failed; a signed feed is never used unsigned")
            try:
                key = Ed25519PublicKey.from_public_bytes(base64.b64decode(r["public_key"]))
                key.verify(base64.b64decode(sig.content.strip(), validate=True), raw)
            except (InvalidSignature, ValueError):
                raise FeedError("list signature does not verify") from None
        return raw

    def refresh_registers(self, force: bool = False) -> dict:
        """Check every active feed that is due. Called from the worker's sweep."""
        now = self.clock.now()
        due_before = iso(now - timedelta(hours=refresh_hours()))
        rows = self.db.all("SELECT * FROM register_feeds WHERE status='active'" +
                           ("" if force else " AND (last_checked_at IS NULL OR last_checked_at<=?)"),
                           () if force else (due_before,))
        out = {}
        for r in rows:
            try:
                out[r["kind"]] = self._refresh_one(r)
            except FeedError as e:
                with self.db.tx(shared=True) as c:
                    c.execute("UPDATE register_feeds SET last_checked_at=?, last_error=? WHERE kind=?",
                              (iso(now), str(e)[:500], r["kind"]))
                log.warning("register feed %s: %s", r["kind"], e)
                out[r["kind"]] = "error"
            except httpx.HTTPError as e:
                with self.db.tx(shared=True) as c:
                    c.execute("UPDATE register_feeds SET last_checked_at=?, last_error=? WHERE kind=?",
                              (iso(now), f"download failed: {e}"[:500], r["kind"]))
                out[r["kind"]] = "error"
        return out

    def _refresh_one(self, r) -> str:
        raw = self._fetch(r)  # network outside any transaction
        digest = hashlib.sha256(raw).hexdigest()
        now = self._now()
        if digest == r["last_hash"]:
            with self.db.tx(shared=True) as c:
                c.execute("UPDATE register_feeds SET last_checked_at=?, last_error=NULL WHERE kind=?", (now, r["kind"]))
            return "unchanged"
        entities, as_of = parse_feed(raw, r["format"], r["ref_field"], r["name_field"], r["sheet"])
        current = {x["regulator_ref"] for x in self.db.all(
            "SELECT regulator_ref FROM regulated_entities WHERE kind=?", (r["kind"],))}
        new = {e["regulator_ref"] for e in entities}
        removes, adds = sorted(current - new), sorted(new - current)
        reason = None
        if not entities:
            reason = "the new list is empty"
        elif current and len(removes) * 100 > r["max_drop_pct"] * len(current):
            reason = (f"the new list removes {len(removes)} of {len(current)} entities "
                      f"(more than {r['max_drop_pct']}%)")
        if reason:
            with self.db.tx() as c:
                c.execute("UPDATE register_feeds SET last_checked_at=?, last_error=NULL, held_json=?, held_reason=?, "
                          "held_at=?, held_hash=? WHERE kind=?",
                          (now, json.dumps({"entities": entities, "as_of": as_of or now[:10], "removes": removes,
                                            "adds": adds}), reason, now, digest, r["kind"]))
                self._audit(c, ACTOR, "register_feed.held", None, kind=r["kind"], reason=reason,
                            removes=len(removes), adds=len(adds))
            return "held"
        self._apply_feed(r["kind"], r["url"], entities, as_of or now[:10], digest, ACTOR, bool(r["auto_suspend"]))
        return "updated"

    def _apply_feed(self, kind: str, source: str, entities: list[dict], as_of: str, digest: str, actor: str,
                    auto_suspend: bool) -> dict:
        now = self._now()
        with self.db.tx() as c:
            current = {x["regulator_ref"] for x in c.execute(
                "SELECT regulator_ref FROM regulated_entities WHERE kind=?", (kind,)).fetchall()}
            c.execute("DELETE FROM regulated_entities WHERE kind=?", (kind,))
            c.executemany("INSERT INTO regulated_entities VALUES (?,?,?,?,?)",
                          [(kind, e["regulator_ref"], e["name"], source, as_of) for e in entities])
            removed = current - {e["regulator_ref"] for e in entities}
            suspended = []
            if auto_suspend and removed:
                marks = ",".join("?" * len(removed))
                for p in c.execute(f"SELECT id, status, pending_action FROM participants WHERE kind=? AND status='active' "
                                   f"AND regulator_ref IN ({marks})", (kind, *sorted(removed))).fetchall():
                    reason = f"no longer on the official {kind} register ({source}, as of {as_of})"
                    c.execute("UPDATE participants SET status='suspended', status_reason=?, status_changed_at=? "
                              "WHERE id=?", (reason, now, p["id"]))
                    if p["pending_action"] in ("activate", "grant"):
                        self._clear_pending(c, p["id"])
                    self._audit(c, actor, "participant.suspended", None, participant_id=p["id"], reason=reason,
                                previous_status="active")
                    self._participant_event(c, p["id"])
                    suspended.append(p["id"])
            c.execute("UPDATE register_feeds SET last_checked_at=?, last_changed_at=?, last_hash=?, last_error=NULL, "
                      "held_json=NULL, held_reason=NULL, held_at=NULL, held_hash=NULL WHERE kind=?",
                      (now, now, digest, kind))
            self._audit(c, actor, "register.loaded", None, kind=kind, source=source, as_of=as_of,
                        entities=len(entities), removed=len(removed), participants_suspended=len(suspended))
        return {"kind": kind, "entities": len(entities), "removed": sorted(removed), "suspended": suspended}

    def apply_held_feed(self, operator: str, kind: str) -> dict:
        r = self._feed_row(kind)
        if not r["held_json"]:
            raise Conflict("no refresh is held for this kind")
        held = json.loads(r["held_json"])
        if not held["entities"]:
            raise Conflict("an empty list can't be applied; discard it and load the register by hand")
        return self._apply_feed(kind, r["url"], held["entities"], held["as_of"], r["held_hash"],
                                f"operator:{operator}", bool(r["auto_suspend"]))

    def discard_held_feed(self, operator: str, kind: str) -> dict:
        r = self._feed_row(kind)
        if not r["held_json"]:
            raise Conflict("no refresh is held for this kind")
        with self.db.tx() as c:
            # remember the hash so the same bad file isn't held again tomorrow
            c.execute("UPDATE register_feeds SET held_json=NULL, held_reason=NULL, held_at=NULL, last_hash=held_hash, "
                      "held_hash=NULL WHERE kind=?", (kind,))
            self._audit(c, f"operator:{operator}", "register_feed.discarded", None, kind=kind)
        return self.feed_view(kind)


__all__ = ["RegisterFeedMixin", "parse_feed", "FeedError"]
