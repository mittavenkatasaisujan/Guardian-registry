"""Participant trust: which institutions may join, and what each one may tell the registry.

Before v0.5 any API key could run payment checks, vouch for a customer's identity and
open SIM-swap windows. A registry that decides who can approve money for a 75-year-old
cannot take claims from just anyone, so:

  * Kind sets the ceiling. Every participant declares what kind of regulated entity it is
    (bank, NBFC, PPI issuer, UPI app, mobile operator...) and its regulator reference. The kind fixes the
    most it may ever be granted:
      - checks        ask the registry before moving a customer's money
      - kyc_full      vouch that a customer passed full KYC
      - kyc_minimum   vouch for minimum-KYC (small wallets)
      - sim_signals   report that a customer's SIM changed
      - number_lifecycle  report that a number was disconnected (telecom operators only)
    A UPI app does not hold the customer's KYC, so it can never vouch for identity.
  * Onboarding is four-eyes. An operator registers a participant as `pending`. It gets an
    API key at once so it can set up its webhook, but it can't call checks, KYC or
    signals until a DIFFERENT operator approves it.
  * Tightening is instant, loosening needs a second operator. Suspending a participant
    or removing a capability takes effect immediately. Reinstating it or adding a
    capability is a request that another operator must approve.
  * Trust follows status. While a participant is suspended its KYC claims stop counting
    (customers may drop back to 'otp' level). Offboarding is permanent: its keys stop
    working, its webhook is cleared, its KYC claims are revoked and customers are told.
    SIM-swap windows it opened stay open: they only ever protect.
  * Every operator action is audited under the operator's own name.
  * Registration numbers are checked against the official register. Operators load each
    regulator's published list (RBI's banks, NBFCs and PPI issuers, NPCI's UPI apps, DoT's
    telecom licensees) with load_regulated_entities. Once a list for a kind is loaded, a
    participant of that kind can only be registered, and approved, with a reference on it.
    In production a list is REQUIRED for the kind (GR_REQUIRE_ENTITY_REGISTER, on by default
    there), so nobody can join on a made-up number.
"""

from __future__ import annotations

import json
import os
import sqlite3

from . import notify
from .errors import Conflict, Forbidden, Invalid, NotFound
from .security import is_production, new_id, new_secret, secret_hash

CAPABILITIES = ("checks", "kyc_full", "kyc_minimum", "sim_signals", "number_lifecycle")

_BANK = frozenset({"checks", "kyc_full", "kyc_minimum", "sim_signals"})

# kind -> (most it may be granted, granted by default)
PARTICIPANT_KINDS: dict[str, tuple[frozenset, frozenset]] = {
    "bank":               (_BANK, _BANK),
    "small_finance_bank": (_BANK, _BANK),
    "payments_bank":      (_BANK, _BANK),
    "nbfc":               (frozenset({"checks", "kyc_full", "kyc_minimum"}),
                           frozenset({"checks", "kyc_full", "kyc_minimum"})),
    "ppi_issuer":         (frozenset({"checks", "kyc_full", "kyc_minimum"}),
                           frozenset({"checks", "kyc_minimum"})),
    "tpap":               (frozenset({"checks", "sim_signals"}), frozenset({"checks"})),
    # mobile operators: the source of SIM-swap, port-out and disconnection events (simfeed.py)
    "telecom":            (frozenset({"sim_signals", "number_lifecycle"}),
                           frozenset({"sim_signals", "number_lifecycle"})),
}

STATUSES = ("pending", "active", "suspended", "offboarded")


def register_required() -> bool:
    default = "1" if is_production() else "0"
    return os.environ.get("GR_REQUIRE_ENTITY_REGISTER", default) == "1"


def _sorted(caps) -> list[str]:
    return [c for c in CAPABILITIES if c in set(caps)]


class ParticipantMixin:
    """Mixed into Registry. Uses its db, clock, _audit and _alert helpers."""

    # ------------------------------------------------------------- helpers
    def _participant_row(self, pid: str) -> sqlite3.Row:
        r = self.db.one("SELECT * FROM participants WHERE id=?", (pid,))
        if not r:
            raise NotFound("participant not found")
        return r

    def _caps(self, r: sqlite3.Row) -> set[str]:
        return set(json.loads(r["capabilities"]))

    def participant_view(self, pid: str) -> dict:
        r = self._participant_row(pid)
        pending = None
        if r["pending_action"]:
            pending = {"action": r["pending_action"], "requested_by": r["pending_by"], "requested_at": r["pending_at"]}
            if r["pending_capabilities"]:
                pending["capabilities"] = json.loads(r["pending_capabilities"])
        allowed, _ = PARTICIPANT_KINDS.get(r["kind"], (frozenset(), frozenset()))
        return {
            "participant_id": r["id"], "name": r["name"], "kind": r["kind"],
            "regulator_ref": r["regulator_ref"], "status": r["status"],
            "status_reason": r["status_reason"], "status_changed_at": r["status_changed_at"],
            "capabilities": _sorted(self._caps(r)), "kind_allows": _sorted(allowed),
            "created_at": r["created_at"], "created_by": r["created_by"],
            "webhook_url": r["webhook_url"], "pending_request": pending,
            "register_match": self._safe_match(r["kind"], r["regulator_ref"]),
        }

    def _safe_match(self, kind: str, ref: str | None) -> dict | None:
        row = self.db.one("SELECT name, source, as_of FROM regulated_entities WHERE kind=? AND regulator_ref=?",
                          (kind, ref or ""))
        return dict(row) if row else None

    def list_participants(self, status: str | None = None) -> list[dict]:
        if status and status not in STATUSES:
            raise Invalid(f"status must be one of {list(STATUSES)}")
        rows = self.db.all("SELECT id FROM participants" + (" WHERE status=?" if status else "") +
                           " ORDER BY created_at", (status,) if status else ())
        return [self.participant_view(r["id"]) for r in rows]

    def _require_participant(self, pid: str, capability: str | None = None, *,
                             allow_suspended: bool = False) -> None:
        """Gate every bank-side action. Creating things needs `active` plus the capability;
        reading or closing out earlier work also works while suspended."""
        r = self._participant_row(pid)
        ok = ("active", "suspended") if allow_suspended else ("active",)
        if r["status"] not in ok:
            hint = " (awaiting operator approval)" if r["status"] == "pending" else ""
            raise Forbidden(f"participant is {r['status']}{hint}")
        if capability and capability not in self._caps(r):
            raise Forbidden(f"participant is not permitted to use '{capability}'")

    def _validate_caps(self, kind: str, caps) -> set[str]:
        caps = set(caps)
        unknown = caps - set(CAPABILITIES)
        if unknown:
            raise Invalid(f"unknown capabilities {sorted(unknown)}; choose from {list(CAPABILITIES)}")
        over = caps - PARTICIPANT_KINDS[kind][0]
        if over:
            raise Invalid(f"a {kind} may not be granted {_sorted(over)}")
        return caps

    def _participant_event(self, c: sqlite3.Connection, pid: str) -> None:
        notify.enqueue_participant(c, self._now(), pid, "participant.updated",
                                   {"participant": self._view_in_tx(c, pid)})

    def _view_in_tx(self, c: sqlite3.Connection, pid: str) -> dict:
        r = c.execute("SELECT status, status_reason, capabilities FROM participants WHERE id=?", (pid,)).fetchone()
        return {"participant_id": pid, "status": r["status"], "status_reason": r["status_reason"],
                "capabilities": _sorted(json.loads(r["capabilities"]))}

    # ------------------------------------------------------------- official register
    def load_regulated_entities(self, operator: str, kind: str, source: str, as_of: str,
                                entities: list[dict]) -> dict:
        """Replace the register for one kind with a regulator's published list."""
        if kind not in PARTICIPANT_KINDS:
            raise Invalid(f"kind must be one of {list(PARTICIPANT_KINDS)}")
        source, as_of = (source or "").strip(), (as_of or "").strip()
        if not source or not as_of:
            raise Invalid("source (where the list came from) and as_of (its date) are required")
        rows, seen = [], set()
        for e in entities:
            ref = str(e.get("regulator_ref") or "").strip()
            name = str(e.get("name") or "").strip()
            if not ref or not name:
                raise Invalid("every entity needs regulator_ref and name")
            if ref in seen:
                raise Invalid(f"duplicate regulator_ref {ref!r}")
            seen.add(ref)
            rows.append((kind, ref, name, source, as_of))
        if not rows:
            raise Invalid("entities must not be empty")
        with self.db.tx() as c:
            c.execute("DELETE FROM regulated_entities WHERE kind=?", (kind,))
            c.executemany("INSERT INTO regulated_entities VALUES (?,?,?,?,?)", rows)
            self._audit(c, f"operator:{operator}", "register.loaded", None, kind=kind, source=source,
                        as_of=as_of, entities=len(rows))
        return {"kind": kind, "entities": len(rows), "source": source, "as_of": as_of}

    def register_status(self) -> list[dict]:
        return [dict(r) for r in self.db.all(
            "SELECT kind, COUNT(*) AS entities, MAX(source) AS source, MAX(as_of) AS as_of "
            "FROM regulated_entities GROUP BY kind ORDER BY kind")]

    def _register_match(self, kind: str, ref: str | None) -> dict | None:
        """None if no list is loaded for the kind (and none is required); raises if the ref is
        missing from a loaded list."""
        has_list = self.db.one("SELECT 1 FROM regulated_entities WHERE kind=?", (kind,))
        if not has_list:
            if register_required():
                raise Invalid(f"no official register is loaded for kind {kind!r}; load one first")
            return None
        row = self.db.one("SELECT * FROM regulated_entities WHERE kind=? AND regulator_ref=?", (kind, ref or ""))
        if not row:
            src = self.db.one("SELECT source, as_of FROM regulated_entities WHERE kind=? LIMIT 1", (kind,))
            raise Invalid(f"regulator_ref {ref!r} is not on the {kind} register ({src['source']}, as of {src['as_of']})")
        return {"name": row["name"], "source": row["source"], "as_of": row["as_of"]}

    # ------------------------------------------------------------- onboarding
    def register_participant(self, name: str, kind: str = "bank", regulator_ref: str | None = None,
                             capabilities=None, *, operator: str = "admin",
                             activate: bool = True) -> tuple[str, str]:
        """Register a bank or payment app. Returns (participant_id, api_key); the key is shown once.

        The HTTP API always passes activate=False so a second operator must approve.
        activate=True is for tests and back-office scripts only."""
        name = (name or "").strip()
        if not name:
            raise Invalid("name is required")
        if kind not in PARTICIPANT_KINDS:
            raise Invalid(f"kind must be one of {list(PARTICIPANT_KINDS)}")
        regulator_ref = (regulator_ref or "").strip() or None
        caps = self._validate_caps(kind, PARTICIPANT_KINDS[kind][1] if capabilities is None else capabilities)
        if not activate or regulator_ref:  # the API path always checks; back-office scripts may skip
            self._register_match(kind, regulator_ref)
        if self.db.one("SELECT 1 FROM participants WHERE name=?", (name,)):
            raise Conflict("participant already registered")
        if regulator_ref and self.db.one("SELECT 1 FROM participants WHERE regulator_ref=?", (regulator_ref,)):
            raise Conflict("a participant with this regulator reference is already registered")
        pid, key = new_id("prt"), new_secret("grk")
        status = "active" if activate else "pending"
        now = self._now()
        with self.db.tx() as c:
            c.execute(
                "INSERT INTO participants (id, name, key_hash, created_at, kind, regulator_ref, status, "
                "capabilities, status_changed_at, created_by, pending_action, pending_by, pending_at) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (pid, name, secret_hash(key), now, kind, regulator_ref, status, json.dumps(_sorted(caps)),
                 now, operator, None if activate else "activate", None if activate else operator,
                 None if activate else now))
            self._audit(c, f"operator:{operator}", "participant.registered", None, participant_id=pid, name=name,
                        kind=kind, regulator_ref=regulator_ref, capabilities=_sorted(caps), status=status)
        return pid, key

    def _set_pending(self, c: sqlite3.Connection, pid: str, action: str, operator: str,
                     caps: set[str] | None = None) -> None:
        c.execute("UPDATE participants SET pending_action=?, pending_capabilities=?, pending_by=?, pending_at=? "
                  "WHERE id=?", (action, json.dumps(_sorted(caps)) if caps is not None else None,
                                 operator, self._now(), pid))

    def _clear_pending(self, c: sqlite3.Connection, pid: str) -> None:
        c.execute("UPDATE participants SET pending_action=NULL, pending_capabilities=NULL, pending_by=NULL, "
                  "pending_at=NULL WHERE id=?", (pid,))

    def approve_participant_request(self, operator: str, pid: str, *, allow_self: bool = False) -> dict:
        """Second operator signs off a pending activation, reinstatement or capability grant."""
        r = self._participant_row(pid)
        action = r["pending_action"]
        if not action:
            raise Conflict("nothing is waiting for approval")
        if r["pending_by"] == operator and not allow_self:
            raise Forbidden("a different operator must approve this (four-eyes rule)")
        if r["status"] == "offboarded":
            raise Conflict("participant is offboarded")
        if action in ("activate", "reinstate"):
            self._register_match(r["kind"], r["regulator_ref"])  # still on the register?
        with self.db.tx() as c:
            if action in ("activate", "reinstate"):
                c.execute("UPDATE participants SET status='active', status_reason=NULL, status_changed_at=? "
                          "WHERE id=?", (self._now(), pid))
            elif action == "grant":
                caps = self._caps(r) | set(json.loads(r["pending_capabilities"]))
                caps = self._validate_caps(r["kind"], caps)  # the kind's ceiling still applies
                c.execute("UPDATE participants SET capabilities=? WHERE id=?", (json.dumps(_sorted(caps)), pid))
            self._clear_pending(c, pid)
            self._audit(c, f"operator:{operator}", f"participant.{action}_approved", None, participant_id=pid,
                        requested_by=r["pending_by"], self_approved=r["pending_by"] == operator)
            self._participant_event(c, pid)
        return self.participant_view(pid)

    def reject_participant_request(self, operator: str, pid: str) -> dict:
        """Any operator (including the requester) may drop a pending request."""
        r = self._participant_row(pid)
        if not r["pending_action"]:
            raise Conflict("nothing is waiting for approval")
        with self.db.tx() as c:
            self._clear_pending(c, pid)
            self._audit(c, f"operator:{operator}", f"participant.{r['pending_action']}_rejected", None,
                        participant_id=pid, requested_by=r["pending_by"])
        return self.participant_view(pid)

    # ------------------------------------------------------------- tightening
    def suspend_participant(self, operator: str, pid: str, reason: str) -> dict:
        """Stop a participant at once (key leak, regulator action, bad data). Its KYC claims
        stop counting until it is reinstated."""
        reason = (reason or "").strip()
        if not reason:
            raise Invalid("reason is required")
        r = self._participant_row(pid)
        if r["status"] in ("suspended", "offboarded"):
            raise Conflict(f"participant is already {r['status']}")
        with self.db.tx() as c:
            c.execute("UPDATE participants SET status='suspended', status_reason=?, status_changed_at=? WHERE id=?",
                      (reason, self._now(), pid))
            if r["pending_action"] in ("activate", "grant"):
                self._clear_pending(c, pid)
            self._audit(c, f"operator:{operator}", "participant.suspended", None, participant_id=pid,
                        reason=reason, previous_status=r["status"])
            self._participant_event(c, pid)
        return self.participant_view(pid)

    def request_reinstatement(self, operator: str, pid: str) -> dict:
        r = self._participant_row(pid)
        if r["status"] != "suspended":
            raise Conflict(f"only a suspended participant can be reinstated (this one is {r['status']})")
        with self.db.tx() as c:
            self._set_pending(c, pid, "reinstate", operator)
            self._audit(c, f"operator:{operator}", "participant.reinstate_requested", None, participant_id=pid)
        return self.participant_view(pid)

    def set_participant_capabilities(self, operator: str, pid: str, capabilities) -> dict:
        """Set the full capability list. Removals apply at once; additions wait for a
        second operator."""
        r = self._participant_row(pid)
        if r["status"] == "offboarded":
            raise Conflict("participant is offboarded")
        wanted = self._validate_caps(r["kind"], capabilities)
        current = self._caps(r)
        removed, added = current - wanted, wanted - current
        with self.db.tx() as c:
            if removed:
                c.execute("UPDATE participants SET capabilities=? WHERE id=?",
                          (json.dumps(_sorted(current - removed)), pid))
                self._audit(c, f"operator:{operator}", "participant.capabilities_removed", None,
                            participant_id=pid, removed=_sorted(removed))
                self._participant_event(c, pid)
            if r["pending_action"] == "grant":
                self._clear_pending(c, pid)  # superseded by this request
            if added:
                self._set_pending(c, pid, "grant", operator, added)
                self._audit(c, f"operator:{operator}", "participant.grant_requested", None,
                            participant_id=pid, added=_sorted(added))
        return self.participant_view(pid)

    def offboard_participant(self, operator: str, pid: str, reason: str) -> dict:
        """Permanent exit. Keys and webhook are wiped and every live KYC claim is revoked."""
        reason = (reason or "").strip()
        if not reason:
            raise Invalid("reason is required")
        r = self._participant_row(pid)
        if r["status"] == "offboarded":
            raise Conflict("participant is already offboarded")
        now = self._now()
        with self.db.tx() as c:
            c.execute("UPDATE participants SET status='offboarded', status_reason=?, status_changed_at=?, "
                      "key_hash=?, prev_key_hash=NULL, prev_key_expires_at=NULL, webhook_url=NULL, "
                      "webhook_secret=NULL, pending_action=NULL, pending_capabilities=NULL, pending_by=NULL, "
                      "pending_at=NULL WHERE id=?",
                      (reason, now, secret_hash(new_secret("void")), pid))
            live = c.execute("SELECT id, user_id, status FROM kyc_attestations WHERE participant_id=? "
                             "AND status IN ('pending_consent','active')", (pid,)).fetchall()
            for a in live:
                c.execute("UPDATE kyc_attestations SET status='revoked', decided_at=?, ended_by=? WHERE id=?",
                          (now, f"operator:{operator}", a["id"]))
                self._audit(c, f"operator:{operator}", "kyc.revoked", a["user_id"], attestation_id=a["id"],
                            reason="participant offboarded")
                if a["status"] == "active":
                    self._alert(c, [a["user_id"]], "kyc_revoked", "Bank verification removed",
                                f"{r['name']} has left Guardian Registry, so its confirmation of your identity "
                                "no longer counts.", a["user_id"], attestation_id=a["id"])
            c.execute("DELETE FROM notifications WHERE recipient_type='participant' AND recipient_id=? "
                      "AND status='pending'", (pid,))
            self._audit(c, f"operator:{operator}", "participant.offboarded", None, participant_id=pid,
                        reason=reason, kyc_revoked=len(live))
        return self.participant_view(pid)
