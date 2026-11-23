"""Shared scam signals: what one bank learns about a fraud protects everyone's customers.

Cross-bank payee watchlist
--------------------------
A participant with the `checks` capability that has CONFIRMED a fraud (the customer
reported it and the bank investigated) reports the payee it went to:
    POST /v1/signals/fraud-payees  {"payee", "reason", "evidence_ref"}
  * one bank's report        -> "reported": payments by protected people to that payee are
    held for a guardian (or wait REPORTED_PAYEE_DELAY_MINUTES with no guardian);
  * two or more banks, or an operator's confirmation -> "confirmed": such payments are
    blocked;
  * an operator can clear a payee (an innocent merchant reported by mistake): reports made
    before the clearance stop counting; later reports count again.
Reports expire after REPORT_DAYS, a bank can withdraw its own, and every step is audited.
Banks learn only the status of a payee they ask about, never who reported it. Payees are
compared after trimming and lower-casing (UPI IDs are case-insensitive).

Coaching patterns
-----------------
Patterns that show up when someone is being talked through a payment by a scammer. They
hold the payment for a guardian (they never block) when the person's rule scam_signals is
on, which the senior and strict presets turn on:
  * much larger than usual: at least LARGE_MULTIPLE times their largest payment in the last
    90 days (with at least 3 earlier payments) and at least LARGE_MIN;
  * a burst of new payees: this is the BURST_COUNT-th new payee within 24 hours;
  * a request to loosen protection or switch payments back on is still waiting: a classic
    "turn that off so the money can go" script;
  * a payment of LARGE_MIN or more between midnight and 5 am IST.
"""

from __future__ import annotations

import json
from datetime import timedelta, timezone

from .clock import iso
from .errors import Conflict, Invalid, NotFound

REPORT_DAYS = 180
LARGE_MULTIPLE = 3
LARGE_MIN = 5_000 * 100      # paise
BURST_COUNT = 3
IST = timezone(timedelta(hours=5, minutes=30))


def norm_payee(payee: str) -> str:
    p = (payee or "").strip().lower()
    if not p or len(p) > 200:
        raise Invalid("payee is required (max 200 characters)")
    return p


class ScamSignalsMixin:
    """Mixed into Registry."""

    # ------------------------------------------------------------- watchlist
    def report_fraud_payee(self, participant_id: str, payee: str, reason: str, evidence_ref: str | None = None) -> dict:
        self._require_participant(participant_id, "checks")
        p = norm_payee(payee)
        reason = (reason or "").strip()
        if not reason:
            raise Invalid("reason is required: what happened, in a sentence")
        now = self.clock.now()
        with self.db.tx() as c:
            c.execute("UPDATE payee_reports SET withdrawn_at=? WHERE payee=? AND participant_id=? AND withdrawn_at IS NULL",
                      (iso(now), p, participant_id))  # one live report per bank per payee: the latest
            c.execute("INSERT INTO payee_reports (id, payee, participant_id, reason, evidence_ref, reported_at, expires_at) "
                      "VALUES (?,?,?,?,?,?,?)", (self._new_report_id(), p, participant_id, reason[:500],
                                                 (evidence_ref or "")[:100] or None, iso(now),
                                                 iso(now + timedelta(days=REPORT_DAYS))))
            self._audit(c, participant_id, "watchlist.reported", None, payee=p)
        return self.payee_status(p)

    def _new_report_id(self) -> str:
        from .security import new_id
        return new_id("rpt")

    def withdraw_fraud_report(self, participant_id: str, payee: str) -> dict:
        self._require_participant(participant_id, allow_suspended=True)
        p = norm_payee(payee)
        with self.db.tx() as c:
            if not c.execute("UPDATE payee_reports SET withdrawn_at=? WHERE payee=? AND participant_id=? "
                             "AND withdrawn_at IS NULL", (self._now(), p, participant_id)).rowcount:
                raise NotFound("you have no live report for this payee")
            self._audit(c, participant_id, "watchlist.withdrawn", None, payee=p)
        return self.payee_status(p)

    def operator_watch_decision(self, operator: str, payee: str, decision: str, reason: str) -> dict:
        if decision not in ("confirmed", "cleared"):
            raise Invalid("decision must be confirmed or cleared")
        reason = (reason or "").strip()
        if not reason:
            raise Invalid("reason is required")
        p = norm_payee(payee)
        with self.db.tx() as c:
            c.execute("INSERT INTO payee_decisions (payee, decision, operator, reason, decided_at) VALUES (?,?,?,?,?) "
                      "ON CONFLICT(payee) DO UPDATE SET decision=excluded.decision, operator=excluded.operator, "
                      "reason=excluded.reason, decided_at=excluded.decided_at",
                      (p, decision, operator, reason[:500], self._now()))
            self._audit(c, f"operator:{operator}", f"watchlist.{decision}", None, payee=p, reason=reason[:200])
        return self.payee_status(p)

    def _watch(self, c, payee: str) -> str | None:
        """None, "reported" or "confirmed" (inside a transaction)."""
        try:
            p = norm_payee(payee)
        except Invalid:
            return None
        d = c.execute("SELECT decision, decided_at FROM payee_decisions WHERE payee=?", (p,)).fetchone()
        if d and d["decision"] == "confirmed":
            return "confirmed"
        since = d["decided_at"] if d else ""  # a clearance wipes the reports made before it
        n = c.execute("SELECT COUNT(DISTINCT participant_id) n FROM payee_reports r JOIN participants p "
                      "ON p.id=r.participant_id WHERE r.payee=? AND r.withdrawn_at IS NULL AND r.expires_at>? "
                      "AND r.reported_at>? AND p.status='active'", (p, self._now(), since)).fetchone()["n"]
        return "confirmed" if n >= 2 else "reported" if n == 1 else None

    def payee_status(self, payee: str) -> dict:
        """What a bank may learn: the status and how many banks, never which."""
        p = norm_payee(payee)
        with self.db.tx(shared=True) as c:
            status = self._watch(c, p)
            banks = c.execute("SELECT COUNT(DISTINCT participant_id) n FROM payee_reports WHERE payee=? "
                              "AND withdrawn_at IS NULL AND expires_at>?", (p, self._now())).fetchone()["n"]
        return {"payee": p, "status": status or "none", "reporting_banks": banks}

    def watchlist(self, limit: int = 200) -> list[dict]:
        """For operators: every payee with live reports or a decision."""
        rows = self.db.all(
            "SELECT payee FROM payee_reports WHERE withdrawn_at IS NULL AND expires_at>? "
            "UNION SELECT payee FROM payee_decisions ORDER BY payee LIMIT ?", (self._now(), limit))
        out = []
        for r in rows:
            st = self.payee_status(r["payee"])
            d = self.db.one("SELECT decision, operator, reason, decided_at FROM payee_decisions WHERE payee=?",
                            (r["payee"],))
            reports = self.db.all("SELECT p.name, r.reason, r.evidence_ref, r.reported_at FROM payee_reports r "
                                  "JOIN participants p ON p.id=r.participant_id WHERE r.payee=? "
                                  "AND r.withdrawn_at IS NULL AND r.expires_at>? ORDER BY r.reported_at",
                                  (r["payee"], self._now()))
            out.append({**st, "operator_decision": dict(d) if d else None, "reports": [dict(x) for x in reports]})
        return out

    # ------------------------------------------------------------- coaching patterns
    def _risk_signals(self, c, principal_id: str, amount: int, payee: str, payee_known: bool) -> list[str]:
        now = self.clock.now()
        out = []
        prior = c.execute("SELECT amount FROM checks WHERE principal_id=? AND created_at>? AND status IN "
                          "('allowed','approved','released')", (principal_id, iso(now - timedelta(days=90)))).fetchall()
        if len(prior) >= 3 and amount >= LARGE_MIN and amount >= LARGE_MULTIPLE * max(r["amount"] for r in prior):
            out.append(f"much larger than this person's usual payments (largest in 90 days: "
                       f"{_rupees(max(r['amount'] for r in prior))})")
        if not payee_known:
            recent = c.execute("SELECT DISTINCT payee FROM checks WHERE principal_id=? AND created_at>? AND payee<>?",
                               (principal_id, iso(now - timedelta(hours=24)), payee)).fetchall()
            new_ones = [r["payee"] for r in recent if not self._payee_known_before(c, principal_id, r["payee"],
                                                                                  now - timedelta(hours=24))]
            if len(new_ones) + 1 >= BURST_COUNT:
                out.append(f"{len(new_ones) + 1} new payees in 24 hours")
        pending = c.execute("SELECT kind, payload FROM pending_changes WHERE principal_id=? AND status='pending'",
                            (principal_id,)).fetchall()
        if any(p["kind"] in ("update_rules", "kill_switch_off", "remove_guardian") for p in pending):
            out.append("a request to loosen protection is waiting")
        local = now.astimezone(IST)
        if amount >= LARGE_MIN and local.hour < 5:
            out.append("a large payment between midnight and 5 am")
        return out

    def _payee_known_before(self, c, principal_id: str, payee: str, before) -> bool:
        if c.execute("SELECT 1 FROM trusted_payees WHERE principal_id=? AND payee=?", (principal_id, payee)).fetchone():
            return True
        return bool(c.execute("SELECT 1 FROM checks WHERE principal_id=? AND payee=? AND created_at<=? AND "
                              "completed_at IS NOT NULL LIMIT 1", (principal_id, payee, iso(before))).fetchone())


def _rupees(paise: int) -> str:
    return f"₹{paise / 100:,.2f}"


__all__ = ["ScamSignalsMixin", "norm_payee", "json", "Conflict"]
