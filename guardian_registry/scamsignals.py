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
  * much larger than usual: at least large_multiple times their largest payment in the last
    90 days (with at least min_prior earlier payments) and at least large_min;
  * a burst of new payees: this is the burst_count-th new payee within 24 hours;
  * a request to loosen protection or switch payments back on is still waiting: a classic
    "turn that off so the money can go" script;
  * a payment of large_min or more at night (IST, night_start to night_end).

Tuning
------
The thresholds above are settings (DEFAULT_SETTINGS), changed by one operator and approved by
another. The features behind them are recorded on every protected payment, even when the
person's rule is off (shadow mode), and banks label outcomes (fraud or genuine). tuning_report
then shows each signal's precision and recall, a what-if grid of alternative thresholds, and
suggestions that keep the hold rate under a budget, so thresholds follow real fraud data.
"""

from __future__ import annotations

import json
from datetime import timedelta, timezone

from .clock import iso
from .errors import Conflict, Invalid, NotFound

REPORT_DAYS = 180
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
    # Features are measured on EVERY protected payment (shadow mode) and stored with the check,
    # whether or not the person's rule is on; only the decision depends on the rule. That is
    # what lets the thresholds be tuned on real outcomes (tuning_report) instead of guessed.

    def _risk_features(self, c, principal_id: str, amount: int, payee: str, payee_known: bool) -> dict:
        now = self.clock.now()
        prior = [r["amount"] for r in c.execute(
            "SELECT amount FROM checks WHERE principal_id=? AND created_at>? AND status IN "
            "('allowed','approved','released')", (principal_id, iso(now - timedelta(days=90)))).fetchall()]
        largest = max(prior) if prior else None
        new_payees = 0
        if not payee_known:
            recent = c.execute("SELECT DISTINCT payee FROM checks WHERE principal_id=? AND created_at>? AND payee<>?",
                               (principal_id, iso(now - timedelta(hours=24)), payee)).fetchall()
            new_payees = 1 + sum(1 for r in recent if not self._payee_known_before(
                c, principal_id, r["payee"], now - timedelta(hours=24)))
        loosen = bool(c.execute("SELECT 1 FROM pending_changes WHERE principal_id=? AND status='pending' AND kind IN "
                                "('update_rules','kill_switch_off','remove_guardian') LIMIT 1", (principal_id,)).fetchone())
        return {"amount": amount, "prior_count": len(prior), "largest_prior": largest,
                "ratio": round(amount / largest, 3) if largest else None, "new_payee": not payee_known,
                "new_payees_24h": new_payees, "loosen_pending": loosen, "local_hour": now.astimezone(IST).hour}

    def _payee_known_before(self, c, principal_id: str, payee: str, before) -> bool:
        if c.execute("SELECT 1 FROM trusted_payees WHERE principal_id=? AND payee=?", (principal_id, payee)).fetchone():
            return True
        return bool(c.execute("SELECT 1 FROM checks WHERE principal_id=? AND payee=? AND created_at<=? AND "
                              "completed_at IS NOT NULL LIMIT 1", (principal_id, payee, iso(before))).fetchone())

    # ------------------------------------------------------------- settings (four-eyes)
    def active_signal_settings(self) -> dict:
        r = self.db.one("SELECT settings FROM signal_settings WHERE status='active' ORDER BY decided_at DESC LIMIT 1")
        return {**DEFAULT_SETTINGS, **(json.loads(r["settings"]) if r else {})}

    def signal_settings_view(self) -> dict:
        p = self.db.one("SELECT * FROM signal_settings WHERE status='pending' ORDER BY proposed_at DESC LIMIT 1")
        return {"active": self.active_signal_settings(), "defaults": DEFAULT_SETTINGS,
                "pending": None if not p else {"id": p["id"], "settings": json.loads(p["settings"]),
                                               "proposed_by": p["proposed_by"], "proposed_at": p["proposed_at"],
                                               "reason": p["reason"]}}

    def propose_signal_settings(self, operator: str, changes: dict, reason: str) -> dict:
        unknown = set(changes) - set(DEFAULT_SETTINGS)
        if unknown:
            raise Invalid(f"unknown settings: {sorted(unknown)}")
        new = {**self.active_signal_settings(), **changes}
        _validate_settings(new)
        if not (reason or "").strip():
            raise Invalid("reason is required (e.g. which tuning report this follows)")
        from .security import new_id
        with self.db.tx() as c:
            c.execute("UPDATE signal_settings SET status='replaced', decided_at=? WHERE status='pending'", (self._now(),))
            c.execute("INSERT INTO signal_settings (id, settings, status, reason, proposed_by, proposed_at) "
                      "VALUES (?,?,?,?,?,?)", (new_id("sig"), json.dumps(new), "pending", reason.strip()[:500],
                                               operator, self._now()))
            self._audit(c, f"operator:{operator}", "signals.settings_proposed", None, settings=new)
        return self.signal_settings_view()

    def decide_signal_settings(self, operator: str, approve: bool, allow_self: bool = False) -> dict:
        p = self.db.one("SELECT * FROM signal_settings WHERE status='pending' ORDER BY proposed_at DESC LIMIT 1")
        if not p:
            raise Conflict("no settings change is waiting")
        if approve and p["proposed_by"] == operator and not allow_self:
            raise Conflict("a second operator must approve a change to the scam-signal thresholds (four-eyes)")
        with self.db.tx() as c:
            if approve:
                c.execute("UPDATE signal_settings SET status='superseded' WHERE status='active'")
            if not c.execute("UPDATE signal_settings SET status=?, decided_by=?, decided_at=? WHERE id=? AND "
                             "status='pending'", ("active" if approve else "rejected", operator, self._now(),
                                                  p["id"])).rowcount:
                raise Conflict("this change was already decided")
            self._audit(c, f"operator:{operator}", "signals.settings_" + ("approved" if approve else "rejected"),
                        None, settings=json.loads(p["settings"]), proposed_by=p["proposed_by"])
        return self.signal_settings_view()

    # ------------------------------------------------------------- outcome labels
    def label_check(self, actor: str, cid: str, fraud: bool, note: str | None = None,
                    participant_id: str | None = None) -> dict:
        """Mark a payment as confirmed fraud or genuine, once the bank knows. Feeds tuning_report."""
        r = self.db.one("SELECT principal_id, participant_id FROM checks WHERE id=?", (cid,))
        if not r or (participant_id and r["participant_id"] != participant_id):
            raise NotFound("check not found")
        label = "fraud" if fraud else "genuine"
        with self.db.tx(r["principal_id"]) as c:
            c.execute("UPDATE checks SET fraud_label=?, fraud_labelled_by=?, fraud_labelled_at=? WHERE id=?",
                      (label, actor, self._now(), cid))
            self._audit(c, actor, "check.labelled", r["principal_id"], check_id=cid, label=label,
                        **({"note": note.strip()[:200]} if note and note.strip() else {}))
        return {"check_id": cid, "label": label}

    # ------------------------------------------------------------- tuning report
    def tuning_report(self, days: int = 90, max_hold_rate: float = 0.05) -> dict:
        since = iso(self.clock.now() - timedelta(days=days))
        rows = self.db.all("SELECT amount, status, features, fraud_label, completed_at FROM checks "
                           "WHERE created_at>? AND features IS NOT NULL", (since,))
        data = [(json.loads(r["features"]), r["fraud_label"], r) for r in rows]
        total = len(data)
        frauds = sum(1 for _, lab, _ in data if lab == "fraud")
        labelled = sum(1 for _, lab, _ in data if lab)
        current = self.active_signal_settings()

        def score(settings: dict, only: str | None = None) -> dict:
            fired = hits = fired_lab = 0
            for f, lab, _ in data:
                codes = [code for code, _ in signals_from(f, settings)]
                if only:
                    codes = [x for x in codes if x == only]
                if codes:
                    fired += 1
                    if lab:
                        fired_lab += 1
                    if lab == "fraud":
                        hits += 1
            return {"held": fired, "hold_rate": _ratio(fired, total), "fraud_caught": hits,
                    "precision": _ratio(hits, fired_lab), "recall": _ratio(hits, frauds)}

        per_signal = {code: score(current, only=code) for code in SIGNAL_CODES}
        grid = {}
        for key, candidates in GRID.items():
            grid[key] = [{"value": v, **score({**current, key: v})} for v in candidates]
        suggestions = []
        enough = frauds >= MIN_LABELLED_FRAUD
        if enough:
            for key, rows_ in grid.items():
                ok = [x for x in rows_ if x["hold_rate"] is not None and x["hold_rate"] <= max_hold_rate]
                best = max(ok, key=lambda x: (_f1(x), -x["hold_rate"]), default=None)
                if best and best["value"] != current[key] and _f1(best) > _f1(next(
                        (x for x in rows_ if x["value"] == current[key]), {"precision": 0, "recall": 0})):
                    suggestions.append({"setting": key, "from": current[key], "to": best["value"],
                                        "precision": best["precision"], "recall": best["recall"],
                                        "hold_rate": best["hold_rate"]})
        stopped = ("denied", "cancelled", "expired", "blocked")
        impact = {
            "checks": total,
            "held_for_review": sum(1 for _, _, r in data if r["status"] not in ("allowed", "blocked")),
            "stopped": sum(1 for _, _, r in data if r["status"] in stopped),
            "amount_stopped": sum(r["amount"] for _, _, r in data if r["status"] in stopped),
            "confirmed_fraud_stopped": sum(1 for _, lab, r in data if lab == "fraud" and r["status"] in stopped),
            "confirmed_fraud_that_went_through": sum(1 for _, lab, r in data if lab == "fraud" and r["completed_at"]),
        }
        return {"days": days, "checks": total, "labelled": labelled, "confirmed_fraud": frauds,
                "settings": current, "all_signals": score(current), "per_signal": per_signal,
                "what_if": grid, "max_hold_rate": max_hold_rate, "suggestions": suggestions,
                "enough_data": enough,
                "note": None if enough else (f"Suggestions need at least {MIN_LABELLED_FRAUD} payments labelled as "
                                             f"confirmed fraud in the window; there are {frauds}. Ask partner banks "
                                             "to label outcomes (POST /v1/checks/{id}/fraud-label)."),
                "impact": impact}


DEFAULT_SETTINGS = {
    "large_multiple": 3.0,      # x the largest payment in 90 days
    "large_min": 5_000 * 100,   # paise; below this, size and night-time don't count
    "min_prior": 3,             # earlier payments needed before "unusual size" can fire
    "burst_count": 3,           # this many new payees within 24 h
    "night_start": 0,           # local hour (IST), inclusive
    "night_end": 5,             # local hour, exclusive
}
SIGNAL_CODES = ("much_larger", "payee_burst", "loosen_pending", "night")
GRID = {
    "large_multiple": [2.0, 2.5, 3.0, 4.0, 5.0],
    "large_min": [2_000 * 100, 5_000 * 100, 10_000 * 100, 25_000 * 100],
    "burst_count": [2, 3, 4, 5],
    "night_end": [4, 5, 6],
}
MIN_LABELLED_FRAUD = 20


def _validate_settings(s: dict) -> None:
    if not 1.5 <= float(s["large_multiple"]) <= 20:
        raise Invalid("large_multiple must be between 1.5 and 20")
    if not 100 * 100 <= int(s["large_min"]) <= 10_00_000 * 100:
        raise Invalid("large_min must be between ₹100 and ₹10,00,000 (in paise)")
    if not 1 <= int(s["min_prior"]) <= 50:
        raise Invalid("min_prior must be between 1 and 50")
    if not 2 <= int(s["burst_count"]) <= 20:
        raise Invalid("burst_count must be between 2 and 20")
    if not (0 <= int(s["night_start"]) < int(s["night_end"]) <= 12):
        raise Invalid("night hours must satisfy 0 <= night_start < night_end <= 12")


def signals_from(f: dict, s: dict) -> list[tuple[str, str]]:
    """(code, reason) for each pattern the features show under settings `s`."""
    out = []
    amount = f["amount"]
    if (f["prior_count"] >= s["min_prior"] and f.get("largest_prior") and amount >= s["large_min"]
            and amount >= s["large_multiple"] * f["largest_prior"]):
        out.append(("much_larger", f"much larger than this person's usual payments (largest in 90 days: "
                                   f"{_rupees(f['largest_prior'])})"))
    if f["new_payee"] and f["new_payees_24h"] >= s["burst_count"]:
        out.append(("payee_burst", f"{f['new_payees_24h']} new payees in 24 hours"))
    if f["loosen_pending"]:
        out.append(("loosen_pending", "a request to loosen protection is waiting"))
    if amount >= s["large_min"] and s["night_start"] <= f["local_hour"] < s["night_end"]:
        out.append(("night", f"a large payment at night ({s['night_start']:02d}:00 to {s['night_end']:02d}:00)"))
    return out


def _ratio(a: int, b: int):
    return round(a / b, 3) if b else None


def _f1(x: dict) -> float:
    p, r = x.get("precision") or 0, x.get("recall") or 0
    return 2 * p * r / (p + r) if p + r else 0.0


def _rupees(paise: int) -> str:
    return f"₹{paise / 100:,.2f}"


__all__ = ["ScamSignalsMixin", "norm_payee", "json", "Conflict"]
