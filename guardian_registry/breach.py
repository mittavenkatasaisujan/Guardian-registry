"""Personal-data breach response (DPDP Act, 2023 and its Rules).

When personal data may have been exposed, a data fiduciary must tell each affected person
without delay, in plain language (what happened, when, what may be affected, what they can do,
who to contact), and send the Data Protection Board a detailed report within 72 hours.

  1. An operator records the incident: what was found, when, the window it covers, which kinds
     of data, cause and containment so far (POST /v1/admin/incidents).
  2. The affected people are worked out from the scope: everyone whose record existed during
     the window ("window"), everyone ("all"), or a given list of accounts ("users").
  3. Notifying is proposed by one operator and sent once a second approves (a mass SMS is not
     something one person should be able to trigger). Each person gets an urgent alert (in-app,
     SMS / WhatsApp and push) in their own language. The wording is fixed per data category,
     with concrete steps, so it can be translated and never leaks one operator's draft.
  4. The Board report (GET .../board-report) gathers what Rule 7 asks for: the facts, timing,
     categories, people affected, cause, containment and remedial measures, the notifications
     sent, and the 72-hour deadline (marked overdue if missed). Filing it is recorded with the
     Board's reference.
Every step is in the audit chain.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta

from .clock import iso
from .errors import Conflict, Invalid, NotFound

BOARD_HOURS = 72
CATEGORIES = {
    # code: (what, what you can do)
    "mobile_numbers": ("your mobile number",
                       "be careful with calls and messages that claim to be from us or your bank"),
    "names": ("your name", "expect scam calls that use your name to sound genuine"),
    "dates_of_birth": ("your date of birth", "never confirm your date of birth to a caller"),
    "payment_history": ("your payment history", "check your recent payments in the app"),
    "sign_in_sessions": ("your sign-in sessions", "sign out everywhere in the app and sign in again"),
    "device_data": ("data about your phone", "ignore unexpected messages asking you to install apps or share codes"),
}
SCOPES = ("window", "all", "users")


def _parse(ts: str, what: str) -> str:
    try:
        d = datetime.fromisoformat(ts)
    except (TypeError, ValueError):
        raise Invalid(f"{what} must be an ISO 8601 time") from None
    if d.tzinfo is None:
        raise Invalid(f"{what} must include a timezone")
    return iso(d)


class BreachMixin:
    """Mixed into Registry."""

    def record_incident(self, operator: str, title: str, description: str, detected_at: str,
                        occurred_from: str, occurred_to: str, categories: list[str], cause: str = "",
                        containment: str = "", scope: str = "window", user_ids: list[str] | None = None) -> dict:
        if not (title or "").strip() or not (description or "").strip():
            raise Invalid("title and description are required")
        bad = sorted(set(categories or []) - set(CATEGORIES))
        if not categories or bad:
            raise Invalid(f"categories must be some of {sorted(CATEGORIES)}")
        if scope not in SCOPES:
            raise Invalid(f"scope must be one of {list(SCOPES)}")
        if scope == "users" and not user_ids:
            raise Invalid("scope 'users' needs user_ids")
        d, f, t = (_parse(detected_at, "detected_at"), _parse(occurred_from, "occurred_from"),
                   _parse(occurred_to, "occurred_to"))
        if f > t:
            raise Invalid("occurred_from must be before occurred_to")
        from .security import new_id
        iid = new_id("inc")
        with self.db.tx() as c:
            c.execute(
                "INSERT INTO incidents (id, title, description, cause, containment, categories, detected_at, "
                "occurred_from, occurred_to, scope, user_ids, status, created_by, created_at) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (iid, title.strip()[:200], description.strip()[:5000], (cause or "").strip()[:5000],
                 (containment or "").strip()[:5000], json.dumps(sorted(set(categories))), d, f, t, scope,
                 json.dumps(sorted(set(user_ids or []))), "open", operator, self._now()))
            self._audit(c, f"operator:{operator}", "incident.recorded", None, incident_id=iid,
                        categories=sorted(set(categories)), scope=scope)
        return self.incident(iid)

    def update_incident(self, operator: str, iid: str, cause: str | None = None, containment: str | None = None,
                        remediation: str | None = None) -> dict:
        self._incident_row(iid)
        with self.db.tx() as c:
            for col, val in (("cause", cause), ("containment", containment), ("remediation", remediation)):
                if val is not None:
                    c.execute(f"UPDATE incidents SET {col}=? WHERE id=?", (val.strip()[:5000], iid))  # nosec B608: fixed column names
            self._audit(c, f"operator:{operator}", "incident.updated", None, incident_id=iid)
        return self.incident(iid)

    def _incident_row(self, iid: str):
        r = self.db.one("SELECT * FROM incidents WHERE id=?", (iid,))
        if not r:
            raise NotFound("incident not found")
        return r

    def _affected(self, r) -> list[str]:
        if r["scope"] == "users":
            ids = json.loads(r["user_ids"])
            return [x["id"] for x in self.db.all(
                f"SELECT id FROM users WHERE erased_at IS NULL AND id IN ({','.join('?' * len(ids))})", ids)]  # nosec B608: placeholders only
        if r["scope"] == "all":
            return [x["id"] for x in self.db.all("SELECT id FROM users WHERE erased_at IS NULL ORDER BY id")]
        return [x["id"] for x in self.db.all(  # records that existed at some point in the window
            "SELECT id FROM users WHERE erased_at IS NULL AND created_at<=? ORDER BY id", (r["occurred_to"],))]

    def incident(self, iid: str) -> dict:
        r = self._incident_row(iid)
        deadline = iso(datetime.fromisoformat(r["detected_at"]) + timedelta(hours=BOARD_HOURS))
        return {"id": r["id"], "title": r["title"], "description": r["description"], "cause": r["cause"],
                "containment": r["containment"], "remediation": r["remediation"],
                "categories": json.loads(r["categories"]), "detected_at": r["detected_at"],
                "occurred_from": r["occurred_from"], "occurred_to": r["occurred_to"], "scope": r["scope"],
                "status": r["status"], "created_by": r["created_by"], "affected_people": len(self._affected(r)),
                "notify": {"proposed_by": r["notify_proposed_by"], "proposed_at": r["notify_proposed_at"],
                           "sent_by": r["notified_by"], "sent_at": r["notified_at"], "people": r["notified_count"]},
                "board": {"deadline": deadline, "reported_at": r["board_reported_at"],
                          "reference": r["board_reference"],
                          "overdue": not r["board_reported_at"] and self._now() > deadline}}

    def incidents(self) -> list[dict]:
        return [self.incident(r["id"]) for r in self.db.all("SELECT id FROM incidents ORDER BY created_at DESC")]

    def propose_notification(self, operator: str, iid: str) -> dict:
        r = self._incident_row(iid)
        if r["notified_at"]:
            raise Conflict("the affected people were already notified")
        with self.db.tx() as c:
            c.execute("UPDATE incidents SET notify_proposed_by=?, notify_proposed_at=? WHERE id=?",
                      (operator, self._now(), iid))
            self._audit(c, f"operator:{operator}", "incident.notify_proposed", None, incident_id=iid)
        return self.incident(iid)

    def send_notification(self, operator: str, iid: str, allow_self: bool = False) -> dict:
        r = self._incident_row(iid)
        if r["notified_at"]:
            raise Conflict("the affected people were already notified")
        if not r["notify_proposed_by"]:
            raise Conflict("propose the notification first; a second operator sends it")
        if r["notify_proposed_by"] == operator and not allow_self:
            raise Conflict("a second operator must approve notifying the affected people (four-eyes)")
        people = self._affected(r)
        cats = json.loads(r["categories"])
        what = ", ".join(CATEGORIES[k][0] for k in cats)
        steps = "; ".join(dict.fromkeys(CATEGORIES[k][1] for k in cats))
        found = r["detected_at"][:10]
        from .privacy import grievance_contact
        contact = grievance_contact()
        for i in range(0, len(people), 500):
            chunk = people[i:i + 500]
            with self.db.tx(shared=True) as c:  # alerts only: no person's protection state changes
                self._alert(c, chunk, "data_breach_notice", "A security incident may affect your data",
                            f"On {found} we found a security incident that may have exposed {what}. "
                            f"What you can do: {steps}. Your protection rules and guardians are not affected. "
                            f"Questions: {contact}.", None, incident_id=iid)
        with self.db.tx() as c:
            if not c.execute("UPDATE incidents SET notified_by=?, notified_at=?, notified_count=?, status='notified' "
                             "WHERE id=? AND notified_at IS NULL", (operator, self._now(), len(people), iid)).rowcount:
                raise Conflict("the affected people were already notified")
            self._audit(c, f"operator:{operator}", "incident.notified", None, incident_id=iid, people=len(people),
                        proposed_by=r["notify_proposed_by"])
        return self.incident(iid)

    def board_report(self, iid: str) -> dict:
        """What the Data Protection Board's detailed report (within 72 hours) needs, in one place."""
        inc = self.incident(iid)
        return {
            "data_fiduciary": "Guardian Registry",
            "incident_id": inc["id"],
            "title": inc["title"],
            "nature_and_circumstances": inc["description"],
            "detected_at": inc["detected_at"],
            "occurred": {"from": inc["occurred_from"], "to": inc["occurred_to"]},
            "personal_data_affected": [CATEGORIES[k][0] for k in inc["categories"]],
            "data_principals_affected": inc["affected_people"],
            "cause_and_findings": inc["cause"] or "(still being investigated)",
            "containment_and_mitigation": inc["containment"] or "(to be completed)",
            "remedial_measures": inc["remediation"] or "(to be completed)",
            "intimation_to_data_principals": inc["notify"],
            "deadline": inc["board"]["deadline"],
            "overdue": inc["board"]["overdue"],
            "grievance_contact": __import__("guardian_registry.privacy", fromlist=["x"]).grievance_contact(),
        }

    def record_board_report(self, operator: str, iid: str, reference: str) -> dict:
        self._incident_row(iid)
        if not (reference or "").strip():
            raise Invalid("reference is required (the Board's acknowledgement number)")
        with self.db.tx() as c:
            c.execute("UPDATE incidents SET board_reported_at=?, board_reference=? WHERE id=?",
                      (self._now(), reference.strip()[:100], iid))
            self._audit(c, f"operator:{operator}", "incident.board_reported", None, incident_id=iid,
                        reference=reference.strip()[:100])
        return self.incident(iid)
