# Guardian Registry

A consent-based, **cross-bank** registry of trusted people and payment-protection rules.
A person sets their rules once (for example "my son approves anything over ₹10,000"),
and every bank or UPI app that joins checks the registry before moving money.
Think of it as an Account Aggregator for protection.

**Why:** RBI's discussion paper reports 28 lakh digital frauds worth ₹22,931 crore in 2025.
Transfers above ₹10,000 are about 45% of cases but 98.5% of the value. RBI has proposed
trusted-person checks for people aged 70 and over, plus a kill switch. If each bank builds
its own version, a family with three bank accounts sets up three separate locks.

## What it does

| Feature | Behaviour |
|---|---|
| Two-way consent | The principal invites a guardian; the link is active only after the guardian accepts. At most 3 guardians. A guardian can step down at any time. |
| Rules | Per-payment limit, daily limit (shared across **all** banks, resets at IST midnight), guardian-approval threshold, cooling-off for first payments to a new payee, blocked channels (UPI/IMPS/NEFT/RTGS/card/netbanking). |
| Decisions | `block` › `needs_approval` › `delay` › `allow`, with human-readable reasons in ₹. With no active guardian, an approval falls back to a cooling-off delay, so nobody is locked out. |
| Anti-coaching | **Tightening applies at once. Loosening is held for 24 h** (raising limits, switching the kill switch off, removing a guardian). Any other guardian can veto it or approve it early. A guardian can't decide on their own removal. |
| Kill switch | The principal or any guardian can pause all payments at once. A guardian can switch payments back on at once; the principal's own request is held. |
| Guardian powers | Approve or deny held payments, cancel payments in cooling-off, vouch for a payee, veto loosening, use the kill switch. Guardians **cannot** loosen someone's rules. |
| Bank API | Idempotent on `(participant, participant_txn_id)`. A bank reports whether money moved: a failed payment frees the daily limit, and a completed one makes the payee "known". Customers who aren't enrolled pass through (`enrolled: false`). |
| Privacy | Mobile numbers are stored only as HMAC hashes (`GR_PEPPER`). API keys and tokens are stored only as hashes. Banks see no principal IDs. |
| Audit | Every change writes a SHA-256 **hash-chained** audit entry in the same transaction. `verify` detects any edited, deleted or reordered row. |

## Run it

```powershell
python -m venv .venv
.venv\Scripts\pip install -r requirements.txt
.venv\Scripts\python -m pytest -q
```

```powershell
$env:GR_ADMIN_TOKEN = "demo-admin"; $env:GR_DB = "demo.db"; .venv\Scripts\uvicorn guardian_registry.api:create_app --factory --port 8000
```

Interactive API docs: http://127.0.0.1:8000/docs. In a second terminal, run the scripted scam-call story over real HTTP:

```powershell
.venv\Scripts\python scripts\demo.py http://127.0.0.1:8000 demo-admin
```

| Env var | Purpose |
|---|---|
| `GR_DB` | SQLite file path (default `guardian_registry.db`) |
| `GR_ADMIN_TOKEN` | Enables `/v1/admin/*` (onboard banks, verify audit). Unset means admin is disabled. |
| `GR_PEPPER` | Secret for mobile-number hashing. **Set it in any real deployment.** |

## API

Auth: banks send `X-Api-Key`, people send `Authorization: Bearer <token>`, operators send `X-Admin-Token`.
Amounts are **integer paise**.

| Who | Endpoints |
|---|---|
| Operator | `POST /v1/admin/participants`, `GET /v1/admin/audit/verify` |
| Bank / app | `POST /v1/checks`, `GET /v1/checks/{id}`, `POST /v1/checks/{id}/outcome` |
| Person | `POST /v1/users`, `GET /v1/me`, `GET/PATCH /v1/me/rules`, `POST /v1/me/kill-switch/{on,off}`, `GET/POST /v1/me/guardians`, `DELETE /v1/me/guardians/{id}`, `GET /v1/me/changes`, `GET /v1/me/payments`, `POST /v1/me/payments/{id}/cancel`, `GET /v1/me/audit` |
| Guardian | `GET /v1/guardian/inbox`, `GET /v1/guardian/wards`, `POST /v1/guardian/invitations/{id}/{accept,decline}`, `POST /v1/guardian/guardianships/{id}/resign`, `POST /v1/guardian/payments/{id}/{approve,deny,cancel}`, `POST /v1/guardian/changes/{id}/{approve,veto}`, `GET /v1/guardian/wards/{pid}/{rules,payments,audit}`, `POST /v1/guardian/wards/{pid}/kill-switch/{on,off}`, `POST /v1/guardian/wards/{pid}/trusted-payees` |

How a bank integrates: call `POST /v1/checks` before executing. If `may_execute` is true, execute and report the outcome.
If the status is `cooling_off` or `pending_approval`, poll `GET /v1/checks/{id}` until it becomes `released`, `approved`,
`denied`, `expired` or `cancelled`.

## Layout

```
guardian_registry/
  models.py    domain types, Rules.is_loosening
  policy.py    pure rules engine (no I/O)
  service.py   registry: consent, held changes, checks, approvals
  audit.py     hash-chained audit log + verify
  db.py        SQLite schema and transactions
  security.py  mobile normalisation/hashing, secrets
  api.py       FastAPI app (create_app factory)
tests/         124 tests: foundation, policy, service, audit, API
scripts/demo.py  end-to-end story over real HTTP
```

## Not built yet (pilot gaps)

- **Real identity:** enrolment currently returns a bearer token. In production the bank or app would vouch through OTP or KYC, and guardian identity would need verifying too.
- **Notifications:** guardians must check their inbox. Push, SMS or WhatsApp alerts are the next thing to build, since a 30-minute approval window needs them.
- **Exact RBI rules:** the final text of RBI's proposal (70+ age rule, 1-hour versus 24-hour delay) isn't published yet. The thresholds are configurable for that reason.
- **Scale and operations:** single-node SQLite with a process lock is fine for a pilot. A real deployment would need Postgres, mTLS for banks, rate limits and key rotation.
