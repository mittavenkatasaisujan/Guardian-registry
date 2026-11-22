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
| Sign-in | SMS one-time code (6 digits, 5 min, single use, 5 wrong tries locks it, 30 s resend cooldown, 3 codes per 15 min, plus a per-IP limit). The response is the same whether or not a number is enrolled. Sessions last 30 days; you can sign out of one device or all of them. |
| **Bank-vouched KYC** | A participant bank that has already KYC'd its customer sends a claim (KYC level `full` or `minimum`, KYC date, optional date of birth, its customer ID). **It counts only after the customer approves it in the app.** Unanswered claims lapse after 7 days. Approved ones expire after a year (re-confirm yearly), and the customer can withdraw or the bank revoke at any time. The customer ID is stored only as a keyed hash and the date of birth only encrypted. Banks get a yes/no **`senior`** flag (70+, per RBI's proposal) in every check response, never the date. If two banks disagree on the date of birth, `senior` becomes unknown and the customer is told. |
| Verified guardians | Every guardian listing shows the guardian's identity level (`bank_verified`, `bank_min_kyc` or `otp`). The rule `require_verified_guardian` lets **only bank-verified guardians approve** payments. Any guardian can still deny or cancel, since that only protects. Turning the rule off is a loosening, so it's held for 24 h. |
| Two-way consent | The principal invites a guardian; the link is active only after the guardian accepts. At most 3 guardians. A guardian can step down at any time. |
| Rules | Per-payment limit, daily limit (shared across **all** banks, resets at IST midnight), guardian-approval threshold, cooling-off for first payments to a new payee, blocked channels. One-tap **presets** (`rbi_high_value_delay`, `senior_with_guardian`, `strict`). |
| Decisions | `block` › `needs_approval` › `delay` › `allow`, with human-readable reasons in ₹. With no active guardian, an approval falls back to a cooling-off delay, so nobody is locked out. |
| Anti-coaching | **Tightening applies at once. Loosening is held for 24 h** (raising limits, switching the kill switch off, removing a guardian). Any other guardian can veto it or approve it early. A guardian can't decide on their own removal. Guardians can't loosen anyone's rules. |
| Kill switch | The principal or any guardian can pause all payments at once. A guardian can switch payments back on at once; the principal's own request is held. |
| **Alerts** | Every event queues alerts **in the same database transaction**, so an alert is never lost or sent for something that rolled back. Guardians get SMS for urgent events (approval needed, payment on hold, protection being loosened, kill switch, guardian removal) and an in-app feed for everything. Delivery retries with backoff. |
| **Bank webhooks** | Banks register an `https://` URL and get a signed `check.updated` event when a held payment is approved, denied, released, expired or cancelled. No polling needed. |
| Background worker | Every few seconds it releases finished cooling-offs, expires unanswered approvals, applies held changes whose delay is over, and delivers alerts. |
| Bank API | Idempotent on `(participant, participant_txn_id)`. A failed payment frees the daily limit, and a completed one makes the payee "known". Customers who aren't enrolled pass through. Per-bank rate limit. **Key rotation** with a 24 h grace period. |
| Privacy | Mobile numbers are stored as an HMAC hash (for lookups) and an encrypted copy (only for sending SMS). Never in plain text. Keys, tokens and OTP codes are stored only as hashes. Banks never see principal IDs. Logs mask numbers. |
| Audit | Every change writes a SHA-256 **hash-chained** audit entry in the same transaction. `verify` detects any edited, deleted or reordered row. |
| Safe production start | With `GR_ENV=production` the server refuses to start on dev secrets, with no SMS gateway, or with the OTP dev echo on. |

## Run it

```powershell
python -m venv .venv
.venv\Scripts\pip install -r requirements.txt
.venv\Scripts\python -m pytest -q
```

Development server. The OTP code is echoed in the response, and SMS go to the console:

```powershell
$env:GR_ADMIN_TOKEN = "demo-admin"; $env:GR_DB = "demo.db"; $env:GR_OTP_DEV_ECHO = "1"; .venv\Scripts\uvicorn guardian_registry.api:create_app --factory --port 8000
```

API docs: http://127.0.0.1:8000/docs. The scripted scam-call story, which also runs a local webhook receiver that checks signatures:

```powershell
.venv\Scripts\python scripts\demo.py http://127.0.0.1:8000 demo-admin
```

Docker (set the production variables below):

```powershell
docker build -t guardian-registry .
```

### Configuration

| Env var | Purpose |
|---|---|
| `GR_ENV` | `production` turns on the startup safety checks |
| `GR_DB` | SQLite file path (default `guardian_registry.db`) |
| `GR_ADMIN_TOKEN` | Enables `/v1/admin/*`. Unset means admin is disabled. |
| `GR_PEPPER` | Secret for hashing mobile numbers. **Required in production.** |
| `GR_DATA_KEY` | Fernet key for encrypting mobile numbers. **Required in production.** Generate one with `python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"` |
| `GR_SMS_URL`, `GR_SMS_TOKEN` | SMS gateway: POST `{"to","text"}` with a bearer token. Put a thin adapter in front of MSG91, Gupshup, Twilio, etc. **Required in production.** |
| `GR_OTP_DEV_ECHO` | `1` returns the OTP in the response (development only, refused in production) |
| `GR_WORKER`, `GR_WORKER_INTERVAL` | Background worker on/off (default on) and interval in seconds (default 5) |
| `GR_RATE_CHECKS`, `GR_RATE_OTP` | Rate limits as `requests/seconds` (defaults `600/60` per bank, `10/60` per IP) |

## API

Auth: banks send `X-Api-Key`, people send `Authorization: Bearer <token>` (from OTP sign-in), operators send `X-Admin-Token`.
Amounts are **integer paise**.

| Who | Endpoints |
|---|---|
| Sign-in | `POST /v1/auth/otp`, `POST /v1/auth/verify` (send `display_name` the first time to enrol), `POST /v1/auth/logout` |
| Operator | `POST /v1/admin/participants`, `GET /v1/admin/audit/verify`, `POST /v1/admin/sweep` |
| Bank / app | `POST /v1/checks`, `GET /v1/checks/{id}`, `POST /v1/checks/{id}/outcome`, `POST /v1/kyc/attestations`, `GET/DELETE /v1/kyc/attestations/{id}`, `PUT /v1/participant/webhook`, `POST /v1/participant/rotate-key` |
| Person | `GET /v1/me`, `GET /v1/me/identity`, `POST /v1/me/identity/attestations/{id}/{approve,reject}`, `DELETE /v1/me/identity/attestations/{id}`, `GET /v1/me/notifications`, `POST /v1/me/notifications/read`, `GET /v1/presets`, `GET/PATCH /v1/me/rules`, `POST /v1/me/rules/preset/{name}`, `POST /v1/me/kill-switch/{on,off}`, `GET/POST /v1/me/guardians`, `DELETE /v1/me/guardians/{id}`, `GET /v1/me/changes`, `GET /v1/me/payments`, `POST /v1/me/payments/{id}/cancel`, `GET /v1/me/audit` |
| Guardian | `GET /v1/guardian/inbox`, `GET /v1/guardian/wards`, `POST /v1/guardian/invitations/{id}/{accept,decline}`, `POST /v1/guardian/guardianships/{id}/resign`, `POST /v1/guardian/payments/{id}/{approve,deny,cancel}`, `POST /v1/guardian/changes/{id}/{approve,veto}`, `GET /v1/guardian/wards/{pid}/{rules,payments,audit}`, `POST /v1/guardian/wards/{pid}/kill-switch/{on,off}`, `POST /v1/guardian/wards/{pid}/trusted-payees` |

**How a bank integrates:**
1. Call `POST /v1/checks` before executing a payment.
2. If `may_execute` is true, execute it, then report with `POST /v1/checks/{id}/outcome`.
3. If the status is `cooling_off` or `pending_approval`, wait for the `check.updated` webhook (or poll `GET /v1/checks/{id}`).

Banks also get a `kyc.updated` webhook when a customer approves, rejects or withdraws a KYC claim, or when one lapses or expires.

To verify a webhook, compare the `X-GR-Signature` header with `"sha256=" + hex(HMAC_SHA256(webhook_secret, raw_body))` using a constant-time comparison. Each delivery carries a unique `X-GR-Delivery` ID, so retries can be de-duplicated.

## Layout

```
guardian_registry/
  models.py     domain types, Rules.is_loosening
  policy.py     pure rules engine (no I/O)
  service.py    registry: sign-in, consent, held changes, checks, approvals, sweeper
  notify.py     alert outbox, SMS senders, signed webhooks, retrying dispatcher
  kyc.py        bank-vouched identity: attestations, consent, senior flag
  presets.py    named rule bundles (RBI-proposal-shaped, not final rules)
  audit.py      hash-chained audit log + verify
  db.py         SQLite schema with versioned migrations
  security.py   hashing, encryption, OTP, signatures, production checks
  ratelimit.py  sliding-window limiter
  api.py        FastAPI app (create_app factory) + background worker
tests/          229 tests
scripts/demo.py end-to-end story over real HTTP (also runs in CI)
```

## Still open

- **RBI's final rules:** the paper is a proposal. Presets live in one file ([presets.py](guardian_registry/presets.py)), so the numbers can change when RBI publishes its final text. The age cut-off is `SENIOR_AGE` in [kyc.py](guardian_registry/kyc.py).
- **Trusting the banks:** any onboarded participant can make a KYC claim. The customer's consent is the check, but a real network would also need onboarding rules (only RBI-regulated entities) and a way to suspend a bank that makes false claims.
- **Number changes and SIM swaps:** a bank-verified identity is tied to the mobile number. Moving to a new number, or spotting a SIM swap (a new sign-in shortly after a bank reports a SIM change), isn't handled yet.
- **Multi-node scale:** SQLite and the in-process rate limiter suit a single-node pilot. Running several nodes needs Postgres, a shared limiter (Redis or the gateway) and mTLS for banks.
- **Delivery channels:** SMS and in-app are built. WhatsApp and push notifications need a provider account.
