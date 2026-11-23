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
| **Participant trust** | Every bank or app declares its **kind** (`bank`, `small_finance_bank`, `payments_bank`, `nbfc`, `ppi_issuer`, `tpap`, `telecom`) and its regulator reference. The kind is a ceiling on its **capabilities**: `checks`, `kyc_full`, `kyc_minimum`, `sim_signals`, `number_lifecycle`. A UPI app (`tpap`) can run checks but can **never vouch for identity**; a wallet gets minimum-KYC claims by default. **Onboarding is four-eyes:** one operator registers a participant as `pending` (it gets its key and can set its webhook), and a **different operator** must approve it before it can call checks, KYC or signals. Suspending a participant or removing a capability is instant. Reinstating it or adding a capability needs a second operator. While a participant is suspended, its KYC claims stop counting. **Offboarding** is permanent: keys and webhook are wiped, its KYC claims are revoked and customers are told; SIM-swap windows it opened stay open. Operator actions are audited under each operator's name. |
| Sign-in | SMS one-time code (6 digits, 5 min, single use, 5 wrong tries locks it, 30 s resend cooldown, 3 codes per 15 min, plus a per-IP limit). The response is the same whether or not a number is enrolled. Sessions last 30 days; you can sign out of one device or all of them. |
| **Bank-vouched KYC** | A participant bank that has already KYC'd its customer sends a claim (KYC level `full` or `minimum`, KYC date, optional date of birth, its customer ID). **It counts only after the customer approves it in the app.** Unanswered claims lapse after 7 days. Approved ones expire after a year (re-confirm yearly), and the customer can withdraw or the bank revoke at any time. The customer ID is stored only as a keyed hash and the date of birth only encrypted. Banks get a yes/no **`senior`** flag (70+, per RBI's proposal) in every check response, never the date. If two banks disagree on the date of birth, `senior` becomes unknown and the customer is told. |
| Verified guardians | Every guardian listing shows the guardian's identity level (`bank_verified`, `bank_min_kyc` or `otp`). The rule `require_verified_guardian` lets **only bank-verified guardians approve** payments. Any guardian can still deny or cancel, since that only protects. Turning the rule off is a loosening, so it's held for 24 h. |
| **SIM-swap protection** | A fraudster who gets a victim's number moved to their own SIM receives the sign-in codes. Defences: (1) a bank reports a SIM change (`POST /v1/signals/sim-change`), or the person or a guardian reports a lost phone, which signs that person out everywhere. Either one opens a **72-hour risk window**. (2) Sign-ins after the SIM change, and sign-ins from a **new device (24 h probation)**, are **restricted**. They can read, deny, cancel, veto, tighten rules and switch the kill switch on. They can't approve payments, accept a guardian role, invite guardians, loosen rules, confirm the SIM change or change the number. A late bank report still restricts sessions that started after the change. (3) During the window, payments to new payees (any amount) and ₹2,000+ to known payees need a guardian's approval, or wait 24 h without one (rule `sim_swap_hold`, on by default). (4) No SMS goes to the swapped number; guardians are told instead, and the people a swapped guardian protects are warned. (5) Only a trusted session (the person's old phone, or a guardian) can end the window early. |
| **Operator SIM feed** | Mobile operators join as participants of kind `telecom` (they can send SIM and number events, nothing else). **Push:** `POST /v1/signals/operator-events` takes up to 500 `sim_swap`, `port_out` and `disconnected` events per call. Each event gets its own result, a resent `event_id` is a no-op, and the same SIM change reported by a bank and an operator counts once. Nothing is kept about numbers that aren't enrolled beyond the event id and outcome. **Live lookup:** at every sign-in and before every high-trust action, the registry asks the operator's SIM-swap API when the SIM last changed (CAMARA SIM Swap retrieve-date shape, cached 10 min). A recent change opens the 72-hour window at once, so a thief's fresh sign-in is restricted even before anyone reports it. If the API is down it carries on by default; `GR_SIM_LOOKUP_FAIL=closed` blocks high-trust actions instead. **Disconnected numbers** (operators recycle them) are detached from the account at once: whoever gets the number next signs in to a **new, empty account**, so they can't act as the old owner's guardian. The owner keeps the phone they're signed in on and can add a new number from it. Bank KYC ends, guardians are told. A disconnection dated before the person linked the number is ignored. |
| Number change | A new number is proven by an OTP, then the move is **held for 24 h** with guardian veto or early approval. Existing bank KYC claims end, since they vouched for the old number. |
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
$env:GR_OPERATORS = "alice:demo-alice-token,bob:demo-bob-token"; $env:GR_DB = "demo.db"; $env:GR_OTP_DEV_ECHO = "1"; .venv\Scripts\uvicorn guardian_registry.api:create_app --factory --port 8000
```

API docs: http://127.0.0.1:8000/docs. The scripted scam-call story, which also runs a local webhook receiver that checks signatures:

```powershell
.venv\Scripts\python scripts\demo.py http://127.0.0.1:8000 demo-alice-token demo-bob-token
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
| `GR_OPERATORS` | Named operators for `/v1/admin/*`: `alice:<token>,bob:<token>`. **Production needs at least two** (four-eyes onboarding); tokens must be 16+ characters. |
| `GR_ADMIN_TOKEN` | Development shortcut: a single operator called `admin`, which approves its own onboarding requests. Refused in production. Unset (with no `GR_OPERATORS`) means admin is disabled. |
| `GR_PEPPER` | Secret for hashing mobile numbers. **Required in production.** |
| `GR_DATA_KEY` | Fernet key for encrypting mobile numbers. **Required in production.** Generate one with `python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"` |
| `GR_SMS_URL`, `GR_SMS_TOKEN` | SMS gateway: POST `{"to","text"}` with a bearer token. Put a thin adapter in front of MSG91, Gupshup, Twilio, etc. **Required in production.** |
| `GR_OTP_DEV_ECHO` | `1` returns the OTP in the response (development only, refused in production) |
| `GR_WORKER`, `GR_WORKER_INTERVAL` | Background worker on/off (default on) and interval in seconds (default 5) |
| `GR_SIM_LOOKUP_URL`, `GR_SIM_LOOKUP_TOKEN` | Operator SIM-swap API: POST `{"phoneNumber": "+91..."}`, reply `{"latestSimChange": "<ISO 8601>" or null}` (CAMARA SIM Swap shape), bearer token. Unset means no live lookup. |
| `GR_SIM_LOOKUP_FAIL` | `open` (default) or `closed`: what to do when the lookup API is down |
| `GR_RATE_CHECKS`, `GR_RATE_OTP` | Rate limits as `requests/seconds` (defaults `600/60` per bank, `10/60` per IP) |

## API

Auth: banks send `X-Api-Key`, people send `Authorization: Bearer <token>` (from OTP sign-in), operators send `X-Admin-Token`.
Amounts are **integer paise**.

| Who | Endpoints |
|---|---|
| Sign-in | `POST /v1/auth/otp`, `POST /v1/auth/verify` (send `display_name` the first time to enrol and a stable `device_id`; the response says if the session is `restricted`), `POST /v1/auth/logout` |
| Operator | `POST/GET /v1/admin/participants` (body: `name`, `kind`, `regulator_ref`, optional `capabilities`), `GET /v1/admin/participants/{id}`, `POST /v1/admin/participants/{id}/{approve,reject,suspend,reinstate,offboard}`, `PUT /v1/admin/participants/{id}/capabilities`, `GET /v1/admin/audit/verify`, `POST /v1/admin/sweep` |
| Bank / app | `POST /v1/signals/sim-change`, `POST /v1/signals/operator-events` (telecom), `POST /v1/checks`, `GET /v1/checks/{id}`, `POST /v1/checks/{id}/outcome`, `POST /v1/kyc/attestations`, `GET/DELETE /v1/kyc/attestations/{id}`, `GET /v1/participant/me`, `PUT /v1/participant/webhook`, `POST /v1/participant/rotate-key` |
| Person | `GET /v1/me`, `GET /v1/me/security`, `POST /v1/me/security/{lost-phone,confirm-sim-change}`, `POST /v1/me/mobile/{change,verify}`, `GET /v1/me/identity`, `POST /v1/me/identity/attestations/{id}/{approve,reject}`, `DELETE /v1/me/identity/attestations/{id}`, `GET /v1/me/notifications`, `POST /v1/me/notifications/read`, `GET /v1/presets`, `GET/PATCH /v1/me/rules`, `POST /v1/me/rules/preset/{name}`, `POST /v1/me/kill-switch/{on,off}`, `GET/POST /v1/me/guardians`, `DELETE /v1/me/guardians/{id}`, `GET /v1/me/changes`, `GET /v1/me/payments`, `POST /v1/me/payments/{id}/cancel`, `GET /v1/me/audit` |
| Guardian | `GET /v1/guardian/inbox`, `GET /v1/guardian/wards`, `POST /v1/guardian/invitations/{id}/{accept,decline}`, `POST /v1/guardian/guardianships/{id}/resign`, `POST /v1/guardian/payments/{id}/{approve,deny,cancel}`, `POST /v1/guardian/changes/{id}/{approve,veto}`, `GET /v1/guardian/wards/{pid}/{rules,payments,audit,security}`, `POST /v1/guardian/wards/{pid}/{lost-phone,confirm-sim-change}`, `POST /v1/guardian/wards/{pid}/kill-switch/{on,off}`, `POST /v1/guardian/wards/{pid}/trusted-payees` |

**How a bank integrates:**
1. Call `POST /v1/checks` before executing a payment.
2. If `may_execute` is true, execute it, then report with `POST /v1/checks/{id}/outcome`.
3. If the status is `cooling_off` or `pending_approval`, wait for the `check.updated` webhook (or poll `GET /v1/checks/{id}`).

A participant also gets a `participant.updated` webhook when it is approved, suspended or reinstated, or its capabilities change. Banks also get a `kyc.updated` webhook when a customer approves, rejects or withdraws a KYC claim, or when one lapses or expires.

To verify a webhook, compare the `X-GR-Signature` header with `"sha256=" + hex(HMAC_SHA256(webhook_secret, raw_body))` using a constant-time comparison. Each delivery carries a unique `X-GR-Delivery` ID, so retries can be de-duplicated.

## Layout

```
guardian_registry/
  models.py     domain types, Rules.is_loosening
  policy.py     pure rules engine (no I/O)
  service.py    registry: sign-in, consent, held changes, checks, approvals, sweeper
  notify.py     alert outbox, SMS senders, signed webhooks, retrying dispatcher
  participants.py  participant kinds, capabilities, four-eyes onboarding, suspension
  kyc.py        bank-vouched identity: attestations, consent, senior flag
  simswap.py    SIM-swap windows, device probation, restricted sessions, number change
  simfeed.py    mobile-operator feed: pushed events, number disconnection, live SIM-swap lookup
  presets.py    named rule bundles (RBI-proposal-shaped, not final rules)
  audit.py      hash-chained audit log + verify
  db.py         SQLite schema with versioned migrations
  security.py   hashing, encryption, OTP, signatures, production checks
  ratelimit.py  sliding-window limiter
  api.py        FastAPI app (create_app factory) + background worker
tests/          322 tests
scripts/demo.py end-to-end story over real HTTP (also runs in CI)
```

## Still open

- **RBI's final rules:** the paper is a proposal. Presets live in one file ([presets.py](guardian_registry/presets.py)), so the numbers can change when RBI publishes its final text. The age cut-off is `SENIOR_AGE` in [kyc.py](guardian_registry/kyc.py).
- **Checking the regulator reference:** operators type in the RBI/NPCI reference and a second operator approves it, but the registry doesn't look it up against RBI's published lists of regulated entities. Operator tokens are long-lived shared secrets; a real deployment would put operators behind SSO with hardware keys.
- **Real operator connections:** the push feed and live lookup are built to a standard shape, but no operator or aggregator is connected. In India that means signing up with each operator's or an aggregator's network API (or the DoT revocation list for disconnections). The device ID is chosen by the app, so it shows a device is new but doesn't prove one is the same: that's why a SIM change restricts every sign-in after it, whatever device it claims.
- **Account recovery without a signed-in phone:** if someone's number is disconnected and they have no phone still signed in, they can't add a new number themselves yet. A guardian-assisted or bank-assisted recovery is still to build.
- **Multi-node scale:** SQLite and the in-process rate limiter suit a single-node pilot. Running several nodes needs Postgres, a shared limiter (Redis or the gateway) and mTLS for banks.
- **Delivery channels:** SMS and in-app are built. WhatsApp and push notifications need a provider account.
