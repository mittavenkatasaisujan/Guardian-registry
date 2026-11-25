# Integrating a bank or payment app

Guardian Registry is asked **before** money moves. Your customer's protection rules, guardians and
cross-bank limits live in the registry; you keep executing payments exactly as today, but only when
the registry says you may.

The API is described in [openapi.json](openapi.json) (OpenAPI 3). Client libraries:
[Python](../sdk/python) (`pip install ./sdk/python`) and [Java 17+](../sdk/java) (`gradle -p sdk/java build`).

## 1. Get connected

1. An operator registers you with your regulator reference (RBI / NPCI licence number); a second
   operator approves it. You receive an **API key** once: store it in your secret manager.
2. Send your **client certificate** (PEM). Once it is pinned, every call must come over mutual TLS
   with that certificate, as well as the `X-Api-Key` header. A key alone is refused.
3. Register a **webhook URL** (`PUT /v1/participant/webhook`) and keep the returned secret.
4. Run the **conformance script** against the sandbox (see section 6) and send us its output.

## 2. Check every outgoing payment

```
POST /v1/checks
{"mobile": "+919876543210", "participant_txn_id": "YOUR-TXN-ID", "amount": 2000000,
 "payee": "shop@upi", "channel": "upi"}
```

* `amount` is **integer paise** (₹20,000 = 2000000). Never send rupees or floats.
* `kind` (optional, default `transfer`): `merchant` for a payment to a shop, `recurring` for a debit
  under an existing mandate or standing instruction, `new_mandate` when the customer sets one up.
  This follows RBI's November 2026 draft directions: existing recurring mandates keep running
  while the customer's payments are paused (the draft's Stop Switch), and customers who choose the
  RBI scope for their trusted person only have transfers outside UPI sent for approval (the
  draft leaves out UPI, merchant and recurring payments).
* `narration` (optional, up to 140 characters): the payment's note as the customer typed it ("rent
  for November"). The customer's guardian sees it next to the amount and payee when deciding, as
  the draft's trusted person mechanism asks. It is stored as sent (on one line) and removed if the
  customer erases their account.
* `participant_txn_id` is your own id for the payment. The call is **idempotent** on it: after a
  timeout, send the same request again; you get the same check back, never a second one.
* Decide only on **`may_execute`**:

| `status` | `may_execute` | What you do |
|---|---|---|
| `allowed` | true | Execute the payment. |
| `pending_approval` | false | Tell the customer a guardian must approve (`approval_expires_at`). Wait. |
| `cooling_off` | false | Tell the customer it goes through at `release_at` unless stopped. Wait. |
| `approved`, `released` | true | Execute now. |
| `blocked`, `denied`, `expired`, `cancelled` | false | Don't execute. Show `reasons`. |

A customer who isn't enrolled comes back with `"enrolled": false, "may_execute": true`: carry on as
today. `reasons` are plain English sentences you can show the customer.

## 3. Learn the decision

**Webhooks (preferred).** When a held payment is approved, denied, released, expired or cancelled you
receive `check.updated`:

```
POST <your url>
X-GR-Event: check.updated
X-GR-Delivery: ntf_...        (unique; a delivery can be repeated, so de-duplicate on it)
X-GR-Signature: sha256=<hex HMAC-SHA256(webhook_secret, raw body)>
{"id": "ntf_...", "event": "check.updated", "created_at": "...", "data": {"check": {...}}}
```

Verify the signature over the **raw body bytes**, before parsing, with a constant-time comparison.
Both libraries do this (`verify_webhook` / `GuardianRegistryClient.verifyWebhook`). Answer 2xx
quickly; failed deliveries are retried with backoff for about two hours.

**Polling.** `GET /v1/checks/{check_id}` (or `wait_for_decision` / `waitForDecision`).

## 4. Report what happened

After executing (or failing) a payment the registry let through:

```
POST /v1/checks/{check_id}/outcome   {"completed": true}
```

A failed payment frees the customer's daily limit; a completed one makes the payee "known" (no new-payee
wait next time). Reporting twice is safe.

## 5. Share what you learn

* **SIM changes** you detect: `POST /v1/signals/sim-change {"mobile", "changed_at"}`. Larger payments
  are then held for a while: this is how most account takeovers start.
* **Fraud payees**, after you have *confirmed* a fraud: `POST /v1/signals/fraud-payees {"payee",
  "reason", "evidence_ref"}`. One bank's report holds payments to that payee for every protected
  customer at every bank; two banks' reports block them. You can withdraw your report
  (`DELETE /v1/signals/fraud-payees/{payee}`) and check a payee (`GET`); you never learn which bank
  reported it.

## 6. Label outcomes

When you learn how a checked payment turned out (the customer reported fraud and you confirmed it, or
you confirmed it was genuine), tell the registry:

```
POST /v1/checks/{check_id}/fraud-label   {"fraud": true, "note": "complaint 2026-118"}
```

Labels never change the check. They let operators measure how well each scam signal predicts real
fraud and tune the thresholds for everyone (`label_fraud` / `labelFraud` in the libraries).

## 7. Prove it works

```
python scripts/bank_conformance.py https://sandbox.registry.example.in --admin <sandbox operator token>
```

It registers a test bank and a protected family in the sandbox, starts a webhook receiver, and checks
the whole flow: an allowed payment and its outcome, idempotent retries, a payment held for a guardian
and approved (with a signed webhook), a denied one, a customer who isn't enrolled, a reported fraud
payee, labelling an outcome, and that a tampered webhook fails verification. Every line must say PASS.

## Errors and limits

* `4xx` responses carry `{"detail": "..."}`. Don't retry them, except `429` (honour `Retry-After`).
* Retry `5xx` and network errors with the same `participant_txn_id`.
* Default rate limit: 600 checks per minute per bank (ask if you need more).
* Send `Accept-Language: hi` to get error messages in Hindi.
