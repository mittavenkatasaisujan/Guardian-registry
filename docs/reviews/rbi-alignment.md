# RBI rules and the registry (checked 25 November 2026)

## Where RBI stands

| Text | Status | What it means here |
|---|---|---|
| Customer liability amendment, 24 June 2026 ("Customer Protection in Fraudulent Electronic Banking Transactions") | **Final** | Zero customer liability when fraud comes from bank negligence. Banks carry the risk, which is why they want strong preventive controls. |
| Discussion paper, April 2026 (trusted person for customers 70+; delay on high-value transfers) | Superseded by the draft below | The `senior_with_guardian` and `rbi_high_value_delay` presets came from it. |
| **Draft** directions, ~23 November 2026: Commercial Banks – Responsible Business Conduct, Fifth Amendment Directions, 2026 | **Draft, not final.** Stop Switch and trusted person mechanism to apply from **1 July 2027**; the wider "negligence by a bank" from **1 January 2027** | The registry now follows it (below). |

Sources: news coverage of the November draft ([MediaNama](https://www.medianama.com/2026/11/223-rbis-draft-rules-online-fraud/), [Upstox](https://upstox.com/news/business-news/latest-updates/rbi-proposes-stop-switch-to-let-bank-customers-block-all-outgoing-digital-payments/article-203896/)).
The RBI draft PDF itself and its comment deadline were not read; **check the RBI text before relying on any detail below.**

## The draft, rule by rule

| Draft rule | Registry | Where |
|---|---|---|
| Trusted person mechanism offered to every customer, voluntary, both must consent | Guardian invite and accept | `service.invite_guardian`, `respond_to_invite` |
| Trusted person's mobile differs from the account's | You can't be your own guardian; one account per number | `invite_guardian` |
| Covers fund transfers above a threshold the customer sets | `approval_threshold` (customer-set) | `models.Rules` |
| **Leaves out UPI, merchant payments and recurring payments** | Rule `approval_scope: "rbi"`; banks send `kind` (`transfer`, `merchant`, `recurring`, `new_mandate`) with each check | `policy.evaluate`, `CheckIn.kind`, migration v19 |
| Trusted person has **one hour**; no answer means rejected | `approval_timeout_minutes: 60` in the `rbi_trusted_person` preset; an unanswered check expires and is never executed | `presets.py`, `Registry.sweep` |
| Trusted person sees amount, beneficiary, narration | Approval alert shows amount and payee (no narration field yet) | `_decide_new_check` |
| **24 hours before a trusted person becomes active** | Rule `new_guardian_wait_hours` (24 in the preset): a newer guardian can deny or stop, but not approve | `_approver_ids`, `_decide_check` |
| Any change, removal, threshold change or opt-out waits 24 hours | Loosening and guardian removal are held 24 hours and guardians can stop them. **Tightening is immediate**, which is stricter than the draft and can't hurt the customer | `update_rules`, `_propose_change` |
| Trusted person gets no access, no liability | Guardians see only the person's protection screens; they can't move money | authorization matrix, `tests/test_authz.py` |
| **Stop Switch**: blocks customer debits, new mandates, new UPI registrations; **existing recurring mandates, liens and bank-initiated debits continue**; credits continue | Kill switch blocks every `kind` except `recurring`. Liens and bank-initiated debits never reach the registry. New UPI app registrations are the bank's own control | `policy.evaluate` |
| Customer limits: per transaction, per beneficiary per day, per channel per day, overall daily | `per_txn_limit`, `per_payee_daily_limit`, `channel_daily_limits`, `daily_limit` | `models.Rules`, `policy.evaluate` |
| Switch channels off | `blocked_channels` | |
| Time window when chosen channels stay off | **Not built.** The `scam_signals` night rule holds large night payments instead | possible follow-up |
| Channels off by default at onboarding; first-24-hour cap for new customers | Bank-side controls (the bank's own channels), not the registry's | bank |
| "Negligence by a bank" includes not providing the trusted person mechanism or customer controls | The registry gives banks both through one API, with an audit trail to show they were applied | `docs/bank-integration.md` |

## When RBI publishes final text

1. Read the final directions; compare each row above.
2. Change `presets.py` (thresholds, window, waits) and, if needed, `policy.evaluate`.
3. Run `pytest tests/test_rbi_draft.py` and update its expectations to the final text.
