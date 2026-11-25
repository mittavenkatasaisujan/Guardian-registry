# Data protection and payments law review (25 November 2026)

**Not legal advice.** A compliance review against the texts as reported in public sources, to
give counsel a head start. A lawyer must review the notice text, the lawful basis for each purpose,
the retention periods and the provider contracts before real users.

## Laws in play

| Law | Status | Dates |
|---|---|---|
| Digital Personal Data Protection Act, 2023 + DPDP Rules, 2025 (notified Nov 2025) | In force in phases | Most duties (notice, security, breach reporting, erasure, rights) from about **May 2027**; consent-manager registration from Nov 2026 |
| RBI: storage of payment system data (April 2018 circular) | Final | Payment data stored only in India; processing abroad allowed if data is deleted there within one business day or 24 hours |
| RBI customer-liability amendment (June 2026) and the November 2026 draft directions | Final / draft | See [rbi-alignment.md](rbi-alignment.md) |

## DPDP Act: duty by duty

| Duty | Registry | Gap / action |
|---|---|---|
| Notice in clear terms (s.5) | `GET /v1/privacy/notice`, versioned; consent recorded per version | **Fixed:** notice v2026-11-25 now names the outside messaging services (some outside India), says the service is for adults, and lists the new rights. **Fixed (v0.27.0):** the notice is also in Hindi (`Accept-Language: hi`, same version), and the web, Android and iOS apps now show it with an "I agree" button that records consent (before, only the API had it). **Counsel:** final wording of both languages. |
| Consent: free, specific, withdrawable as easily as given (s.6) | Consent recorded; erasure available | **Counsel:** erasure is held 7 days so a scammer can't strip protection in one tap; confirm this is a reasonable safeguard under s.6(4) and say so in the notice (it does). |
| Legitimate uses without consent (s.7) | Banks' checks rely on the person's enrolment | **Counsel:** lawful basis for processing payment checks of enrolled customers. |
| Security safeguards (s.8(5)) | See [security-review.md](security-review.md) | Independent penetration test before launch. |
| Breach notification (s.8(6)) | `breach.py`: incident record, notify the Board and affected people, four-eyes approval of notices | **Counsel:** confirm the Rules' timeline (commentary cites 72 hours; verify in the Gazette text). |
| Retention and erasure (s.8(7)) | **"Delete my account"** in the apps (held 7 days, guardians told, can be cancelled; `GET /v1/me/erasure` shows a waiting deletion). Erasure deletes number, name, sessions, devices, push tokens, rules, nominee; alerts deleted after 180 days, sessions after 90 | **Counsel:** payment check records (without number or name) and the audit chain are kept after erasure for banks' record-keeping; confirm the period and basis. |
| Grievance officer (s.8(10)) | `GR_GRIEVANCE_CONTACT` in the notice | Appoint one. |
| Children (s.9) | **Fixed (v0.29.0):** a new account needs "I am 18 or older" ticked in the web, Android and iOS apps; the server refuses enrolment without it (`adult_required`) and records when it was confirmed (`users.adult_confirmed_at`, in the data export) | **Counsel:** whether self-declaration is enough, or banks' KYC age should be relied on. |
| Access (s.11) | `GET /v1/me/data-export`; **"Download my data"** in the web, Android and iOS apps (v0.28.0) | — |
| **Correction (s.12)** | **Fixed:** `PUT /v1/me/name` (the notice already promised it; it didn't exist) | Rules are corrected in the app. |
| **Nomination (s.14)** | **Fixed:** `GET/PUT/DELETE /v1/me/nominee` (name, relation, mobile; encrypted; exported; erased). Gives no account access | **Counsel:** the grievance officer's process for verifying death or incapacity. |
| Significant Data Fiduciary (s.10) | — | **Counsel:** if notified as one (payments data at scale), a DPO in India, audits and impact assessments follow. |
| Processors (s.8(2)) | SMS, push (Google, Apple), WhatsApp (Meta) | Written contracts with each provider. |

## RBI data localisation

The registry receives payment details from banks (amount, payee, time), so it is likely within
the circular as a bank's service provider. Two consequences:

1. **Hosting:** run the database and servers in an Indian region (for Oracle Cloud Free Tier:
   Mumbai or Hyderabad; for Google Cloud: asia-south1 or asia-south2). `deploy/bootstrap.sh` works
   on either.
2. **Messages through outside services:** **Fixed:** `GR_ALERT_DETAIL=minimal` (the **default in
   production**) sends push, SMS and WhatsApp alerts without names, amounts or payees, only
   "Open Guardian Registry to see the details" in the person's language. The full alert stays in
   the app, served from India. Counsel and the banks may decide `full` is acceptable for domestic
   SMS providers; set it explicitly then.

## Before launch (for counsel)

1. Final notice text, in English and the languages offered.
2. Lawful basis for each purpose; retention periods; banks' record-keeping basis for kept checks.
3. Children: enforce adults only, or design verifiable parental consent.
4. Contracts with every processor; hosting in India confirmed.
5. Grievance officer appointed; breach procedure rehearsed against the Rules' timeline.
6. Agreements with partner banks (roles: who is the data fiduciary for checks).
