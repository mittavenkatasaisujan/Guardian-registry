# Security review (25 November 2026)

**Status: partial.** A manual, source-level review following the OWASP Top 10:2025 and ASVS 5.0
checklist from the security-audit skill. That skill's scanner engine isn't installed on the
review machine, so no runtime exploitation or scanner sweep (Gitleaks, Semgrep, Trivy) was run
beyond what CI already runs: CodeQL (Python, JavaScript), bandit, pip-audit and an OWASP ZAP
baseline scan of the running deployment. **Not a penetration test.**

## Findings fixed

| ID | Severity | Finding | Fix |
|---|---|---|---|
| SEC-1 | Medium | A bank could register a webhook URL inside the registry's own network (`https://169.254.169.254/` cloud metadata, `https://10.x`, `https://localhost`), making the server send requests there (server-side request forgery). Onboarding is four-eyes, so it needs a compromised bank key. | In production the host must resolve only to public addresses, checked when the URL is set and again before each delivery (DNS can change). `security.webhook_url_problem`; tests in `tests/test_security_audit.py`. |
| SEC-2 | Low | The repository's debug signing key is public by design (test APKs install over each other). If its certificate were ever listed as genuine, any app signed with it would pass attestation. | Production refuses to start when `GR_ANDROID_CERT_DIGESTS` includes it. |
| SEC-3 | Medium | `GR_SMS_PROVIDER=twilio_verify` (added for free-trial testing) sends sign-in codes only; in production a SIM-swap warning would never be texted. | Production refuses to start with it. |
| CodeQL #8, #9 | Medium | Log injection: a name or number with line breaks could forge log lines. | `security.log_safe` strips control characters. |
| CodeQL #5, #6 | Low | The translation file path was built from the request's language code (only enabled codes got that far). | The path comes only from the server's own language list. |
| CodeQL #4 | Low | Operators' event results echoed Python's exception text. | Fixed messages. |
| CodeQL #3 | Low | The demo printed part of the webhook secret. | No longer printed. |
| CodeQL #1 | Low | The conformance script's env file (test API key and token) was world-readable. | Created owner-only (0600). |
| pip-audit | Low | `pytest 8.3.4` (PYSEC-2026-1845), a test-only dependency. | 9.0.3. |

Dismissed on GitHub with reasons: **CodeQL #7** (SHA-256 of 192-bit random tokens; these are not
passwords, so a slow hash adds nothing) and **CodeQL #2** (`deploy_init.py` exists to write the
deployment's secret files; they are owner-only and git-ignored). CodeQL: 0 open alerts.

## Checked and found sound

- **Authentication:** OTP hashed with a keyed hash, 5 attempts per code, resend wait and window
  limits, the same answer whether a number is enrolled; device keys (P-256, Secure Enclave /
  StrongBox) with challenge signing; new devices on 24-hour probation; SIM-swap windows restrict
  new sign-ins; sessions are revoked on sign-out, lost phone and recovery.
- **Authorization:** banks see only their own checks (`get_check`, `report_outcome` scoped by
  participant); the route-by-route matrix in `tests/test_authz.py`; four-eyes operator actions;
  restricted sessions can't approve, invite, loosen or remove devices.
- **Injection:** all SQL is parameterised; the few f-string fragments splice fixed column or
  table names only. No shell, `eval` or pickle.
- **Webhooks:** HMAC-SHA256 over the raw body, constant-time comparison; events carry an id and time
  for de-duplication.
- **Secrets:** none tracked in git (checked for Google, Twilio, GitHub, Slack and private-key
  patterns). Production refuses development keys, the OTP echo, a missing SMS provider, the public
  debug certificate and a codes-only SMS provider. Real provider keys for testing live only in the
  git-ignored `local-secrets/`.
- **Rate limits:** per IP behind trusted proxies only (`X-Forwarded-For` from untrusted peers is
  ignored); per participant for checks.
- **Web app:** strict CSP (no inline script), COOP/COEP/CORP, frame-ancestors none.
- **Mobile:** Android backups off, cleartext only in debug builds, token encrypted with a Keystore
  key; iOS token in the Keychain (this device only), local HTTP only for the simulator.
- **CI:** no `pull_request_target`; secrets are not given to pull requests from forks.

## Fixed after the review

- **DNS rebinding of webhook delivery** (v0.27.0): in production the webhook host is resolved once,
  every address is checked, and the request is sent to the checked address, with the original name
  kept for the Host header, TLS SNI and the certificate check (`security.pin_webhook`). Redirects are
  not followed. Tests: `tests/test_security_audit.py`.

## Left for an independent tester

1. A penetration test of the deployed stack (nginx mTLS, both API nodes, Postgres, backups).
2. Mobile app reverse-engineering and tamper tests on real devices.
3. Load and abuse testing of OTP and recovery flows across many IPs.
