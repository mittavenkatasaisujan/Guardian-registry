# Reviews (25 November 2026)

Four reviews made with the tools available to the project, and what they changed. None of them
replaces the people who must sign off before real users: a lawyer, native speakers, and an
independent penetration test. Each file ends with what is left for them.

| Review | File | Changed in code |
|---|---|---|
| RBI rules: what is final, what is draft, and how the registry follows the draft | [rbi-alignment.md](rbi-alignment.md) | RBI scope for the trusted person, 24-hour start for new guardians, Stop Switch lets existing mandates run, per-payee and per-channel daily limits, payment `kind`, `rbi_trusted_person` preset |
| Security review (manual, OWASP Top 10:2025 / ASVS 5.0 checklist) and CodeQL alerts | [security-review.md](security-review.md) | No webhooks into internal networks, production refuses the public debug certificate and a codes-only SMS provider, log-injection-safe logging, safer translation paths and error messages, pytest 9.0.3 |
| Translations (Hindi live; Tamil, Telugu, Bengali, Marathi drafts) | [translation-review.md](translation-review.md) | Unambiguous Hindi for "a call you made yourself", ready-made set names translated |
| Data protection and payments law (DPDP Act 2023 and Rules 2025; RBI) | [legal-review.md](legal-review.md) | Name correction, nominee, notice v2026-11-25, alert detail kept out of outside services by default in production |
