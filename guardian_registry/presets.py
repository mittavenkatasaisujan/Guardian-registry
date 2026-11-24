"""Named rule bundles a person (or the guardian helping them set up) can apply in one tap.

RBI's rules here are still DRAFTS (checked 25 Nov 2026):
  * April 2026 discussion paper: a trusted-person check for customers aged 70 and over,
    and a delay on high-value transfers.
  * November 2026 draft directions (Commercial Banks - Responsible Business Conduct, Fifth
    Amendment, 2026; to apply from 1 July 2027): the trusted person mechanism is voluntary
    for every customer, the trusted person has one hour to approve or the transfer is
    rejected, UPI, merchant and recurring payments are left out, a trusted person starts
    only after 24 hours, and any change or opt-out waits 24 hours. Customers also get a
    Stop Switch (existing recurring mandates continue) and their own per-beneficiary and
    per-channel daily limits. The draft dropped the mandatory one-hour delay.
These presets are starting points, not legal requirements. Change them when RBI publishes
final text. Amounts are in paise.

₹10,000 is used as the "high value" line because RBI's paper reports that transfers
above ₹10,000 are about 45% of fraud cases but 98.5% of the value lost. The draft lets
each customer set their own threshold.
"""

R = 100  # paise per rupee

PRESETS: dict[str, dict] = {
    "rbi_high_value_delay": {
        "label": "1-hour wait on high-value payments to new payees",
        "basis": "RBI discussion paper, Apr 2026: proposed delay for high-value transfers (dropped as a requirement in the Nov 2026 draft; still useful)",
        "rules": {
            "new_payee_delay_threshold": 10_000 * R,
            "cooling_off_minutes": 60,
        },
    },
    "rbi_trusted_person": {
        "label": "Trusted person approves large transfers (RBI draft rules)",
        "basis": "RBI draft directions, Nov 2026: trusted person mechanism (not final; to apply from 1 July 2027)",
        "rules": {
            "approval_threshold": 10_000 * R,
            "approval_scope": "rbi",
            "approval_timeout_minutes": 60,
            "new_guardian_wait_hours": 24,
        },
    },
    "senior_with_guardian": {
        "label": "Trusted person approves large payments",
        "basis": "RBI discussion paper, Apr 2026: trusted-person check for customers aged 70+, plus this registry's extra holds",
        "rules": {
            "approval_threshold": 10_000 * R,
            "approval_timeout_minutes": 30,
            "new_payee_delay_threshold": 5_000 * R,
            "cooling_off_minutes": 60,
            "daily_limit": 1_00_000 * R,
            "scam_signals": True,
        },
    },
    "strict": {
        "label": "Strict: low limits, no RTGS",
        "basis": "For someone who has already been targeted by a scam",
        "rules": {
            "per_txn_limit": 25_000 * R,
            "daily_limit": 50_000 * R,
            "approval_threshold": 5_000 * R,
            "new_payee_delay_threshold": 2_000 * R,
            "cooling_off_minutes": 120,
            "approval_timeout_minutes": 30,
            "blocked_channels": ["rtgs"],
            "scam_signals": True,
        },
    },
}
