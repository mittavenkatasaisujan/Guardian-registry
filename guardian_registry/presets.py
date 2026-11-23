"""Named rule bundles a person (or the guardian helping them set up) can apply in one tap.

RBI's proposals (a delay on high-value transfers, a trusted-person check for people
aged 70 and over, a kill switch) are still a DISCUSSION PAPER. The final thresholds
aren't known, so these presets are starting points, not legal requirements. Change
the numbers here when RBI publishes its final text. Amounts are in paise.

₹10,000 is used as the "high value" line because RBI's paper reports that transfers
above ₹10,000 are about 45% of fraud cases but 98.5% of the value lost.
"""

R = 100  # paise per rupee

PRESETS: dict[str, dict] = {
    "rbi_high_value_delay": {
        "label": "1-hour wait on high-value payments to new payees",
        "basis": "RBI discussion paper: proposed delay for high-value digital transfers (not final)",
        "rules": {
            "new_payee_delay_threshold": 10_000 * R,
            "cooling_off_minutes": 60,
        },
    },
    "senior_with_guardian": {
        "label": "Trusted person approves large payments",
        "basis": "RBI discussion paper: trusted-person check for customers aged 70+ (not final)",
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
