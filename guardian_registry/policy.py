"""The rules engine. Pure: no database, no clock. Same inputs, same decision.

Precedence, strongest first:
  1. BLOCK          kill switch, blocked channel, per-transaction limit, daily limit
  2. NEEDS_APPROVAL amount at/above the approval threshold (needs an active guardian)
  3. DELAY          first payment to a payee at/above the new-payee threshold,
                    or approval was needed but nobody is available to approve
  4. ALLOW

While a SIM change is recent (sim_swap_recent) and the rule sim_swap_hold is on, payments
to new payees (any amount) and payments of SIM_SWAP_KNOWN_PAYEE_LIMIT or more to known
payees are also held: a guardian must approve, or, with no guardian, they wait
SIM_SWAP_DELAY_MINUTES. A SIM swap is how scammers take over OTPs and UPI apps.
Every rule that fired is listed in `reasons`, so a bank can show the customer why.
"""

from __future__ import annotations

from .models import Decision, Outcome, Rules, Transaction

SIM_SWAP_KNOWN_PAYEE_LIMIT = 2_000 * 100   # paise
SIM_SWAP_DELAY_MINUTES = 24 * 60


def _rupees(paise: int) -> str:
    return f"₹{paise / 100:,.2f}"


def evaluate(
    rules: Rules,
    txn: Transaction,
    *,
    spent_today: int,
    payee_known: bool,
    has_active_guardian: bool,
    sim_swap_recent: bool = False,
) -> Decision:
    if txn.amount <= 0:
        return Decision(Outcome.BLOCK, ["amount must be positive"])

    blocks: list[str] = []
    if rules.kill_switch:
        blocks.append("kill switch is on: all outgoing payments are paused")
    if txn.channel in rules.blocked_channels:
        blocks.append(f"channel '{txn.channel}' is switched off")
    if rules.per_txn_limit is not None and txn.amount > rules.per_txn_limit:
        blocks.append(f"amount {_rupees(txn.amount)} is over the per-payment limit {_rupees(rules.per_txn_limit)}")
    if rules.daily_limit is not None and spent_today + txn.amount > rules.daily_limit:
        left = max(rules.daily_limit - spent_today, 0)
        blocks.append(f"daily limit {_rupees(rules.daily_limit)} would be exceeded ({_rupees(left)} left today)")
    if blocks:
        return Decision(Outcome.BLOCK, blocks)

    needs_approval = rules.approval_threshold is not None and txn.amount >= rules.approval_threshold
    new_payee_hold = (
        not payee_known
        and rules.new_payee_delay_threshold is not None
        and txn.amount >= rules.new_payee_delay_threshold
    )

    sim_hold = sim_swap_recent and rules.sim_swap_hold and (
        not payee_known or txn.amount >= SIM_SWAP_KNOWN_PAYEE_LIMIT)

    reasons: list[str] = []
    if sim_hold:
        reasons.append("the SIM card for this number was changed recently, so this payment needs extra checks")
    if needs_approval:
        reasons.append(f"amount {_rupees(txn.amount)} is at or above the approval threshold {_rupees(rules.approval_threshold)}")
    if new_payee_hold:
        reasons.append(f"first payment of {_rupees(txn.amount)} to a new payee")

    if (needs_approval or sim_hold) and has_active_guardian:
        return Decision(Outcome.NEEDS_APPROVAL, reasons,
                        approval_timeout_minutes=rules.approval_timeout_minutes)
    if needs_approval or sim_hold:
        reasons.append("no active guardian to approve, so a cooling-off delay applies instead")
    if sim_hold:
        return Decision(Outcome.DELAY, reasons, delay_minutes=max(rules.cooling_off_minutes, SIM_SWAP_DELAY_MINUTES))
    if needs_approval or new_payee_hold:
        return Decision(Outcome.DELAY, reasons, delay_minutes=rules.cooling_off_minutes)
    return Decision(Outcome.ALLOW, [])
