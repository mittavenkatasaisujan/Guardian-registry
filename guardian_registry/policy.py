"""The rules engine. Pure: no database, no clock. Same inputs, same decision.

Precedence, strongest first:
  1. BLOCK          kill switch, blocked channel, per-transaction limit, daily limit
  2. NEEDS_APPROVAL amount at/above the approval threshold (needs an active guardian)
  3. DELAY          first payment to a payee at/above the new-payee threshold,
                    or approval was needed but nobody is available to approve
  4. ALLOW
Every rule that fired is listed in `reasons`, so a bank can show the customer why.
"""

from __future__ import annotations

from .models import Decision, Outcome, Rules, Transaction


def _rupees(paise: int) -> str:
    return f"₹{paise / 100:,.2f}"


def evaluate(
    rules: Rules,
    txn: Transaction,
    *,
    spent_today: int,
    payee_known: bool,
    has_active_guardian: bool,
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

    reasons: list[str] = []
    if needs_approval:
        reasons.append(f"amount {_rupees(txn.amount)} is at or above the approval threshold {_rupees(rules.approval_threshold)}")
    if new_payee_hold:
        reasons.append(f"first payment of {_rupees(txn.amount)} to a new payee")

    if needs_approval and has_active_guardian:
        return Decision(Outcome.NEEDS_APPROVAL, reasons,
                        approval_timeout_minutes=rules.approval_timeout_minutes)
    if needs_approval:
        reasons.append("no active guardian to approve, so a cooling-off delay applies instead")
    if needs_approval or new_payee_hold:
        return Decision(Outcome.DELAY, reasons, delay_minutes=rules.cooling_off_minutes)
    return Decision(Outcome.ALLOW, [])
