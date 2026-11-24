"""Domain types. Money is always integer paise to avoid float rounding."""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from enum import Enum


class Outcome(str, Enum):
    ALLOW = "allow"
    DELAY = "delay"                    # cooling-off: goes through later unless cancelled
    NEEDS_APPROVAL = "needs_approval"  # a guardian must approve
    BLOCK = "block"


class CheckStatus(str, Enum):
    ALLOWED = "allowed"
    COOLING_OFF = "cooling_off"
    RELEASED = "released"              # cooling-off ended without cancellation
    PENDING_APPROVAL = "pending_approval"
    APPROVED = "approved"
    DENIED = "denied"
    EXPIRED = "expired"
    CANCELLED = "cancelled"
    BLOCKED = "blocked"
    FAILED = "failed"                  # bank reported the payment did not complete

    @property
    def counts_as_spend(self) -> bool:
        """Statuses whose amount counts toward the daily limit (money moved or will move)."""
        return self in {
            CheckStatus.ALLOWED, CheckStatus.COOLING_OFF, CheckStatus.RELEASED,
            CheckStatus.PENDING_APPROVAL, CheckStatus.APPROVED,
        }

    @property
    def is_final_go(self) -> bool:
        """The bank may execute the payment."""
        return self in {CheckStatus.ALLOWED, CheckStatus.RELEASED, CheckStatus.APPROVED}


class GuardianStatus(str, Enum):
    INVITED = "invited"
    ACTIVE = "active"
    DECLINED = "declined"
    ENDED = "ended"


class ChangeKind(str, Enum):
    UPDATE_RULES = "update_rules"
    KILL_SWITCH_OFF = "kill_switch_off"
    REMOVE_GUARDIAN = "remove_guardian"
    CHANGE_MOBILE = "change_mobile"


class ChangeStatus(str, Enum):
    PENDING = "pending"
    APPLIED = "applied"
    VETOED = "vetoed"


CHANNELS = ("upi", "imps", "neft", "rtgs", "card", "netbanking")
# What a payment is, as the bank knows it. RBI's Nov 2026 draft treats these differently: the trusted
# person mechanism leaves out merchant and recurring payments, and the Stop Switch lets existing
# recurring mandates continue while blocking new ones.
KINDS = ("transfer", "merchant", "recurring", "new_mandate")
APPROVAL_SCOPES = ("all", "rbi")


def quiet_hours_set(q: dict | None) -> set[int]:
    """The IST hours (0-23) a quiet-hours rule covers. start == end covers nothing (refused)."""
    if not q:
        return set()
    s, e = q["start"], q["end"]
    return {h for h in range(24) if (s <= h < e if s < e else h >= s or h < e)}


@dataclass
class Rules:
    """A person's protection rules. `None` means "no limit" for that field."""

    per_txn_limit: int | None = None            # hard block above this
    daily_limit: int | None = None              # hard block if day total would exceed
    approval_threshold: int | None = None       # guardian approval at or above this
    new_payee_delay_threshold: int | None = None  # cooling-off for first payment to a payee at or above this
    cooling_off_minutes: int = 60
    approval_timeout_minutes: int = 30
    blocked_channels: list[str] = field(default_factory=list)
    require_verified_guardian: bool = False     # only bank-KYC'd guardians may approve
    sim_swap_hold: bool = True                  # extra holds while a SIM change is recent
    scam_signals: bool = False                  # hold payments that look coached (scamsignals.py)
    # RBI draft directions of Nov 2026 (customer-induced controls and the trusted person mechanism):
    per_payee_daily_limit: int | None = None    # block if today's total to one payee would go over
    channel_daily_limits: dict[str, int] = field(default_factory=dict)  # block if a channel's day total would go over
    approval_scope: str = "all"                 # "all", or "rbi": not UPI, merchant or recurring payments
    new_guardian_wait_hours: int = 0            # a newly accepted guardian approves only after this wait
    # chosen channels switched off during set hours (IST), e.g. {"channels": ["upi"], "start": 22, "end": 6}
    quiet_hours: dict | None = None
    kill_switch: bool = False

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "Rules":
        known = {k: d[k] for k in cls.__dataclass_fields__ if k in d}
        return cls(**known)

    def is_loosening(self, new: "Rules") -> bool:
        """True if `new` gives less protection than `self` in any dimension.

        Loosening is the move a fraudster coaches a victim into, so it is held
        for a cooling-off period or a guardian's approval. Tightening applies at once.
        """
        def looser_limit(old: int | None, nxt: int | None) -> bool:
            if old is None:
                return False          # already unlimited; can't get looser
            return nxt is None or nxt > old

        if looser_limit(self.per_txn_limit, new.per_txn_limit):
            return True
        if looser_limit(self.daily_limit, new.daily_limit):
            return True
        if looser_limit(self.approval_threshold, new.approval_threshold):
            return True
        if looser_limit(self.new_payee_delay_threshold, new.new_payee_delay_threshold):
            return True
        if new.cooling_off_minutes < self.cooling_off_minutes:
            return True
        if new.approval_timeout_minutes > self.approval_timeout_minutes:
            return True  # longer window gives a coached victim more time to pressure a guardian
        if set(self.blocked_channels) - set(new.blocked_channels):
            return True
        if self.require_verified_guardian and not new.require_verified_guardian:
            return True
        if self.sim_swap_hold and not new.sim_swap_hold:
            return True
        if self.scam_signals and not new.scam_signals:
            return True
        if looser_limit(self.per_payee_daily_limit, new.per_payee_daily_limit):
            return True
        for ch, limit in self.channel_daily_limits.items():
            if looser_limit(limit, new.channel_daily_limits.get(ch)):
                return True
        if self.approval_scope == "all" and new.approval_scope != "all":
            return True   # fewer payments go to the trusted person
        if new.new_guardian_wait_hours < self.new_guardian_wait_hours:
            return True
        if self.quiet_hours:
            if not new.quiet_hours:
                return True
            if set(self.quiet_hours["channels"]) - set(new.quiet_hours["channels"]):
                return True   # a channel is no longer switched off at night
            if quiet_hours_set(self.quiet_hours) - quiet_hours_set(new.quiet_hours):
                return True   # fewer hours covered
        if self.kill_switch and not new.kill_switch:
            return True
        return False


@dataclass
class Transaction:
    amount: int        # paise
    payee: str         # VPA / account ref, as the bank sees it
    channel: str = "upi"
    kind: str = "transfer"   # see KINDS


@dataclass
class Decision:
    outcome: Outcome
    reasons: list[str]
    delay_minutes: int = 0
    approval_timeout_minutes: int = 0
