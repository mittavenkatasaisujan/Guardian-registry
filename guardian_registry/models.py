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


class ChangeStatus(str, Enum):
    PENDING = "pending"
    APPLIED = "applied"
    VETOED = "vetoed"


CHANNELS = ("upi", "imps", "neft", "rtgs", "card", "netbanking")


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
        if self.kill_switch and not new.kill_switch:
            return True
        return False


@dataclass
class Transaction:
    amount: int        # paise
    payee: str         # VPA / account ref, as the bank sees it
    channel: str = "upi"


@dataclass
class Decision:
    outcome: Outcome
    reasons: list[str]
    delay_minutes: int = 0
    approval_timeout_minutes: int = 0
