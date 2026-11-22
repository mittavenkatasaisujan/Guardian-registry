"""Injectable clock so time-based rules (delays, expiry, daily limits) are testable."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

IST = timezone(timedelta(hours=5, minutes=30))


class Clock:
    def now(self) -> datetime:
        return datetime.now(timezone.utc)


class FixedClock(Clock):
    """A clock that only moves when told to. Used in tests and the demo."""

    def __init__(self, start: datetime | None = None):
        self._now = start or datetime(2026, 11, 23, 4, 30, tzinfo=timezone.utc)

    def now(self) -> datetime:
        return self._now

    def advance(self, **kwargs) -> None:
        self._now = self._now + timedelta(**kwargs)


def ist_day(ts: datetime) -> str:
    """Daily limits reset at midnight India time, not UTC."""
    return ts.astimezone(IST).date().isoformat()


def iso(ts: datetime) -> str:
    return ts.astimezone(timezone.utc).isoformat()


def parse(ts: str) -> datetime:
    return datetime.fromisoformat(ts)
