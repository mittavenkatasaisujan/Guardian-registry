"""Rate limiters.

RateLimiter is an in-process sliding window: fine for one node. SharedRateLimiter keeps
fixed-window counters in the database so several API nodes enforce one limit.
"""

from __future__ import annotations

import re
import threading
import time
from collections import defaultdict, deque


class RateLimiter:
    def __init__(self, limit: int, per_seconds: float, now=time.monotonic):
        self.limit, self.per = limit, per_seconds
        self._now = now
        self._hits: dict[str, deque] = defaultdict(deque)
        self._lock = threading.Lock()

    @classmethod
    def parse(cls, spec: str, now=time.monotonic) -> "RateLimiter":
        """'600/60' -> 600 requests per 60 seconds."""
        m = re.fullmatch(r"\s*(\d+)\s*/\s*(\d+(?:\.\d+)?)\s*", spec)
        if not m:
            raise ValueError(f"bad rate limit spec {spec!r}; use 'requests/seconds'")
        return cls(int(m.group(1)), float(m.group(2)), now)

    def hit(self, key: str) -> tuple[bool, float]:
        """Record one request. Returns (allowed, seconds until a slot frees up)."""
        t = self._now()
        with self._lock:
            q = self._hits[key]
            while q and q[0] <= t - self.per:
                q.popleft()
            if len(q) >= self.limit:
                return False, max(q[0] + self.per - t, 0.0)
            q.append(t)
            return True, 0.0


class SharedRateLimiter:
    """Fixed-window counter kept in the registry's database, so every API node that shares
    the database enforces ONE limit. Select it with GR_RATE_BACKEND=db.

    A fixed window lets through at most 2x the limit across a window boundary; that is the
    usual trade for needing only one row per key and window."""

    def __init__(self, db, name: str, limit: int, per_seconds: float, now=time.time):
        self.db, self.name, self.limit, self.per, self._now = db, name, limit, per_seconds, now

    @classmethod
    def parse(cls, db, name: str, spec: str, now=time.time) -> "SharedRateLimiter":
        base = RateLimiter.parse(spec)
        return cls(db, name, base.limit, base.per, now)

    def hit(self, key: str) -> tuple[bool, float]:
        t = self._now()
        window = int(t // self.per)
        end = (window + 1) * self.per
        bucket = f"{self.name}:{key}:{window}"
        with self.db.tx() as c:
            c.execute("INSERT INTO rate_counters (bucket, count, window_end) VALUES (?, 1, ?) "
                      "ON CONFLICT(bucket) DO UPDATE SET count = rate_counters.count + 1", (bucket, end))
            n = c.execute("SELECT count FROM rate_counters WHERE bucket=?", (bucket,)).fetchone()["count"]
            if window % 50 == 0:  # occasional clean-up of finished windows
                c.execute("DELETE FROM rate_counters WHERE window_end < ?", (t - self.per,))
        if n > self.limit:
            return False, max(end - t, 0.0)
        return True, 0.0


def make_limiter(db, name: str, spec: str, backend: str | None = None):
    """'memory' (default, per process) or 'db' (shared by every node using the database)."""
    if (backend or "memory").lower() == "db":
        return SharedRateLimiter.parse(db, name, spec)
    return RateLimiter.parse(spec)
