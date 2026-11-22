"""In-process sliding-window rate limiter.

Good enough for a single-node pilot. With several API nodes, move the counters to
Redis (or the API gateway) so the limit applies across nodes.
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
