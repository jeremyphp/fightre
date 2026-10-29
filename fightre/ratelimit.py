"""Token-bucket rate limiting, per identity, in process.

Small on purpose: this is the L1 backstop, not a replacement for your edge WAF.
It exists so that a single-process deployment still has a rate signal, and so
the demo is honest about where the number comes from.
"""

from __future__ import annotations

import threading
import time
from typing import Callable, Dict, Tuple


class TokenBucket:
    """Classic token bucket with lazy refill."""

    __slots__ = ("rate", "burst", "tokens", "updated", "clock")

    def __init__(self, rate: float, burst: float, clock: Callable[[], float] = time.monotonic) -> None:
        self.rate = max(0.0, float(rate))
        self.burst = max(1.0, float(burst))
        self.tokens = self.burst
        self.updated = clock()
        self.clock = clock

    def take(self, cost: float = 1.0) -> bool:
        now = self.clock()
        elapsed = max(0.0, now - self.updated)
        self.tokens = min(self.burst, self.tokens + elapsed * self.rate)
        self.updated = now
        if self.tokens >= cost:
            self.tokens -= cost
            return True
        return False

    def retry_after(self, cost: float = 1.0) -> float:
        if self.rate <= 0:
            return float("inf")
        missing = max(0.0, cost - self.tokens)
        return missing / self.rate


class RateLimiter:
    """Per-identity buckets with opportunistic pruning."""

    def __init__(
        self,
        rate: float = 0.5,
        burst: float = 40.0,
        max_keys: int = 50_000,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.rate = float(rate)
        self.burst = float(burst)
        self.max_keys = int(max_keys)
        self.clock = clock
        self._buckets: Dict[str, TokenBucket] = {}
        self._lock = threading.Lock()

    def allow(self, identity: str, cost: float = 1.0) -> Tuple[bool, float]:
        """Return ``(allowed, retry_after_seconds)``."""
        with self._lock:
            bucket = self._buckets.get(identity)
            if bucket is None:
                if len(self._buckets) >= self.max_keys:
                    self._prune_locked()
                bucket = TokenBucket(self.rate, self.burst, self.clock)
                self._buckets[identity] = bucket
            allowed = bucket.take(cost)
            return allowed, (0.0 if allowed else bucket.retry_after(cost))

    def _prune_locked(self) -> None:
        # Drop buckets that have fully refilled: they carry no state worth keeping.
        full = [key for key, bucket in self._buckets.items() if bucket.tokens >= bucket.burst]
        for key in full:
            del self._buckets[key]
        if len(self._buckets) >= self.max_keys:
            self._buckets.clear()

    def __len__(self) -> int:
        return len(self._buckets)


__all__ = ["RateLimiter", "TokenBucket"]
