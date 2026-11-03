"""Shared state: local memory by default, Redis when configured.

Why this module exists
----------------------

Attestation and signatures are stateless: any worker can verify them. Replay
defence, rate limiting, path diversity and canary attribution are *not* -- they
need to agree across workers. This module gives every one of those a backend:

* ``memory`` (default): the classes the single-process demo already uses;
* ``redis``: thin wrappers over a Redis server, with a **local fallback**.

The fallback rule is explicit: if Redis is unreachable, a store degrades to its
in-memory twin and counts the failure. Availability wins over perfect
coordination -- a worker that cannot reach Redis should keep serving and keep
*some* replay protection, not return 500s to every user.
"""

from __future__ import annotations

import json
import threading
import time
from collections import deque
from dataclasses import dataclass
from typing import Deque, Dict, List, Optional, Tuple

from .canary import TOKEN_RE, Canary, CanaryRegistry
from .challenge import NonceStore
from .config import Config
from .ratelimit import RateLimiter
from .redis import RedisClient, RedisError

CANARY_TTL_SECONDS = 60 * 60 * 24 * 90


class SequenceTracker:
    """Counts distinct paths per identity in a sliding window."""

    def __init__(self, window_seconds: int = 60, distinct: int = 25, max_keys: int = 20_000) -> None:
        self.window = float(window_seconds)
        self.distinct = int(distinct)
        self.max_keys = int(max_keys)
        self._events: Dict[str, Deque[Tuple[float, str]]] = {}
        self._lock = threading.Lock()

    def hit(self, identity: str, path: str, now: Optional[float] = None) -> bool:
        stamp = time.time() if now is None else now
        with self._lock:
            if len(self._events) > self.max_keys:
                self._events.clear()
            events = self._events.setdefault(identity, deque())
            cutoff = stamp - self.window
            while events and events[0][0] < cutoff:
                events.popleft()
            events.append((stamp, path))
            if len({p for _, p in events}) >= self.distinct:
                events.clear()
                return True
            return False


# --------------------------------------------------------------------------
# Redis-backed stores
# --------------------------------------------------------------------------
class RedisNonceStore:
    """Single-use keys via ``SET key 1 NX EX ttl`` (atomic on the server)."""

    def __init__(
        self,
        client: RedisClient,
        default_ttl: int = 600,
        prefix: str = "nonce",
        fallback: Optional[NonceStore] = None,
    ) -> None:
        self.client = client
        self.default_ttl = int(default_ttl)
        self.prefix = prefix
        self.fallback = fallback

    def consume(self, key: str, ttl: Optional[float] = None, now: Optional[float] = None) -> bool:
        seconds = int(max(1, ttl if ttl is not None else self.default_ttl))
        try:
            reply = self.client.command(
                "SET", self.client.key(self.prefix, key), "1", "NX", "EX", seconds
            )
        except RedisError:
            if self.fallback is not None:
                return self.fallback.consume(key, ttl=seconds, now=now)
            return True
        return reply is not None and str(reply).upper() == "OK"

    def seen(self, key: str, now: Optional[float] = None) -> bool:
        try:
            return self.client.command("GET", self.client.key(self.prefix, key)) is not None
        except RedisError:
            return self.fallback.seen(key, now=now) if self.fallback is not None else False


class RedisRateLimiter:
    """Fixed-window counter: ``INCR`` per window bucket, ``EXPIRE`` on first hit.

    A window is chosen so that it holds a full burst (``burst / rate`` seconds),
    which approximates the in-memory token bucket at every window boundary and
    is exact for "N requests per window" semantics inside it.
    """

    def __init__(
        self,
        client: RedisClient,
        limit: int,
        window_seconds: float,
        prefix: str = "rate",
        fallback: Optional[RateLimiter] = None,
    ) -> None:
        self.client = client
        self.limit = max(1, int(limit))
        self.window = max(1.0, float(window_seconds))
        self.prefix = prefix
        self.fallback = fallback

    def allow(self, identity: str, cost: float = 1.0) -> Tuple[bool, float]:
        now = time.time()
        bucket = int(now // self.window)
        key = self.client.key(self.prefix, identity, bucket)
        try:
            count = int(self.client.command("INCR", key))
            if count == 1:
                self.client.command("EXPIRE", key, int(self.window) + 1)
        except (RedisError, TypeError, ValueError):
            if self.fallback is not None:
                return self.fallback.allow(identity, cost)
            return True, 0.0
        allowed = count <= self.limit
        retry_after = 0.0 if allowed else max(0.0, self.window - (now % self.window))
        return allowed, retry_after


class RedisCanaryStore:
    """Remote half of a canary registry, so worker B recognises worker A's bait."""

    def __init__(self, client: RedisClient, ttl_seconds: int = CANARY_TTL_SECONDS,
                 prefix: str = "canary") -> None:
        self.client = client
        self.ttl = int(ttl_seconds)
        self.prefix = prefix

    def put(self, canary: Canary) -> None:
        try:
            self.client.command(
                "SET",
                self.client.key(self.prefix, canary.token),
                json.dumps(canary.as_dict(), ensure_ascii=False),
                "EX",
                self.ttl,
            )
        except RedisError:
            pass  # local registry still has it; attribution degrades, service does not

    def get(self, token: str) -> Optional[Canary]:
        try:
            raw = self.client.command("GET", self.client.key(self.prefix, token))
        except RedisError:
            return None
        if raw is None:
            return None
        try:
            data = json.loads(raw.decode("utf-8") if isinstance(raw, bytes) else str(raw))
            return Canary(
                token=str(data["token"]),
                owner=str(data.get("owner", "")),
                created=float(data.get("created", 0.0)),
                meta=dict(data.get("meta") or {}),
            )
        except (ValueError, KeyError, TypeError):
            return None


class HybridCanaryRegistry:
    """Local registry (authoritative, fast) with a Redis write-through cache."""

    def __init__(self, local: CanaryRegistry, remote: RedisCanaryStore) -> None:
        self.local = local
        self.remote = remote

    def issue(self, owner: str, meta: Optional[Dict[str, object]] = None,
              now: Optional[float] = None) -> Canary:
        canary = self.local.issue(owner, meta, now=now)
        self.remote.put(canary)
        return canary

    def get(self, token: str) -> Optional[Canary]:
        found = self.local.get(token)
        return found if found is not None else self.remote.get(token)

    def find(self, text: str) -> List[Canary]:
        results: List[Canary] = []
        for match in TOKEN_RE.finditer(text or ""):
            entry = self.get(match.group(0))
            if entry is not None:
                results.append(entry)
        return results

    def unknown_tokens(self, text: str) -> List[str]:
        return [m.group(0) for m in TOKEN_RE.finditer(text or "") if self.get(m.group(0)) is None]

    def expire(self, now: Optional[float] = None) -> int:
        return self.local.expire(now)

    def __len__(self) -> int:
        return len(self.local)


class RedisSequenceTracker:
    """Distinct-path counting across two adjacent window buckets."""

    def __init__(
        self,
        client: RedisClient,
        window_seconds: int = 60,
        distinct: int = 25,
        prefix: str = "seq",
        fallback: Optional[SequenceTracker] = None,
    ) -> None:
        self.client = client
        self.window = max(1.0, float(window_seconds))
        self.distinct = int(distinct)
        self.prefix = prefix
        self.fallback = fallback

    def hit(self, identity: str, path: str, now: Optional[float] = None) -> bool:
        stamp = time.time() if now is None else now
        bucket = int(stamp // self.window)
        current = self.client.key(self.prefix, identity, bucket)
        try:
            self.client.command("SADD", current, path)
            self.client.command("EXPIRE", current, int(self.window) * 2)
            count = int(self.client.command("SCARD", current) or 0)
            previous = self.client.command("SCARD", self.client.key(self.prefix, identity, bucket - 1))
            count += int(previous or 0)
        except (RedisError, TypeError, ValueError):
            return self.fallback.hit(identity, path, now=stamp) if self.fallback is not None else False
        if count >= self.distinct:
            try:
                self.client.command("DEL", current)
            except RedisError:
                pass
            return True
        return False


# --------------------------------------------------------------------------
# bundle
# --------------------------------------------------------------------------
@dataclass
class Stores:
    nonce: object
    rate: object
    canaries: object
    sequence: object
    backend: str = "memory"
    client: Optional[RedisClient] = None

    def health(self) -> Dict[str, object]:
        if self.client is None:
            return {"backend": self.backend, "ok": True, "errors": 0}
        return {"backend": "redis", "ok": self.client.ping(), "errors": self.client.errors}


def build_stores(config: Optional[Config] = None, secret: str = "") -> Stores:
    """Return memory stores, or Redis-backed stores when configured."""
    config = config or Config()
    memory = Stores(
        nonce=NonceStore(ttl_seconds=max(config.challenge.ttl_seconds * 2, 600)),
        rate=RateLimiter(config.rate.rate, config.rate.burst),
        canaries=CanaryRegistry(),
        sequence=SequenceTracker(config.sequence_window_seconds, config.sequence_paths),
        backend="memory",
    )
    settings = config.redis
    if not settings.enabled:
        return memory

    client = RedisClient(
        host=settings.host,
        port=settings.port,
        db=settings.db,
        password=settings.password,
        timeout=settings.timeout,
        max_connections=settings.max_connections,
        prefix=settings.prefix,
    )
    window = max(1.0, float(config.rate.burst) / max(float(config.rate.rate), 0.01))
    return Stores(
        nonce=RedisNonceStore(
            client,
            default_ttl=max(config.challenge.ttl_seconds * 2, 600),
            fallback=memory.nonce,
        ),
        rate=RedisRateLimiter(
            client, limit=int(config.rate.burst), window_seconds=window, fallback=memory.rate
        ),
        canaries=HybridCanaryRegistry(memory.canaries, RedisCanaryStore(client)),
        sequence=RedisSequenceTracker(
            client,
            window_seconds=config.sequence_window_seconds,
            distinct=config.sequence_paths,
            fallback=memory.sequence,
        ),
        backend="redis",
        client=client,
    )


__all__ = [
    "CANARY_TTL_SECONDS",
    "HybridCanaryRegistry",
    "RedisCanaryStore",
    "RedisNonceStore",
    "RedisRateLimiter",
    "RedisSequenceTracker",
    "SequenceTracker",
    "Stores",
    "build_stores",
]
