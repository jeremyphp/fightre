"""Proof-of-work challenges and single-use nonce tracking.

A challenge is a signed, expiring statement: *"whoever answers me has to burn
N bits of SHA-256 work and hand me a fresh client attestation"*.  The work is
cheap for one browser tab and expensive at 10k requests/second, which is the
point: it moves the cost curve of scraping without ever blocking a human.

The token is self-contained (HMAC + expiry, no server state).  Only *solved*
challenges are remembered, so a stolen solution cannot be replayed.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import threading
import time
from dataclasses import dataclass
from typing import Dict, Optional, Tuple

TOKEN_VERSION = "v1"
MAX_TOKEN_LEN = 4096


# --------------------------------------------------------------------------
# encoding helpers
# --------------------------------------------------------------------------
def b64u_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def b64u_decode(text: str) -> bytes:
    padding = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + padding)


def canonical_json(payload: object) -> bytes:
    """Stable JSON encoding used for every signature in this package."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )


# --------------------------------------------------------------------------
# proof of work
# --------------------------------------------------------------------------
def leading_zero_bits(digest: bytes) -> int:
    """Count leading zero bits of a byte string."""
    total = 0
    for byte in digest:
        if byte == 0:
            total += 8
            continue
        total += 8 - byte.bit_length()
        break
    return total


def pow_digest(seed: str, nonce: int) -> bytes:
    return hashlib.sha256(f"{seed}:{nonce}".encode("utf-8")).digest()


def pow_matches(seed: str, nonce: int, difficulty: int) -> bool:
    return leading_zero_bits(pow_digest(seed, nonce)) >= difficulty


def solve_pow(seed: str, difficulty: int, max_iterations: int = 1 << 28) -> Optional[int]:
    """Find a nonce satisfying *difficulty* leading zero bits (client-side)."""
    for nonce in range(max_iterations):
        if pow_matches(seed, nonce, difficulty):
            return nonce
    return None


# --------------------------------------------------------------------------
# nonce store
# --------------------------------------------------------------------------
class NonceStore:
    """Thread-safe, bounded TTL set used for replay defense."""

    def __init__(self, ttl_seconds: float = 300.0, max_entries: int = 200_000) -> None:
        self.ttl = float(ttl_seconds)
        self.max_entries = int(max_entries)
        self._seen: Dict[str, float] = {}
        self._lock = threading.Lock()

    def consume(self, key: str, ttl: Optional[float] = None, now: Optional[float] = None) -> bool:
        """Mark *key* as used.

        Returns ``True`` when the key was fresh (request may proceed) and
        ``False`` when it was already used (replay).
        """
        if not key:
            return False
        stamp = time.time() if now is None else now
        expiry = stamp + (self.ttl if ttl is None else float(ttl))
        with self._lock:
            if len(self._seen) >= self.max_entries:
                self._prune_locked(stamp)
            previous = self._seen.get(key)
            if previous is not None and previous > stamp:
                return False
            self._seen[key] = expiry
            return True

    def seen(self, key: str, now: Optional[float] = None) -> bool:
        stamp = time.time() if now is None else now
        with self._lock:
            expiry = self._seen.get(key)
            return expiry is not None and expiry > stamp

    def _prune_locked(self, now: float) -> None:
        expired = [k for k, exp in self._seen.items() if exp <= now]
        for key in expired:
            del self._seen[key]
        # Still full: drop the oldest half rather than grow without bound.
        if len(self._seen) >= self.max_entries:
            ordered = sorted(self._seen.items(), key=lambda kv: kv[1])
            for key, _ in ordered[: len(ordered) // 2]:
                del self._seen[key]

    def prune(self, now: Optional[float] = None) -> int:
        stamp = time.time() if now is None else now
        with self._lock:
            before = len(self._seen)
            self._prune_locked(stamp)
            return before - len(self._seen)

    def __len__(self) -> int:
        return len(self._seen)


# --------------------------------------------------------------------------
# challenge issuer
# --------------------------------------------------------------------------
@dataclass(frozen=True)
class Challenge:
    jti: str
    subject: str
    difficulty: int
    issued_at: float
    expires_at: float

    @property
    def seed(self) -> str:
        return self.jti


class ChallengeIssuer:
    """Issues and verifies HMAC-signed proof-of-work challenges."""

    def __init__(
        self,
        secret: str,
        ttl_seconds: int = 120,
        difficulty: int = 18,
        store: Optional[NonceStore] = None,
    ) -> None:
        if not secret:
            raise ValueError("challenge secret must not be empty")
        self.secret = secret.encode("utf-8")
        self.ttl = int(ttl_seconds)
        self.difficulty = int(difficulty)
        self._solved = (
            store if store is not None else NonceStore(ttl_seconds=max(self.ttl * 2, 120))
        )

    # -- keys --------------------------------------------------------------
    def attest_key(self, jti: str) -> bytes:
        """Per-challenge key handed to the client to sign its attestation."""
        return hmac.new(self.secret, f"attest:{jti}".encode("utf-8"), hashlib.sha256).digest()

    # -- issue -------------------------------------------------------------
    def issue(self, subject: str = "anon", difficulty: Optional[int] = None,
              now: Optional[float] = None) -> Dict[str, object]:
        stamp = time.time() if now is None else now
        diff = int(self.difficulty if difficulty is None else difficulty)
        jti = secrets.token_hex(12)
        payload = {
            "v": 1,
            "jti": jti,
            "sub": subject[:120],
            "diff": diff,
            "iat": round(stamp, 3),
            "exp": round(stamp + self.ttl, 3),
        }
        body = canonical_json(payload)
        signature = hmac.new(self.secret, b"challenge." + body, hashlib.sha256).digest()
        token = f"{TOKEN_VERSION}.{b64u_encode(body)}.{b64u_encode(signature)}"
        return {
            "token": token,
            "jti": jti,
            "difficulty": diff,
            "algorithm": "sha256-leading-zero-bits",
            "expires_in": self.ttl,
            "attest_key": b64u_encode(self.attest_key(jti)),
        }

    # -- verify ------------------------------------------------------------
    def verify(self, token: str, now: Optional[float] = None) -> Optional[Challenge]:
        """Return the Challenge when the token is authentic and unexpired."""
        if not token or len(token) > MAX_TOKEN_LEN:
            return None
        parts = token.split(".")
        if len(parts) != 3 or parts[0] != TOKEN_VERSION:
            return None
        try:
            body = b64u_decode(parts[1])
            signature = b64u_decode(parts[2])
        except (ValueError, TypeError):
            return None
        expected = hmac.new(self.secret, b"challenge." + body, hashlib.sha256).digest()
        if not hmac.compare_digest(signature, expected):
            return None
        try:
            payload = json.loads(body.decode("utf-8"))
            challenge = Challenge(
                jti=str(payload["jti"]),
                subject=str(payload.get("sub", "anon")),
                difficulty=int(payload["diff"]),
                issued_at=float(payload["iat"]),
                expires_at=float(payload["exp"]),
            )
        except (ValueError, KeyError, TypeError, UnicodeDecodeError):
            return None
        stamp = time.time() if now is None else now
        if challenge.expires_at < stamp:
            return None
        if not (1 <= challenge.difficulty <= 32):
            return None
        return challenge

    # -- solution ----------------------------------------------------------
    def check_solution(
        self, challenge: Challenge, nonce: object, now: Optional[float] = None
    ) -> Tuple[bool, str]:
        try:
            nonce_int = int(nonce)  # type: ignore[arg-type]
        except (TypeError, ValueError):
            return False, "nonce must be an integer"
        if nonce_int < 0 or nonce_int > (1 << 63):
            return False, "nonce out of range"
        if not pow_matches(challenge.seed, nonce_int, challenge.difficulty):
            return False, "insufficient work"
        if not self._solved.consume(challenge.jti, ttl=self.ttl * 2, now=now):
            return False, "challenge already solved"
        return True, "ok"


__all__ = [
    "Challenge",
    "ChallengeIssuer",
    "NonceStore",
    "b64u_decode",
    "b64u_encode",
    "canonical_json",
    "leading_zero_bits",
    "pow_matches",
    "solve_pow",
]
