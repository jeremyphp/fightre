"""Request signing (HMAC-SHA256) for machine clients and app-to-app calls.

Browsers cannot keep a secret, so signing is *not* used to authenticate the
browser -- attestation covers that imperfectly.  Signing is for the clients that
genuinely can hold a key: partner integrations, your own mobile backend, service
to service traffic.  There it gives replay protection, payload binding and key
rotation for free.

Wire format::

    Authorization: FightRE-Key <key-id>
    X-FightRE-Sign: v1:<unix-ts>:<nonce>:<hex-hmac>

Canonical string::

    METHOD \n PATH \n sha256(body) \n TS \n NONCE
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from . import signals as sig
from .challenge import NonceStore
from .signals import Signal

SIGN_HEADER = "x-fightre-sign"
AUTH_PREFIX = "fightre-key"
MAX_CLOCK_SKEW = 300


@dataclass
class SignatureResult:
    ok: bool
    key_id: str = ""
    reason: str = "absent"
    signals: List[Signal] = field(default_factory=list)

    def as_dict(self) -> Dict[str, object]:
        return {
            "ok": self.ok,
            "key_id": self.key_id,
            "reason": self.reason,
            "signals": [s.name for s in self.signals],
        }


class RequestSigner:
    """Verifies HMAC request signatures and enforces nonce uniqueness."""

    def __init__(
        self,
        api_keys: Optional[Dict[str, str]] = None,
        clock_skew: int = MAX_CLOCK_SKEW,
        store: Optional[NonceStore] = None,
    ) -> None:
        self.api_keys = {str(k): str(v) for k, v in (api_keys or {}).items()}
        self.clock_skew = int(clock_skew)
        self.store = store or NonceStore(ttl_seconds=max(self.clock_skew * 2, 600))

    # -- canonical form ----------------------------------------------------
    @staticmethod
    def canonical(method: str, path: str, body: bytes, ts: str, nonce: str) -> str:
        body_hash = hashlib.sha256(body or b"").hexdigest()
        return "\n".join([method.upper(), path, body_hash, str(ts), str(nonce)])

    def sign(
        self,
        key_id: str,
        method: str,
        path: str,
        body: bytes = b"",
        ts: Optional[str] = None,
        nonce: Optional[str] = None,
    ) -> Tuple[str, str]:
        """Return ``(authorization_value, signature_header_value)``."""
        key = self.api_keys.get(key_id)
        if key is None:
            raise KeyError(f"unknown api key {key_id!r}")
        stamp = str(int(time.time()) if ts is None else int(ts))
        token = nonce or secrets.token_hex(8)
        message = self.canonical(method, path, body, stamp, token)
        digest = hmac.new(key.encode("utf-8"), message.encode("utf-8"), hashlib.sha256).hexdigest()
        return f"{AUTH_PREFIX} {key_id}", f"v1:{stamp}:{token}:{digest}"

    # -- verification ------------------------------------------------------
    def verify(
        self,
        method: str,
        path: str,
        headers: Dict[str, str],
        body: bytes = b"",
        now: Optional[float] = None,
    ) -> SignatureResult:
        lookup = {k.lower(): v for k, v in headers.items()}
        auth = lookup.get("authorization", "")
        sign_header = lookup.get(SIGN_HEADER, "")
        if not auth and not sign_header:
            return SignatureResult(ok=False, reason="absent")

        if not auth.lower().startswith(AUTH_PREFIX + " "):
            return SignatureResult(
                ok=False,
                reason="bad-scheme",
                signals=[sig.make("app.bad_signature", "unexpected Authorization scheme")],
            )
        key_id = auth.split(" ", 1)[1].strip()
        secret = self.api_keys.get(key_id)
        if secret is None:
            return SignatureResult(
                ok=False,
                key_id=key_id,
                reason="unknown-key",
                signals=[sig.make("app.bad_signature", f"unknown key id {key_id[:24]!r}")],
            )

        parts = sign_header.split(":")
        if len(parts) != 4 or parts[0] != "v1":
            return SignatureResult(
                ok=False,
                key_id=key_id,
                reason="malformed",
                signals=[sig.make("app.bad_signature", "malformed signature header")],
            )
        version, ts, nonce, digest = parts
        try:
            stamp = float(ts)
        except ValueError:
            return SignatureResult(
                ok=False,
                key_id=key_id,
                reason="bad-timestamp",
                signals=[sig.make("app.bad_signature", "non-numeric timestamp")],
            )
        current = time.time() if now is None else now
        if abs(current - stamp) > self.clock_skew:
            return SignatureResult(
                ok=False,
                key_id=key_id,
                reason="clock-skew",
                signals=[sig.make("app.timestamp_skew", f"{int(abs(current - stamp))}s")],
            )

        message = self.canonical(method, path, body, ts, nonce)
        expected = hmac.new(secret.encode("utf-8"), message.encode("utf-8"),
                            hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, digest):
            return SignatureResult(
                ok=False,
                key_id=key_id,
                reason="bad-signature",
                signals=[sig.make("app.bad_signature", "HMAC mismatch")],
            )

        if not self.store.consume(f"sig:{key_id}:{nonce}", now=current):
            return SignatureResult(
                ok=False,
                key_id=key_id,
                reason="replay",
                signals=[sig.make("app.replay_detected", f"nonce {nonce[:16]} reused")],
            )
        return SignatureResult(ok=True, key_id=key_id, reason="ok")


__all__ = ["AUTH_PREFIX", "RequestSigner", "SIGN_HEADER", "SignatureResult"]
