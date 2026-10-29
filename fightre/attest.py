"""Client environment attestation.

What this proves (honestly): *a browser-like runtime executed our JavaScript
recently and returned a consistent picture of itself*.  What it does not prove:
that a human is on the other side.  Attestation raises the cost of automation
and gives us signals; it is not authentication.  Treat the trust it grants as a
discount on suspicion, never as a free pass.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from . import signals as sig
from .challenge import b64u_decode, b64u_encode, canonical_json
from .signals import Signal

MAX_BLOB = 8192
ATTEST_VERSION = 1

_SOFTWARE_RENDERERS = ("swiftshader", "llvmpipe", "softpipe", "microsoft basic render", "mesa offscreen")

_BROWSER_MARKERS = ("chrome", "firefox", "safari", "edg/", "opera", "opr/")


@dataclass
class AttestResult:
    ok: bool
    trust: float = 0.0
    signals: List[Signal] = field(default_factory=list)
    env: Dict[str, object] = field(default_factory=dict)
    reason: str = "missing"
    age_seconds: float = 0.0
    jti: str = ""

    def as_dict(self) -> Dict[str, object]:
        return {
            "ok": self.ok,
            "trust": round(self.trust, 2),
            "reason": self.reason,
            "age_seconds": round(self.age_seconds, 1),
            "jti": self.jti,
            "signals": [s.name for s in self.signals],
        }


def _truthy(value: object) -> bool:
    if isinstance(value, str):
        return value.strip().lower() in ("1", "true", "yes", "on")
    return bool(value)


def analyze_env(env: Dict[str, object]) -> Tuple[List[Signal], float]:
    """Turn environment observations into signals and a trust discount."""
    found: List[Signal] = []
    if not isinstance(env, dict) or len(env) < 3:
        found.append(sig.make("client.env_anomaly", "attestation carried almost no environment data"))
        return found, 0.0

    ua = str(env.get("ua", "")).lower()
    if _truthy(env.get("webdriver")):
        found.append(sig.make("client.webdriver", "navigator.webdriver=true"))
    if "headless" in ua:
        found.append(sig.make("client.headless_ua", "UA contains 'headless'"))
    if _truthy(env.get("cdp")):
        found.append(sig.make("client.cdp_runtime_leak", "CDP marker present"))
    if env.get("native_clean") is False:
        found.append(sig.make("client.function_tostring_patched", "patched native function(s)"))
    renderer = str(env.get("webgl_renderer", "")).lower()
    if any(marker in renderer for marker in _SOFTWARE_RENDERERS):
        found.append(sig.make("client.software_renderer", renderer[:60]))
    if env.get("consistent") is False:
        found.append(sig.make("client.signal_inconsistency", "platform/permission mismatch"))
    if _truthy(env.get("devtools_open")):
        found.append(sig.make("client.devtools_open", "viewport heuristic"))
    if _truthy(env.get("honeypot_filled")):
        found.append(sig.make("client.honeypot_clicked", "hidden form field was populated"))
    if _truthy(env.get("webdriver")) and str(env.get("hardware_concurrency", "")) in ("0", "1"):
        found.append(sig.make("client.env_anomaly", "automation runtime with single core"))

    # A browser claim without any browser marker is a strong inconsistency.
    if ua and any(m in ua for m in _BROWSER_MARKERS) and not env.get("webgl_renderer"):
        found.append(sig.make("client.env_anomaly", "browser UA without WebGL information"))

    discount = 0.0
    if any(s.weight >= 45 for s in found):
        discount = 1.0  # deep evidence cancels the good-citizen discount
    return found, discount


class AttestationVerifier:
    """Builds and verifies attestation blobs (signed with a per-challenge key)."""

    def __init__(self, secret: str, ttl_seconds: int = 3600, trust: float = 30.0) -> None:
        if not secret:
            raise ValueError("attestation secret must not be empty")
        self.secret = secret.encode("utf-8")
        self.ttl = int(ttl_seconds)
        self.trust = float(trust)

    def key_for(self, jti: str) -> bytes:
        return hmac.new(self.secret, f"attest:{jti}".encode("utf-8"), hashlib.sha256).digest()

    # -- producer (used by tests and the demo client; the browser does the same)
    def build(self, jti: str, env: Dict[str, object], now: Optional[float] = None) -> str:
        stamp = time.time() if now is None else now
        payload = {"v": ATTEST_VERSION, "jti": jti, "ts": round(stamp, 3), "env": env}
        body = canonical_json(payload)
        signature = hmac.new(self.key_for(jti), body, hashlib.sha256).digest()
        return f"{b64u_encode(body)}.{b64u_encode(signature)}"

    # -- verifier ----------------------------------------------------------
    def verify(self, blob: str, now: Optional[float] = None) -> AttestResult:
        stamp = time.time() if now is None else now
        if not blob or len(blob) > MAX_BLOB:
            return AttestResult(ok=False, reason="missing")
        parts = blob.split(".")
        if len(parts) != 2:
            return AttestResult(ok=False, reason="malformed")
        try:
            body = b64u_decode(parts[0])
            signature = b64u_decode(parts[1])
            payload = json.loads(body.decode("utf-8"))
        except (ValueError, TypeError, UnicodeDecodeError):
            return AttestResult(ok=False, reason="malformed")

        jti = str(payload.get("jti", ""))
        if not jti:
            return AttestResult(ok=False, reason="missing-jti")
        expected = hmac.new(self.key_for(jti), body, hashlib.sha256).digest()
        if not hmac.compare_digest(signature, expected):
            return AttestResult(ok=False, reason="bad-signature")

        try:
            issued = float(payload.get("ts", 0))
        except (TypeError, ValueError):
            return AttestResult(ok=False, reason="bad-timestamp")
        age = stamp - issued
        if age > self.ttl:
            return AttestResult(ok=False, reason="stale", age_seconds=age, jti=jti)
        if age < -60:
            return AttestResult(ok=False, reason="future", age_seconds=age, jti=jti)

        env = payload.get("env") or {}
        if not isinstance(env, dict):
            env = {}
        found, discount = analyze_env(env)
        trust = self.trust * (0.35 if discount else 1.0)
        if age > self.ttl * 0.5:
            found.append(sig.make("client.stale_attestation", f"age {age:.0f}s"))
            trust *= 0.7
        return AttestResult(
            ok=True,
            trust=trust,
            signals=found,
            env=env,
            reason="ok",
            age_seconds=age,
            jti=jti,
        )


__all__ = ["AttestResult", "AttestationVerifier", "analyze_env"]
