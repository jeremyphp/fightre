"""TLS / HTTP/2 fingerprint ingestion.

FightRE does not terminate TLS, so it cannot read a ClientHello itself.  That is
deliberate: parsing TLS inside an application framework is fragile and usually
the wrong layer.  Instead the edge (nginx + ssl_preread, HAProxy, Envoy, a CDN
worker) computes the fingerprint and forwards it as a header.

Which creates the obvious problem -- anybody can send that header.  Therefore
edge headers are only trusted when the edge signs them::

    X-FightRE-Edge-Id:  <edge name>
    X-FightRE-Edge-Ts:  1720000000
    X-FightRE-JA3:      771,4865-4866-...,0-23-...,29-23-24,0
    X-FightRE-H2:       <akamai-style fingerprint string>
    X-FightRE-Edge-Sig: <hex hmac>

The signature covers ``edge1|ts|ja3|h2|client-ip`` with a shared secret.  No
signature, no trust -- unsigned fingerprint headers are themselves a signal.
"""

from __future__ import annotations

import hashlib
import hmac
import re
import time
from typing import Iterable, Optional, Sequence

EDGE_VERSION = "edge1"
_HEX32 = re.compile(r"^[0-9a-f]{32}$")


def ja3_string(
    version: object,
    ciphers: Sequence[object] = (),
    extensions: Sequence[object] = (),
    curves: Sequence[object] = (),
    point_formats: Sequence[object] = (),
) -> str:
    """Build the canonical JA3 string from ClientHello fields."""

    def join(values: Sequence[object]) -> str:
        return "-".join(str(v) for v in values)

    return ",".join(
        [str(version), join(ciphers), join(extensions), join(curves), join(point_formats)]
    )


def ja3_digest(
    version: object,
    ciphers: Sequence[object] = (),
    extensions: Sequence[object] = (),
    curves: Sequence[object] = (),
    point_formats: Sequence[object] = (),
) -> str:
    """MD5 of the JA3 string (the classic 32-hex JA3 hash)."""
    return hashlib.md5(
        ja3_string(version, ciphers, extensions, curves, point_formats).encode("utf-8")
    ).hexdigest()


def normalize_ja3(value: str) -> str:
    """Accept either a raw JA3 string or an already-hashed JA3."""
    text = (value or "").strip()
    if not text:
        return ""
    if _HEX32.match(text.lower()):
        return text.lower()
    return hashlib.md5(text.encode("utf-8")).hexdigest()


def h2_digest(settings: str = "", window_update: str = "", priority: str = "",
              pseudo_order: str = "") -> str:
    """Compact digest of an HTTP/2 fingerprint tuple (Akamai-style fields)."""
    payload = "|".join([settings or "", window_update or "", priority or "", pseudo_order or ""])
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]


def edge_signature(secret: str, ts: str, ja3: str, h2: str, client_ip: str) -> str:
    message = "|".join([EDGE_VERSION, str(ts), ja3 or "", h2 or "", client_ip or ""])
    return hmac.new(secret.encode("utf-8"), message.encode("utf-8"), hashlib.sha256).hexdigest()


def verify_edge_signature(
    secret: str,
    ts: str,
    sig: str,
    ja3: str,
    h2: str,
    client_ip: str,
    skew_seconds: int = 120,
    now: Optional[float] = None,
) -> bool:
    if not (secret and ts and sig):
        return False
    try:
        stamp = float(ts)
    except (TypeError, ValueError):
        return False
    current = time.time() if now is None else now
    if abs(current - stamp) > skew_seconds:
        return False
    expected = edge_signature(secret, ts, ja3, h2, client_ip)
    return hmac.compare_digest(expected, sig)


def known_blocked(ja3: str, blocklist: Iterable[str]) -> bool:
    digest = normalize_ja3(ja3)
    if not digest:
        return False
    wanted = {entry.strip().lower() for entry in blocklist if entry and entry.strip()}
    return digest in wanted


__all__ = [
    "EDGE_VERSION",
    "edge_signature",
    "h2_digest",
    "ja3_digest",
    "ja3_string",
    "known_blocked",
    "normalize_ja3",
    "verify_edge_signature",
]
