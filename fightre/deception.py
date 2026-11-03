"""Deception: tarpits and synthetic responses.

Rationale
---------
A 403 tells an attacker "you were seen, change something".  A 200 with
plausible, watermarked, slowly-served data tells them "keep going".  Deception
buys three things: time, attacker attention, and canary tokens that survive
outside our boundary.

Rules of engagement baked into the code:

* Deception never touches real records -- payloads are generated, not sampled.
* Every stolen canary is attributable (owner = identity hash + path).
* Delays are bounded (``max_ms``) so we cannot be turned into a self-DoS.
"""

from __future__ import annotations

import random
import secrets
from typing import Dict, List, Optional

from .canary import CanaryRegistry, embed
from .config import TarpitSettings

_FAKE_NAMES = ("Ops Console", "Billing Export", "Staging Snapshot", "Customer Vault", "Legacy Sync")
_FAKE_EMAILS = ("ops@example.invalid", "finance@example.invalid", "noreply@example.invalid")


class Decepter:
    """Builds decoy payloads and computes tarpit delays."""

    def __init__(
        self,
        registry: Optional[CanaryRegistry] = None,
        settings: Optional[TarpitSettings] = None,
        base_url: str = "",
        rng: Optional[random.Random] = None,
    ) -> None:
        self.registry = registry if registry is not None else CanaryRegistry()
        self.settings = settings if settings is not None else TarpitSettings()
        self.base_url = base_url.rstrip("/")
        self.rng = rng if rng is not None else random.Random()

    # -- payloads ----------------------------------------------------------
    def payload(self, path: str, identity: str, score: float = 0.0) -> Dict[str, object]:
        owner = f"{identity}:{path}"
        canary = self.registry.issue(owner, {"path": path, "score": round(score, 1)})
        request_id = secrets.token_hex(8)

        if path.rstrip("/").endswith(("export", "download", "dump")):
            body: Dict[str, object] = {
                "ok": True,
                "format": "jsonl",
                "records": [
                    {
                        "id": canary.token,
                        "email": embed(self.rng.choice(_FAKE_EMAILS), f"c:{owner}"),
                        "plan": "enterprise",
                        "mrr": self.rng.randint(900, 4800),
                    }
                    for _ in range(self.rng.randint(3, 6))
                ],
                "next_cursor": canary.token,
                "request_id": request_id,
            }
        else:
            body = {
                "ok": True,
                "data": [
                    {
                        "id": canary.token,
                        "name": embed(self.rng.choice(_FAKE_NAMES), f"c:{owner}"),
                        "status": "active",
                        "updated_at": "2026-01-01T00:00:00Z",
                    }
                    for _ in range(self.rng.randint(2, 5))
                ],
                "page": 1,
                "total": self.rng.randint(40, 400),
                "request_id": request_id,
                "_v": "1",
            }
        return body

    # -- timing ------------------------------------------------------------
    def delay_seconds(self, score: float, band_score: float = 70.0) -> float:
        over = max(0.0, score - band_score)
        delay_ms = self.settings.base_ms + over * self.settings.per_point_ms
        delay_ms = min(self.settings.max_ms, delay_ms)
        if self.settings.jitter_ms:
            delay_ms += self.rng.randint(0, self.settings.jitter_ms)
        return max(0.0, delay_ms / 1000.0)

    # -- attribution -------------------------------------------------------
    def collect_leaks(self, text: str) -> List[Dict[str, object]]:
        """Which canaries does this (external) text carry?"""
        return [
            {"token": c.token, "owner": c.owner, "created": c.created, "meta": c.meta}
            for c in self.registry.find(text)
        ]


__all__ = ["Decepter"]
