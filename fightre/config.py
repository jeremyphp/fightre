"""Configuration objects for FightRE.

Everything is a plain dataclass so it can be built in code, loaded from JSON, or
dumped back out for review.  No YAML, no environment magic beyond two documented
variables (``FIGHTRE_SECRET`` and ``FIGHTRE_CONFIG``).
"""

from __future__ import annotations

import json
import os
import secrets
from dataclasses import asdict, dataclass, field, replace
from typing import Any, Dict, List, Optional

DEV_SECRET_PREFIX = "dev-insecure-"


@dataclass
class ChallengeSettings:
    """Proof-of-work / attestation tuning."""

    ttl_seconds: int = 120
    difficulty: int = 18
    min_difficulty: int = 14
    max_difficulty: int = 26
    attest_ttl_seconds: int = 3600


@dataclass
class RateSettings:
    """Token bucket: *rate* tokens per second, bucket capacity *burst*."""

    rate: float = 0.5
    burst: float = 40.0


@dataclass
class TarpitSettings:
    """Delay applied to the TARPIT band: base + per-point, capped."""

    base_ms: int = 350
    per_point_ms: int = 60
    max_ms: int = 4000
    jitter_ms: int = 120


@dataclass
class SecuritySettings:
    secret: str = ""
    trust_proxy: bool = False
    edge_secret: str = ""
    expose_score: bool = False
    audit_path: str = ""
    redact_ip: bool = True
    cookie_name: str = "fightre_att"


@dataclass
class RedisSettings:
    """Optional shared state for multi-worker deployments.

    FightRE ships a minimal RESP client, so enabling this needs no extra
    dependency. When the server is unreachable the stores fall back to local
    memory and count the failure; see ``fightre/stores.py``.
    """

    enabled: bool = False
    host: str = "127.0.0.1"
    port: int = 6379
    db: int = 0
    password: str = ""
    prefix: str = "fightre"
    timeout: float = 1.0
    max_connections: int = 8


DEFAULT_BANDS: Dict[str, float] = {
    "allow": 0.0,
    "challenge": 30.0,
    "deceive": 55.0,
    "tarpit": 70.0,
    "block": 90.0,
}

DEFAULT_HONEYPOTS: List[str] = [
    "/.env",
    "/.git/config",
    "/wp-login.php",
    "/wp-admin",
    "/admin.php",
    "/phpmyadmin",
    "/actuator/env",
    "/server-status",
    "/api/v1/users/export",
    "/api/internal/metrics",
]


@dataclass
class Config:
    """Top-level configuration."""

    bands: Dict[str, float] = field(default_factory=lambda: dict(DEFAULT_BANDS))
    weights: Dict[str, float] = field(default_factory=dict)
    honeypots: List[str] = field(default_factory=lambda: list(DEFAULT_HONEYPOTS))
    blocklist_ja3: List[str] = field(default_factory=list)
    signed_paths: List[str] = field(default_factory=list)
    api_keys: Dict[str, str] = field(default_factory=dict)
    challenge: ChallengeSettings = field(default_factory=ChallengeSettings)
    rate: RateSettings = field(default_factory=RateSettings)
    tarpit: TarpitSettings = field(default_factory=TarpitSettings)
    security: SecuritySettings = field(default_factory=SecuritySettings)
    redis: RedisSettings = field(default_factory=RedisSettings)
    trust_attested: float = 30.0
    trust_signed_client: float = 30.0
    poison_enabled: bool = True
    bypass_paths: List[str] = field(default_factory=lambda: ["/healthz", "/favicon.ico"])
    hard_block: List[str] = field(
        default_factory=lambda: [
            "proto.smuggling_probe",
            "proto.edge_signature_invalid",
            "app.replay_detected",
            "app.bad_signature",
            "client.attestation_forged",
            "data.canary_echo",
        ]
    )
    max_body_bytes: int = 1_048_576
    sequence_window_seconds: int = 60
    sequence_paths: int = 25

    # -- construction ------------------------------------------------------
    @classmethod
    def from_dict(cls, data: Optional[Dict[str, Any]] = None) -> "Config":
        data = dict(data or {})
        cfg = cls()
        for key in ("bands", "weights", "honeypots", "blocklist_ja3", "signed_paths", "api_keys",
                    "bypass_paths", "hard_block", "sequence_paths", "sequence_window_seconds",
                    "max_body_bytes"):
            if key in data and data[key] is not None:
                setattr(cfg, key, data[key])
        for key in ("trust_attested", "trust_signed_client", "poison_enabled"):
            if key in data:
                setattr(cfg, key, data[key] if key == "poison_enabled" else float(data[key]))
        for section, klass in (
            ("challenge", ChallengeSettings),
            ("rate", RateSettings),
            ("tarpit", TarpitSettings),
            ("security", SecuritySettings),
            ("redis", RedisSettings),
        ):
            payload = data.get(section) or {}
            current = getattr(cfg, section)
            merged = replace(current, **{k: v for k, v in payload.items() if hasattr(current, k)})
            setattr(cfg, section, merged if isinstance(merged, klass) else merged)
        return cfg

    @classmethod
    def load(cls, path: Optional[str] = None) -> "Config":
        """Load JSON config; falls back to ``$FIGHTRE_CONFIG`` then defaults."""
        path = path or os.environ.get("FIGHTRE_CONFIG", "")
        if not path:
            return cls()
        with open(path, "r", encoding="utf-8") as fh:
            return cls.from_dict(json.load(fh))

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    # -- secret handling ---------------------------------------------------
    def resolve_secret(self) -> str:
        """Return the HMAC secret, generating an ephemeral one if unset.

        An ephemeral secret is fine for a single process; it invalidates every
        outstanding challenge/attestation on restart, so production deployments
        should set ``FIGHTRE_SECRET`` (32+ random bytes, base64) or
        ``security.secret`` in the config file.
        """
        if self.security.secret:
            return self.security.secret
        env = os.environ.get("FIGHTRE_SECRET", "")
        if env:
            return env
        self.security.secret = DEV_SECRET_PREFIX + secrets.token_hex(16)
        return self.security.secret

    @property
    def ephemeral_secret(self) -> bool:
        return self.security.secret.startswith(DEV_SECRET_PREFIX)

    def weight_of(self, name: str, default: float) -> float:
        return float(self.weights.get(name, default))

    def merged(self, **overrides: Any) -> "Config":
        return replace(self, **overrides)
