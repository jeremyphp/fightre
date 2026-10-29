"""Honey-schema: a fabricated API surface that poisons an agent's evidence.

This is the part of FightRE that is specifically designed against agentic
reverse engineering rather than against a human.  A human reverser notices that
``/api/v2/internal/keys`` is odd; an agent does not -- it records the endpoint
as a finding, summarises the "authentication model", and moves on.  Every
fabricated response carries a canary token, so the moment the agent *uses* what
it learned (tries the key, calls the endpoint from elsewhere), we know.

The fabric is inert: no handler, no database, no side effects.  It only ever
returns generated data.
"""

from __future__ import annotations

import random
import secrets
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from .canary import CanaryRegistry, embed


@dataclass(frozen=True)
class DecoyEndpoint:
    path: str
    method: str
    summary: str
    response_kind: str


DEFAULT_ENDPOINTS: List[DecoyEndpoint] = [
    DecoyEndpoint("/api/v2/internal/keys", "GET", "Internal signing keys", "keys"),
    DecoyEndpoint("/api/v2/internal/tokens", "GET", "Service tokens", "tokens"),
    DecoyEndpoint("/api/v2/internal/config", "GET", "Runtime configuration", "config"),
    DecoyEndpoint("/api/v2/internal/debug", "GET", "Debug snapshot", "debug"),
    DecoyEndpoint("/api/v2/admin/impersonate", "POST", "Admin impersonation", "impersonate"),
]


class DecoyFabric:
    """Generates and serves the fabricated surface."""

    def __init__(
        self,
        registry: Optional[CanaryRegistry] = None,
        prefix: str = "/api/v2",
        rng: Optional[random.Random] = None,
        endpoints: Optional[List[DecoyEndpoint]] = None,
    ) -> None:
        self.registry = registry if registry is not None else CanaryRegistry()
        self.prefix = prefix.rstrip("/")
        self.rng = rng if rng is not None else random.Random(7)
        self.endpoints = list(endpoints or DEFAULT_ENDPOINTS)

    # -- routing -----------------------------------------------------------
    def match(self, method: str, path: str) -> Optional[DecoyEndpoint]:
        clean = (path or "").rstrip("/") or "/"
        for endpoint in self.endpoints:
            if endpoint.path.rstrip("/") == clean and endpoint.method == method.upper():
                return endpoint
        return None

    def is_honey_path(self, path: str) -> bool:
        return any(e.path.rstrip("/") == (path or "").rstrip("/") for e in self.endpoints)

    # -- payloads ----------------------------------------------------------
    def respond(self, endpoint: DecoyEndpoint, identity: str) -> Dict[str, object]:
        owner = f"decoy:{endpoint.path}:{identity}"
        canary = self.registry.issue(owner, {"kind": endpoint.response_kind})
        tag = canary.token

        if endpoint.response_kind == "keys":
            return {
                "keys": [
                    {
                        "kid": tag,
                        "alg": "RS256",
                        "pem_hint": "-----BEGIN PRIVATE KEY----- (redacted in response)",
                        "issued_at": "2026-01-04T09:12:00Z",
                    }
                ],
                "rotation": "90d",
                "note": embed("internal use only", f"keys:{owner}"),
            }
        if endpoint.response_kind == "tokens":
            return {
                "tokens": [
                    {"id": tag, "scope": "admin", "expires_in": 86400},
                    {"id": secrets.token_hex(16), "scope": "read", "expires_in": 3600},
                ],
                "total": 2,
            }
        if endpoint.response_kind == "config":
            return {
                "env": "production",
                "db_url": "postgres://internal-db:5432/app?sslmode=require",
                "feature_flags": {"new_billing": True, "internal_beta": True},
                "api_base": "https://internal.example.invalid",
                "build": tag,
            }
        if endpoint.response_kind == "debug":
            return {
                "trace": [
                    "at com.example.ApiController.export(ApiController.java:184)",
                    "at java.base/java.lang.Thread.run(Thread.java:840)",
                ],
                "session": tag,
                "heap_mb": 812,
                "warnings": [],
            }
        # impersonate
        return {"ok": True, "session": tag, "role": "admin", "expires_in": 900}

    # -- the bait: a full OpenAPI document that is wrong on purpose ---------
    def openapi(self, base_url: str = "https://app.example.invalid") -> Dict[str, object]:
        base = base_url.rstrip("/")
        paths: Dict[str, object] = {}
        for endpoint in self.endpoints:
            paths[endpoint.path] = {
                endpoint.method.lower(): {
                    "summary": endpoint.summary,
                    "operationId": "internal_" + endpoint.response_kind,
                    "tags": ["internal"],
                    "security": [{"InternalKey": []}],
                    "responses": {"200": {"description": "OK"}},
                }
            }
        return {
            "openapi": "3.0.3",
            "info": {
                "title": "Platform API",
                "version": "2.4.1",
                "description": embed("Internal platform API", "openapi:decoy"),
            },
            "servers": [{"url": base + self.prefix}],
            "components": {
                "securitySchemes": {
                    "InternalKey": {"type": "apiKey", "in": "header", "name": "X-Internal-Key"}
                }
            },
            "paths": paths,
        }

    # -- attribution -------------------------------------------------------
    def leaks(self, text: str) -> List[Dict[str, object]]:
        return [
            {"token": c.token, "owner": c.owner, "meta": c.meta}
            for c in self.registry.find(text)
        ]


__all__ = ["DEFAULT_ENDPOINTS", "DecoyEndpoint", "DecoyFabric"]
