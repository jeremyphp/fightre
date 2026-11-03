"""Detection of RE-agent toolchains at the HTTP boundary.

REA-style agents do not look like classic scrapers.  They look like a *pipeline*:
a headless browser or a proxy observes the app, a static analyser chews the
bundle, and the agent keeps notes.  Server-side we only see the HTTP shadow of
that pipeline, but the shadow is distinctive:

* Playwright/Puppeteer/CDP header and UA artefacts;
* schema introspection (OpenAPI, Swagger, GraphQL ``__schema``);
* requests for build artefacts (``.map``, ``.git``, ``.asar``, backup files);
* GraphQL introspection bodies, which static analysers send verbatim.

We score these, they are not proof.  A developer with a `.map` open in DevTools
is not an attacker -- which is exactly why the weights stay moderate and the
policy prefers challenge/deception over a hard block.
"""

from __future__ import annotations

import re
from typing import Dict, List, Optional, Sequence

from . import signals as sig
from .signals import Signal

RUNTIME_MARKERS: Sequence[str] = (
    "playwright",
    "puppeteer",
    "selenium",
    "webdriver",
    "headless_shell",
    "headlesschrome",
    "frida",
    "mitmproxy",
    "httptoolkit",
    "http-toolkit",
    "cdp-bridge",
)

INTROSPECTION_PATHS: Sequence[str] = (
    "/openapi.json",
    "/openapi.yaml",
    "/swagger.json",
    "/swagger.yaml",
    "/swagger-ui",
    "/v3/api-docs",
    "/api-docs",
    "/graphql",
    "/graphiql",
    "/altair",
    "/.well-known/openapi",
)

ARTIFACT_RE = re.compile(
    r"\.(map|asar|apk|ipa|dex|har|pcap|pdb|dSYM|bak)$"
    r"|(^|/)\.git(/|$)"
    r"|(^|/)\.svn/"
    r"|(^|/)webpack\.stats\.json$"
    r"|\.tar\.gz$",
    re.IGNORECASE,
)

_SCHEMA_BODY_RE = re.compile(rb'__schema|"query"\s*:\s*"[^"]*__type')
_HEADER_SCAN_LIMIT = 40
_HEADER_VALUE_LIMIT = 512


def _markers_in(text: str) -> Optional[str]:
    lowered = text.lower()[:_HEADER_VALUE_LIMIT]
    for marker in RUNTIME_MARKERS:
        if marker in lowered:
            return marker
    return None


def analyze(
    method: str,
    path: str,
    query: str = "",
    headers: Optional[Dict[str, str]] = None,
    body: bytes = b"",
) -> List[Signal]:
    """Return REA-toolchain signals for one request."""
    found: List[Signal] = []
    headers = headers or {}
    lowered_path = (path or "").lower()

    # 1. automation runtimes announce themselves somewhere in the header block
    marker = _markers_in(headers.get("user-agent", ""))
    if marker:
        found.append(sig.make("proto.agent_runtime", f"User-Agent contains {marker!r}"))
    if not marker:
        for key, value in list(headers.items())[:_HEADER_SCAN_LIMIT]:
            if not key.startswith(("x-", "sec-", "cookie")):
                continue
            marker = _markers_in(str(value))
            if marker:
                found.append(sig.make("proto.agent_runtime", f"{key} contains {marker!r}"))
                break

    # 2. schema introspection: the first thing every agent asks for
    if any(lowered_path.startswith(p) or lowered_path == p for p in INTROSPECTION_PATHS):
        found.append(sig.make("app.introspection_probe", path))
    elif "introspection" in (query or "").lower():
        found.append(sig.make("app.introspection_probe", "introspection query parameter"))
    elif body and _SCHEMA_BODY_RE.search(body[:65536]):
        found.append(sig.make("app.introspection_probe", "GraphQL __schema body"))

    # 3. build artefacts are gold for static analysis
    match = ARTIFACT_RE.search(lowered_path)
    if match:
        found.append(sig.make("app.source_artifact_probe", match.group(0)))

    return found


__all__ = ["ARTIFACT_RE", "INTROSPECTION_PATHS", "RUNTIME_MARKERS", "analyze"]
