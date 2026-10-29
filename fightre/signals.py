"""Signal taxonomy.

A *signal* is one piece of evidence that a request is not what it claims to be.
Every signal belongs to exactly one defence layer and carries a weight in the
range 0..100.  Weights are interpreted as independent probabilities by the
scoring engine (noisy-OR), so a single 90-weight signal is already decisive
while five weight-20 signals are merely suspicious.

Everything here is data, not behaviour: adding a detector means adding a *spec*
and emitting the signal from the layer that owns the evidence.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Dict, List, Optional


class Layer(str, Enum):
    """Defence layer a signal belongs to."""

    NETWORK = "L1-network"
    PROTOCOL = "L2-protocol"
    CLIENT = "L3-client"
    APP = "L4-app"
    DATA = "L5-data"

    def __str__(self) -> str:  # pragma: no cover - cosmetic
        return self.value


@dataclass(frozen=True)
class Signal:
    """One observation about a request, with its contribution to the score."""

    name: str
    layer: Layer
    weight: float
    detail: str = ""
    critical: bool = False

    def as_dict(self) -> Dict[str, object]:
        return {
            "name": self.name,
            "layer": self.layer.value,
            "weight": self.weight,
            "detail": self.detail,
            "critical": self.critical,
        }

    def __str__(self) -> str:  # pragma: no cover - cosmetic
        flag = "!" if self.critical else ""
        return f"{self.name}{flag} (+{self.weight:g})"


@dataclass(frozen=True)
class SignalSpec:
    """Static definition of a signal: where it lives and how much it matters."""

    layer: Layer
    weight: float
    description: str
    critical: bool = False


# --- L1: network -----------------------------------------------------------
# Supplied by the edge or by an in-process limiter. FightRE never does its own
# DNS/ASN lookups: the operator feeds reputation in, we do not invent it.
LIBRARY: Dict[str, SignalSpec] = {
    "net.rate_burst": SignalSpec(
        Layer.NETWORK, 35, "Request rate exceeded the per-identity budget"
    ),
    "net.datacenter_asn": SignalSpec(
        Layer.NETWORK, 22, "Client IP belongs to a datacenter/hosting ASN"
    ),
    "net.proxy_or_vpn": SignalSpec(
        Layer.NETWORK, 28, "Client IP is a known commercial proxy or VPN exit"
    ),
    "net.tor_exit": SignalSpec(
        Layer.NETWORK, 50, "Client IP is a Tor exit node"
    ),
    "net.geo_mismatch": SignalSpec(
        Layer.NETWORK, 14, "Accept-Language region disagrees with IP geolocation"
    ),
    "net.scanner_pattern": SignalSpec(
        Layer.NETWORK, 42, "Sequential path probing typical of a scanner"
    ),
    # --- L2: protocol ------------------------------------------------------
    "proto.bot_user_agent": SignalSpec(
        Layer.PROTOCOL, 40, "User-Agent announces a scripting HTTP client"
    ),
    "proto.ua_client_hints_mismatch": SignalSpec(
        Layer.PROTOCOL, 28, "User-Agent version/brand contradicts sec-ch-ua hints"
    ),
    "proto.missing_browser_headers": SignalSpec(
        Layer.PROTOCOL, 16, "A browser User-Agent without the headers that browser always sends"
    ),
    "proto.header_order_anomaly": SignalSpec(
        Layer.PROTOCOL, 14, "Header ordering deviates from the claimed browser engine"
    ),
    "proto.duplicate_header": SignalSpec(
        Layer.PROTOCOL, 12, "Duplicate singleton header (possible proxy or rewriter)"
    ),
    "proto.smuggling_probe": SignalSpec(
        Layer.PROTOCOL, 55, "Both Content-Length and Transfer-Encoding present", critical=True
    ),
    "proto.ja3_known_bot": SignalSpec(
        Layer.PROTOCOL, 50, "TLS ClientHello fingerprint matches a known automation stack"
    ),
    "proto.h2_fingerprint_anomaly": SignalSpec(
        Layer.PROTOCOL, 26, "HTTP/2 SETTINGS fingerprint deviates from the claimed client"
    ),
    "proto.edge_signature_invalid": SignalSpec(
        Layer.PROTOCOL, 70, "Edge-injected fingerprint headers were not signed by the edge",
        critical=True,
    ),
    "proto.accept_encoding_mismatch": SignalSpec(
        Layer.PROTOCOL, 8, "Modern browser claim without the compression it always offers"
    ),
    "proto.agent_runtime": SignalSpec(
        Layer.PROTOCOL, 50, "Automation / RE-agent runtime markers (Playwright, CDP bridge, Frida helper)"
    ),
    # --- L3: client --------------------------------------------------------
    "client.webdriver": SignalSpec(
        Layer.CLIENT, 55, "navigator.webdriver is set (automation driver attached)"
    ),
    "client.headless_ua": SignalSpec(
        Layer.CLIENT, 45, "User-Agent contains a headless/automation marker"
    ),
    "client.cdp_runtime_leak": SignalSpec(
        Layer.CLIENT, 50, "Chrome DevTools Protocol artefacts leaked into the page"
    ),
    "client.function_tostring_patched": SignalSpec(
        Layer.CLIENT, 42, "Native functions were monkey-patched (hook injection)"
    ),
    "client.software_renderer": SignalSpec(
        Layer.CLIENT, 30, "WebGL renderer is a software rasterizer (SwiftShader/llvmpipe)"
    ),
    "client.signal_inconsistency": SignalSpec(
        Layer.CLIENT, 36, "Client environment signals contradict each other"
    ),
    "client.devtools_open": SignalSpec(
        Layer.CLIENT, 8, "DevTools appears to be open (weak, humans do this too)"
    ),
    "client.missing_attestation": SignalSpec(
        Layer.CLIENT, 16, "Browser claim without a valid FightRE attestation"
    ),
    "client.stale_attestation": SignalSpec(
        Layer.CLIENT, 20, "Attestation older than the freshness window"
    ),
    "client.attestation_forged": SignalSpec(
        Layer.CLIENT, 75, "Attestation signature invalid or replayed", critical=True
    ),
    "client.honeypot_clicked": SignalSpec(
        Layer.CLIENT, 55, "Invisible honeypot field was filled by the client"
    ),
    "client.env_anomaly": SignalSpec(
        Layer.CLIENT, 18, "Client environment has an unusual but non-decisive property"
    ),
    "client.debugger_attached": SignalSpec(
        Layer.CLIENT, 55, "A debugger or tracer is attached to the process (TracerPid, sys.gettrace)"
    ),
    "client.instrumentation_detected": SignalSpec(
        Layer.CLIENT, 70, "Dynamic instrumentation agent found in process memory (Frida/gum)"
    ),
    "client.preload_hijack": SignalSpec(
        Layer.CLIENT, 45, "Library preload or injected extension is active (LD_PRELOAD, DYLD_INSERT)"
    ),
    "client.root_or_jailbreak": SignalSpec(
        Layer.CLIENT, 35, "Device is rooted/jailbroken, weakening every client-side control"
    ),
    # --- L4: application ---------------------------------------------------
    "app.honeypot_endpoint": SignalSpec(
        Layer.APP, 85, "Request hit a decoy endpoint that no real client links to"
    ),
    "app.rate_limit": SignalSpec(
        Layer.APP, 30, "Application-level quota exceeded"
    ),
    "app.replay_detected": SignalSpec(
        Layer.APP, 70, "Signed request replayed (nonce reuse)", critical=True
    ),
    "app.bad_signature": SignalSpec(
        Layer.APP, 60, "Request signature did not verify", critical=True
    ),
    "app.missing_signature": SignalSpec(
        Layer.APP, 22, "Signed endpoint called without a signature"
    ),
    "app.timestamp_skew": SignalSpec(
        Layer.APP, 35, "Signature timestamp outside the tolerated clock skew"
    ),
    "app.enumeration_pattern": SignalSpec(
        Layer.APP, 32, "Sequential identifier enumeration detected"
    ),
    "app.payload_tamper": SignalSpec(
        Layer.APP, 45, "Payload hash disagreees with the signature binding"
    ),
    "app.bulk_export": SignalSpec(
        Layer.APP, 40, "Bulk export shape requested by an unverified identity"
    ),
    "app.introspection_probe": SignalSpec(
        Layer.APP, 34, "API schema introspection requested (OpenAPI, Swagger, GraphQL __schema)"
    ),
    "app.source_artifact_probe": SignalSpec(
        Layer.APP, 40, "Build artefact requested (source map, .git, ASAR, backup file)"
    ),
    "app.decoy_schema_access": SignalSpec(
        Layer.APP, 70, "Honey-schema endpoint used: the client is consuming poisoned evidence"
    ),
    "app.sequence_scan": SignalSpec(
        Layer.APP, 30, "Rapid traversal of many distinct paths by one identity"
    ),
    # --- L5: data ----------------------------------------------------------
    "data.canary_echo": SignalSpec(
        Layer.DATA, 65, "A FightRE canary token was sent back to the service", critical=True
    ),
    "data.canary_accessed": SignalSpec(
        Layer.DATA, 70, "A canary token was read and re-submitted to the service",
        critical=True,
    ),
    "data.watermark_leak": SignalSpec(
        Layer.DATA, 60, "Leaked document carries our zero-width watermark", critical=True
    ),
    "data.field_tamper": SignalSpec(
        Layer.DATA, 38, "Client-side field integrity check failed"
    ),
    "data.bulk_scan": SignalSpec(
        Layer.DATA, 28, "Response paging pattern consistent with dataset scraping"
    ),
}


def spec(name: str) -> SignalSpec:
    """Return the static spec for *name* (raises ``KeyError`` when unknown)."""
    try:
        return LIBRARY[name]
    except KeyError as exc:  # pragma: no cover - programming error
        raise KeyError(
            f"unknown signal {name!r}; known signals: {', '.join(sorted(LIBRARY))}"
        ) from exc


def make(name: str, detail: str = "", weight: Optional[float] = None) -> Signal:
    """Build a Signal from the library, optionally overriding its weight."""
    sp = spec(name)
    return Signal(
        name=name,
        layer=sp.layer,
        weight=sp.weight if weight is None else weight,
        detail=detail,
        critical=sp.critical,
    )


def describe() -> List[Dict[str, object]]:
    """Machine-readable catalogue (used by ``fightre signals`` and the docs)."""
    rows = []
    for name, sp in LIBRARY.items():
        rows.append(
            {
                "name": name,
                "layer": sp.layer.value,
                "weight": sp.weight,
                "critical": sp.critical,
                "description": sp.description,
            }
        )
    return sorted(rows, key=lambda r: (str(r["layer"]), str(r["name"])))
