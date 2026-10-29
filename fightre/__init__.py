"""FightRE - five-layer anti-reverse-engineering defense for web services.

Layers
------
L1 network   : rate, ASN/proxy/Tor, scanner cadence
L2 protocol  : TLS/JA3, HTTP/2, header order & client-hint consistency, smuggling probes
L3 client    : environment attestation, automation markers, proof-of-work challenge
L4 app       : request signing, replay defense, honeypot endpoints, behaviour scoring
L5 data      : canary tokens, zero-width watermarking, leak attribution

Design goals: zero runtime dependencies, explainable decisions, safe default
(never silently block a human), and an audit trail you can actually read.
"""

from .config import Config
from .middleware import FightREMiddleware
from .scoring import RiskEngine, RiskReport
from .signals import LIBRARY, Layer, Signal

__all__ = [
    "Config",
    "FightREMiddleware",
    "RiskEngine",
    "RiskReport",
    "LIBRARY",
    "Layer",
    "Signal",
]

__version__ = "0.2.0"
