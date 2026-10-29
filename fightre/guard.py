"""The Guard: one request in, one explainable verdict out.

Every adapter (ASGI, WSGI, CLI test harness) builds a :class:`Request`, hands it
to :meth:`Guard.evaluate`, and then either forwards the request or asks the
Guard to build the response for the chosen action.  Keeping the decision logic
here means the framework layer stays ~100 lines and the behaviour is identical
in tests, in the demo and in production.
"""

from __future__ import annotations

import json
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Deque, Dict, List, Optional, Tuple

from . import headers as header_rules
from . import signals as sig
from .agent_detect import analyze as analyze_agent
from .attest import AttestResult, AttestationVerifier
from .canary import CanaryRegistry
from .challenge import ChallengeIssuer
from .config import Config
from .decoy import DecoyFabric
from .deception import Decepter
from .fingerprint import known_blocked, normalize_ja3, verify_edge_signature
from .policy import Action, Decision, Policy
from .ratelimit import RateLimiter
from .report import AuditLog
from .scoring import RiskEngine, RiskReport
from .signals import Signal
from .signing import RequestSigner, SignatureResult

BROWSER_HINTS = ("mozilla/", "chrome/", "safari/", "firefox/")
COOKIE_NAME_DEFAULT = "fightre_att"


def parse_cookie(header: str, name: str) -> str:
    for chunk in (header or "").split(";"):
        key, _, value = chunk.strip().partition("=")
        if key.strip() == name:
            return value.strip()
    return ""


@dataclass
class Request:
    """Framework-neutral snapshot of one HTTP request."""

    method: str
    path: str
    query: str = ""
    headers: Dict[str, str] = field(default_factory=dict)
    raw_pairs: List[Tuple[str, str]] = field(default_factory=list)
    body: bytes = b""
    client_ip: str = "0.0.0.0"
    http_version: str = "1.1"
    now: float = 0.0

    def __post_init__(self) -> None:
        self.headers = {str(k).lower(): str(v) for k, v in self.headers.items()}
        if not self.now:
            self.now = time.time()

    @property
    def target(self) -> str:
        return self.path + (f"?{self.query}" if self.query else "")

    @property
    def identity(self) -> str:
        return self.client_ip or "unknown"

    @property
    def is_browser(self) -> bool:
        ua = self.headers.get("user-agent", "").lower()
        return any(hint in ua for hint in BROWSER_HINTS)

    @property
    def cookie(self) -> str:
        return self.headers.get("cookie", "")


@dataclass
class Response:
    status: int
    body: bytes = b""
    headers: Dict[str, str] = field(default_factory=dict)

    @classmethod
    def json(
        cls, status: int, payload: object, headers: Optional[Dict[str, str]] = None
    ) -> "Response":
        merged = {"content-type": "application/json; charset=utf-8", "cache-control": "no-store"}
        merged.update(headers or {})
        return cls(
            status=status,
            body=json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8"),
            headers=merged,
        )


@dataclass
class Verdict:
    report: RiskReport
    decision: Decision
    request: Request
    attestation: AttestResult
    signature: SignatureResult
    decoy: bool = False
    duration_ms: float = 0.0

    def as_dict(self) -> Dict[str, object]:
        return {
            "action": self.decision.action.value,
            "score": round(self.report.score, 2),
            "band": self.decision.band,
            "decoy": self.decoy,
            "signals": [s.as_dict() for s in self.report.signals],
            "reasons": self.report.reasons,
            "attestation": self.attestation.as_dict(),
            "signature": self.signature.as_dict(),
            "delay_ms": self.decision.delay_ms,
            "duration_ms": round(self.duration_ms, 2),
        }


class SequenceTracker:
    """Counts distinct paths per identity in a sliding window."""

    def __init__(self, window_seconds: int = 60, distinct: int = 25, max_keys: int = 20_000) -> None:
        self.window = float(window_seconds)
        self.distinct = int(distinct)
        self.max_keys = int(max_keys)
        self._events: Dict[str, Deque[Tuple[float, str]]] = {}
        self._lock = threading.Lock()

    def hit(self, identity: str, path: str, now: Optional[float] = None) -> bool:
        stamp = time.time() if now is None else now
        with self._lock:
            if len(self._events) > self.max_keys:
                self._events.clear()
            events = self._events.setdefault(identity, deque())
            cutoff = stamp - self.window
            while events and events[0][0] < cutoff:
                events.popleft()
            events.append((stamp, path))
            if len({p for _, p in events}) >= self.distinct:
                events.clear()
                return True
            return False


class Guard:
    """Holds all defence state for one process."""

    def __init__(self, config: Optional[Config] = None) -> None:
        self.config = config or Config()
        secret = self.config.resolve_secret()
        challenge_cfg = self.config.challenge
        self.issuer = ChallengeIssuer(
            secret, ttl_seconds=challenge_cfg.ttl_seconds, difficulty=challenge_cfg.difficulty
        )
        self.attestation = AttestationVerifier(
            secret,
            ttl_seconds=challenge_cfg.attest_ttl_seconds,
            trust=self.config.trust_attested,
        )
        self.signer = RequestSigner(self.config.api_keys)
        self.limiter = RateLimiter(self.config.rate.rate, self.config.rate.burst)
        self.canaries = CanaryRegistry()
        self.audit = AuditLog(self.config.security.audit_path)
        self.decepter = Decepter(self.canaries, self.config.tarpit)
        self.decoys = DecoyFabric(self.canaries)
        self.engine = RiskEngine(self.config.weights)
        self.policy = Policy(
            self.config.bands,
            challenge_min=challenge_cfg.min_difficulty,
            challenge_max=challenge_cfg.max_difficulty,
            tarpit_base_ms=self.config.tarpit.base_ms,
            tarpit_per_point_ms=self.config.tarpit.per_point_ms,
            tarpit_max_ms=self.config.tarpit.max_ms,
            hard_block=self.config.hard_block,
        )
        self.sequence = SequenceTracker(
            self.config.sequence_window_seconds, self.config.sequence_paths
        )

    # -- bypass ------------------------------------------------------------
    def is_bypass(self, path: str) -> bool:
        return any(path == entry or path.startswith(entry + "/")
                   for entry in self.config.bypass_paths)

    def needs_signature(self, path: str) -> bool:
        return any(path.startswith(prefix) for prefix in self.config.signed_paths)

    # -- evaluation --------------------------------------------------------
    def evaluate(self, request: Request) -> Verdict:
        started = time.perf_counter()
        found: List[Signal] = []
        trust = 0.0

        # L1: rate
        allowed, retry_after = self.limiter.allow(request.identity)
        if not allowed:
            found.append(sig.make("net.rate_burst", f"retry after {retry_after:.1f}s"))

        # L4: honeypots and honey-schema
        if self._is_honeypot(request.path):
            found.append(sig.make("app.honeypot_endpoint", request.path))
        decoy_hit = self.decoys.match(request.method, request.path) is not None
        if decoy_hit:
            found.append(sig.make("app.decoy_schema_access", request.path))

        # L2: headers, edge fingerprints, agent runtimes
        found.extend(
            header_rules.analyze(request.headers, request.raw_pairs or None, request.http_version)
        )
        found.extend(self._edge_signals(request))
        found.extend(
            analyze_agent(request.method, request.path, request.query, request.headers, request.body)
        )

        # L3: attestation
        attestation = self._check_attestation(request, found)
        if attestation.ok:
            trust += attestation.trust

        # L4: request signatures
        signature = self._check_signature(request, found)
        if signature.ok:
            trust += self.config.trust_signed_client

        # L5: canary echo (did someone use what we planted?)
        haystack = f"{request.query}\n{request.body.decode('utf-8', 'ignore')}"
        echoes = self.canaries.find(haystack)
        if echoes:
            owners = ", ".join(sorted({c.owner[:40] for c in echoes}))[:120]
            found.append(sig.make("data.canary_echo", f"owner(s): {owners}"))

        # L1/app: rapid traversal of distinct paths
        if self.sequence.hit(request.identity, request.path, now=request.now):
            found.append(sig.make("app.sequence_scan", f"{self.config.sequence_paths}+ distinct paths"))

        report = self.engine.score(found, trust=trust)
        decision = self.policy.decide(report)
        elapsed = (time.perf_counter() - started) * 1000.0
        return Verdict(
            report=report,
            decision=decision,
            request=request,
            attestation=attestation,
            signature=signature,
            decoy=decoy_hit,
            duration_ms=elapsed,
        )

    # -- helpers -----------------------------------------------------------
    def _is_honeypot(self, path: str) -> bool:
        for entry in self.config.honeypots:
            clean = entry.rstrip("/")
            if path == clean or path.startswith(clean + "/"):
                return True
        return False

    def _edge_signals(self, request: Request) -> List[Signal]:
        ja3 = request.headers.get("x-fightre-ja3", "")
        h2 = request.headers.get("x-fightre-h2", "")
        if not ja3 and not h2:
            return []
        secret = self.config.security.edge_secret
        if not secret:
            return [sig.make("proto.edge_signature_invalid", "edge headers without configured secret")]
        ts = request.headers.get("x-fightre-edge-ts", "")
        signature = request.headers.get("x-fightre-edge-sig", "")
        if not verify_edge_signature(secret, ts, signature, ja3, h2, request.client_ip):
            return [sig.make("proto.edge_signature_invalid", "HMAC mismatch or clock skew")]
        if known_blocked(ja3, self.config.blocklist_ja3):
            return [sig.make("proto.ja3_known_bot", normalize_ja3(ja3))]
        return []

    def _check_attestation(self, request: Request, found: List[Signal]) -> AttestResult:
        name = self.config.security.cookie_name or COOKIE_NAME_DEFAULT
        blob = parse_cookie(request.cookie, name)
        if not blob:
            if request.is_browser:
                found.append(sig.make("client.missing_attestation", "no attestation cookie"))
            return AttestResult(ok=False, reason="missing")
        result = self.attestation.verify(blob, now=request.now)
        if result.ok:
            found.extend(result.signals)
            return result
        if result.reason == "stale":
            found.append(sig.make("client.stale_attestation", f"age {result.age_seconds:.0f}s"))
        else:
            found.append(sig.make("client.attestation_forged", result.reason))
        return result

    def _check_signature(self, request: Request, found: List[Signal]) -> SignatureResult:
        if not self.needs_signature(request.path):
            return SignatureResult(ok=False, reason="not-required")
        result = self.signer.verify(
            request.method, request.target, request.headers, request.body, now=request.now
        )
        if result.ok:
            return result
        if result.reason == "absent":
            found.append(sig.make("app.missing_signature", request.path))
        else:
            found.extend(result.signals)
        return result

    # -- responses ---------------------------------------------------------
    def build_response(self, verdict: Verdict) -> Optional[Response]:
        """Return a Response for the action, or ``None`` to pass through."""
        request = verdict.request
        action = verdict.decision.action

        # A fabricated schema is the strongest bait we have: serve it whenever
        # we are not hard-blocking, so the agent records a wrong API model.
        if action is not Action.BLOCK:
            honey = self._honey_document(request)
            if honey is not None:
                honey.headers["x-fightre-action"] = action.value
                honey.headers.setdefault("server", "nginx/1.24.0")
                return honey

        if action is Action.ALLOW:
            return None

        if action is Action.CHALLENGE:
            challenge = self.issuer.issue(
                request.identity, difficulty=verdict.decision.difficulty or None
            )
            return Response.json(
                429,
                {
                    "error": "verification_required",
                    "challenge": challenge,
                    "attest_endpoint": "/_fightre/attest",
                },
                {"x-fightre-action": "challenge", "retry-after": "5"},
            )

        if action in (Action.DECEIVE, Action.TARPIT):
            endpoint = self.decoys.match(request.method, request.path)
            if endpoint is not None:
                payload = self.decoys.respond(endpoint, request.identity)
            else:
                payload = self.decepter.payload(
                    request.path, request.identity, verdict.report.score
                )
            return Response.json(
                200,
                payload,
                {
                    "x-fightre-action": action.value,
                    "server": "nginx/1.24.0",
                },
            )

        # BLOCK: boring, information free
        return Response.json(403, {"error": "forbidden"}, {"x-fightre-action": "block"})

    def _honey_document(self, request: Request) -> Optional[Response]:
        """Serve a fabricated OpenAPI document to schema crawlers."""
        if not self.config.poison_enabled:
            return None
        clean = request.path.rstrip("/") or "/"
        if clean in ("/openapi.json", "/swagger.json", "/v3/api-docs", "/openapi.yaml"):
            host = request.headers.get("host", "app.example.invalid")
            scheme = "https" if request.headers.get("x-forwarded-proto", "https") == "https" else "http"
            return Response.json(200, self.decoys.openapi(f"{scheme}://{host}"))
        return None

    # -- internal endpoints ------------------------------------------------
    def handle_challenge(self, request: Request) -> Response:
        challenge = self.issuer.issue(request.identity)
        return Response.json(200, {"challenge": challenge, "attest_endpoint": "/_fightre/attest"})

    def handle_attest(self, request: Request) -> Response:
        try:
            payload = json.loads(request.body.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return Response.json(400, {"error": "invalid_json"})
        if not isinstance(payload, dict):
            return Response.json(400, {"error": "invalid_json"})

        challenge = self.issuer.verify(str(payload.get("token", "")))
        if challenge is None:
            return Response.json(400, {"error": "bad_challenge"})

        ok, reason = self.issuer.check_solution(challenge, payload.get("nonce"))
        if not ok:
            return Response.json(403, {"error": "challenge_failed", "reason": reason})

        result = self.attestation.verify(str(payload.get("attestation", "")))
        if not result.ok:
            return Response.json(403, {"error": "attestation_failed", "reason": result.reason})
        if result.jti != challenge.jti:
            # The attestation must be bound to the challenge we just solved.
            return Response.json(403, {"error": "attestation_failed", "reason": "jti-mismatch"})

        name = self.config.security.cookie_name or COOKIE_NAME_DEFAULT
        max_age = self.config.challenge.attest_ttl_seconds
        set_cookie = (
            f"{name}={payload['attestation']}; Path=/; HttpOnly; SameSite=Lax; Max-Age={max_age}"
        )
        return Response.json(
            200,
            {
                "ok": True,
                "trust": round(result.trust, 2),
                "signals": [s.name for s in result.signals],
            },
            {"set-cookie": set_cookie},
        )

    # -- observability -----------------------------------------------------
    def stats(self) -> Dict[str, object]:
        return {
            "canaries": len(self.canaries),
            "buckets": len(self.limiter),
            "bands": dict(self.policy.bands),
            "poison": self.config.poison_enabled,
        }


__all__ = [
    "COOKIE_NAME_DEFAULT",
    "Guard",
    "Request",
    "Response",
    "SequenceTracker",
    "Verdict",
    "parse_cookie",
]
