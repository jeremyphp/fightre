"""WSGI adapter (Flask/Django/plain WSGI).

WSGI loses header order and duplicates, so L2 analysis is weaker here -- the
ASGI adapter can see both.  Everything else (scoring, challenge, deception,
canaries) behaves identically.
"""

from __future__ import annotations

import io
import time
import uuid
from typing import Callable, Dict, List, Optional, Tuple

from .config import Config
from .guard import Guard, Request, Response
from .report import AuditLog

StartResponse = Callable[[str, List[Tuple[str, str]]], None]


class FightREWSGIMiddleware:
    def __init__(
        self,
        app: Callable,
        config: Optional[Config] = None,
        guard: Optional[Guard] = None,
        audit: Optional[AuditLog] = None,
    ) -> None:
        self.app = app
        self.config = config or Config()
        self.guard = guard or Guard(self.config)
        self.audit = audit or self.guard.audit

    def __call__(self, environ: Dict[str, object], start_response: StartResponse):
        request = self._snapshot(environ)
        path = request.path

        if path == "/_fightre/challenge" and request.method == "GET":
            return self._deliver(self.guard.handle_challenge(request), start_response)
        if path == "/_fightre/attest" and request.method == "POST":
            return self._deliver(self.guard.handle_attest(request), start_response)
        if self.guard.is_bypass(path):
            return self.app(environ, start_response)

        verdict = self.guard.evaluate(request)
        try:
            self.audit.record(
                request_id=request.headers.get("x-request-id") or uuid.uuid4().hex[:16],
                identity=request.identity,
                method=request.method,
                path=request.target,
                report=verdict.report,
                decision=verdict.decision,
                detail={"decoy": verdict.decoy, "ms": round(verdict.duration_ms, 2)},
            )
        except Exception:
            pass

        response = self.guard.build_response(verdict)
        if response is None:
            return self.app(environ, start_response)
        if verdict.decision.delay_ms:
            time.sleep(verdict.decision.delay_ms / 1000.0)
        return self._deliver(response, start_response)

    # -- helpers -----------------------------------------------------------
    def _snapshot(self, environ: Dict[str, object]) -> Request:
        headers: Dict[str, str] = {}
        for key, value in environ.items():
            if key.startswith("HTTP_"):
                headers[key[5:].replace("_", "-").lower()] = str(value)
        if environ.get("CONTENT_TYPE"):
            headers["content-type"] = str(environ["CONTENT_TYPE"])
        if environ.get("CONTENT_LENGTH"):
            headers["content-length"] = str(environ["CONTENT_LENGTH"])

        ip = str(environ.get("REMOTE_ADDR") or "0.0.0.0")
        if self.config.security.trust_proxy:
            forwarded = headers.get("x-forwarded-for", "")
            if forwarded:
                ip = forwarded.split(",")[0].strip() or ip

        raw = environ.get("wsgi.input")
        body = b""
        if raw is not None:
            try:
                length = int(environ.get("CONTENT_LENGTH") or 0)
                if length > 0:
                    body = raw.read(min(length, self.config.max_body_bytes))  # type: ignore[attr-defined]
            except (ValueError, OSError):
                body = b""
            environ["wsgi.input"] = io.BytesIO(body)

        return Request(
            method=str(environ.get("REQUEST_METHOD", "GET")).upper(),
            path=str(environ.get("PATH_INFO") or "/"),
            query=str(environ.get("QUERY_STRING") or ""),
            headers=headers,
            raw_pairs=[],  # WSGI exposes no header order; ASGI does.
            body=body,
            client_ip=ip,
            http_version=str(environ.get("SERVER_PROTOCOL", "HTTP/1.1")).replace("HTTP/", ""),
        )

    @staticmethod
    def _deliver(response: Response, start_response: StartResponse):
        status = f"{response.status} {_reason(response.status)}"
        headers = [(str(k), str(v)) for k, v in response.headers.items()]
        headers.append(("content-length", str(len(response.body))))
        start_response(status, headers)
        return [response.body]


def _reason(status: int) -> str:
    return {
        200: "OK",
        400: "Bad Request",
        403: "Forbidden",
        413: "Payload Too Large",
        429: "Too Many Requests",
    }.get(status, "OK")


__all__ = ["FightREWSGIMiddleware"]
