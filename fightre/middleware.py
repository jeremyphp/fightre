"""ASGI adapter.

Drop-in for FastAPI / Starlette / Litestar / plain ASGI::

    app = FightREMiddleware(app, Config.load("fightre.json"))

The adapter buffers the request body (bounded by ``max_body_bytes``) because
signature verification needs it; requests above the bound are rejected with 413
rather than silently scored on a truncated body.  If you proxy multi-gigabyte
uploads, mount FightRE on the API routes only.
"""

from __future__ import annotations

import asyncio
import time
import uuid
from typing import Any, Awaitable, Callable, Dict, List, Optional, Tuple

from .config import Config
from .guard import Guard, Request, Response
from .report import AuditLog

Scope = Dict[str, Any]
Message = Dict[str, Any]
Receive = Callable[[], Awaitable[Message]]
Send = Callable[[Message], Awaitable[None]]


class BodyTooLarge(Exception):
    pass


class FightREMiddleware:
    """Pure-ASGI middleware; no Starlette dependency."""

    def __init__(
        self,
        app: Callable[[Scope, Receive, Send], Awaitable[None]],
        config: Optional[Config] = None,
        guard: Optional[Guard] = None,
        audit: Optional[AuditLog] = None,
    ) -> None:
        self.app = app
        self.config = config or Config()
        self.guard = guard or Guard(self.config)
        self.audit = audit or self.guard.audit

    # -- ASGI entry point --------------------------------------------------
    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        request, replay = await self._snapshot(scope, receive)
        path = request.path

        if path == "/_fightre/challenge" and request.method == "GET":
            await self._deliver(send, self.guard.handle_challenge(request))
            return
        if path == "/_fightre/attest" and request.method == "POST":
            await self._deliver(send, self.guard.handle_attest(request))
            return
        if self.guard.is_bypass(path):
            await self.app(scope, replay, send)
            return

        verdict = self.guard.evaluate(request)
        self._audit(request, verdict)
        response = self.guard.build_response(verdict)
        if response is None:
            await self.app(scope, replay, send)
            return
        if verdict.decision.delay_ms:
            await asyncio.sleep(verdict.decision.delay_ms / 1000.0)
        await self._deliver(send, response)

    # -- helpers -----------------------------------------------------------
    def _audit(self, request: Request, verdict) -> None:
        try:
            self.audit.record(
                request_id=self._request_id(request),
                identity=request.identity,
                method=request.method,
                path=request.target,
                report=verdict.report,
                decision=verdict.decision,
                detail={"decoy": verdict.decoy, "ms": round(verdict.duration_ms, 2)},
            )
        except Exception:  # never break a request because telemetry failed
            pass

    @staticmethod
    def _request_id(request: Request) -> str:
        return request.headers.get("x-request-id") or uuid.uuid4().hex[:16]

    async def _snapshot(self, scope: Scope, receive: Receive) -> Tuple[Request, Receive]:
        raw_headers: List[Tuple[str, str]] = []
        for name, value in scope.get("headers") or []:
            raw_headers.append((name.decode("latin-1"), value.decode("latin-1")))

        headers: Dict[str, str] = {}
        for name, value in raw_headers:
            headers.setdefault(name.lower(), value)

        client = scope.get("client") or ("0.0.0.0", 0)
        ip = str(client[0]) if client else "0.0.0.0"
        if self.config.security.trust_proxy:
            forwarded = headers.get("x-forwarded-for", "")
            if forwarded:
                ip = forwarded.split(",")[0].strip() or ip

        body = await self._read_body(receive)
        request = Request(
            method=str(scope.get("method", "GET")).upper(),
            path=str(scope.get("path") or "/"),
            query=(scope.get("query_string") or b"").decode("latin-1"),
            headers=headers,
            raw_pairs=raw_headers,
            body=body,
            client_ip=ip,
            http_version=str(scope.get("http_version", "1.1")),
        )
        return request, self._replay(body)

    async def _read_body(self, receive: Receive) -> bytes:
        chunks: List[bytes] = []
        total = 0
        more = True
        while more:
            message = await receive()
            if message.get("type") == "http.disconnect":
                break
            chunk = message.get("body", b"") or b""
            total += len(chunk)
            if total > self.config.max_body_bytes:
                raise BodyTooLarge
            chunks.append(chunk)
            more = bool(message.get("more_body", False))
        return b"".join(chunks)

    @staticmethod
    def _replay(body: bytes) -> Receive:
        state = {"sent": False}

        async def receive() -> Message:
            if not state["sent"]:
                state["sent"] = True
                return {"type": "http.request", "body": body, "more_body": False}
            return {"type": "http.disconnect"}

        return receive

    @staticmethod
    async def _deliver(send: Send, response: Response) -> None:
        headers = [
            (str(k).lower().encode("latin-1"), str(v).encode("latin-1"))
            for k, v in response.headers.items()
        ]
        await send({"type": "http.response.start", "status": response.status, "headers": headers})
        await send({"type": "http.response.body", "body": response.body, "more_body": False})


__all__ = ["FightREMiddleware", "BodyTooLarge"]
