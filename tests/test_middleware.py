"""ASGI end-to-end tests through FightREMiddleware (no server needed)."""

from __future__ import annotations

import asyncio
import json
import unittest
from typing import Dict, List, Optional, Tuple

from fightre.challenge import solve_pow
from fightre.config import Config
from fightre.middleware import FightREMiddleware

CHROME_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
)
BROWSER_HEADERS = {
    "user-agent": CHROME_UA,
    "sec-ch-ua": '"Chromium";v="131", "Not_A Brand";v="24"',
    "sec-ch-ua-platform": '"Windows"',
    "sec-fetch-site": "none",
    "accept": "text/html",
    "accept-encoding": "gzip, deflate, br",
    "accept-language": "en-US,en;q=0.9",
}


async def echo_app(scope, receive, send):
    body = b""
    while True:
        message = await receive()
        if message["type"] == "http.request":
            body += message.get("body", b"")
            if not message.get("more_body"):
                break
        else:
            break
    payload = json.dumps({"path": scope["path"], "body_len": len(body)}).encode()
    await send(
        {
            "type": "http.response.start",
            "status": 200,
            "headers": [(b"content-type", b"application/json")],
        }
    )
    await send({"type": "http.response.body", "body": payload})


def call(
    app,
    method: str = "GET",
    path: str = "/api/v1/items",
    headers: Optional[Dict[str, str]] = None,
    body: bytes = b"",
    query: str = "",
) -> Tuple[int, Dict[str, str], bytes]:
    scope = {
        "type": "http",
        "method": method,
        "path": path,
        "query_string": query.encode(),
        "headers": [(k.lower().encode(), v.encode()) for k, v in (headers or {}).items()],
        "client": ("198.51.100.9", 4432),
        "http_version": "1.1",
        "scheme": "https",
        "server": ("testserver", 443),
    }
    inbox: List[dict] = [{"type": "http.request", "body": body, "more_body": False}]
    sent: List[dict] = []

    async def receive():
        if inbox:
            return inbox.pop(0)
        return {"type": "http.disconnect"}

    async def send(message):
        sent.append(message)

    asyncio.run(app(scope, receive, send))
    start = next(m for m in sent if m["type"] == "http.response.start")
    payload = b"".join(m.get("body", b"") for m in sent if m["type"] == "http.response.body")
    response_headers = {
        k.decode(): v.decode() for k, v in start.get("headers", [])
    }
    return start["status"], response_headers, payload


class MiddlewareTests(unittest.TestCase):
    def setUp(self) -> None:
        self.config = Config.from_dict(
            {"security": {"secret": "mw-test-secret", "audit_path": ""}}
        )
        self.app = FightREMiddleware(echo_app, self.config)

    def test_allowed_request_reaches_app(self) -> None:
        status, _, body = call(self.app, headers=BROWSER_HEADERS)
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["path"], "/api/v1/items")

    def test_challenge_endpoint_issues_work(self) -> None:
        status, _, body = call(self.app, path="/_fightre/challenge")
        self.assertEqual(status, 200)
        challenge = json.loads(body)["challenge"]
        self.assertGreaterEqual(challenge["difficulty"], 1)
        self.assertIn("token", challenge)

    def test_attestation_flow_grants_trust(self) -> None:
        _, _, body = call(self.app, path="/_fightre/challenge")
        challenge = json.loads(body)["challenge"]
        nonce = solve_pow(challenge["jti"], challenge["difficulty"])
        attestation = self.app.guard.attestation.build(
            challenge["jti"], {"ua": CHROME_UA, "webgl_renderer": "ANGLE"}
        )
        payload = json.dumps(
            {"token": challenge["token"], "nonce": nonce, "attestation": attestation}
        ).encode()
        status, headers, body = call(
            self.app,
            method="POST",
            path="/_fightre/attest",
            headers={"content-type": "application/json"},
            body=payload,
        )
        self.assertEqual(status, 200)
        self.assertTrue(json.loads(body)["ok"])
        cookie = headers["set-cookie"].split(";")[0]

        status, _, _ = call(
            self.app, headers={**BROWSER_HEADERS, "cookie": cookie}
        )
        self.assertEqual(status, 200)
        verdict = self.app.guard.audit.recent(1)[0]
        self.assertEqual(verdict["action"], "allow")
        self.assertEqual(verdict["score"], 0)

    def test_scripted_client_gets_challenge(self) -> None:
        status, headers, body = call(self.app, headers={"user-agent": "python-requests/2.32"})
        self.assertEqual(status, 429)
        self.assertEqual(headers["x-fightre-action"], "challenge")
        self.assertIn("challenge", json.loads(body))

    def test_agent_gets_honey_schema(self) -> None:
        status, headers, body = call(
            self.app,
            path="/openapi.json",
            headers={"user-agent": "HeadlessChrome/131 Playwright/1.49"},
        )
        self.assertEqual(status, 200)
        self.assertEqual(headers["x-fightre-action"], "tarpit")
        self.assertIn("openapi", json.loads(body))

    def test_forged_cookie_blocked(self) -> None:
        status, headers, _ = call(
            self.app, headers={**BROWSER_HEADERS, "cookie": "fightre_att=bad.bad"}
        )
        self.assertEqual(status, 403)
        self.assertEqual(headers["x-fightre-action"], "block")

    def test_bypass_paths_skip_scoring(self) -> None:
        status, _, body = call(self.app, path="/healthz", headers={"user-agent": "curl/8"})
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["path"], "/healthz")

    def test_body_is_replayed_to_app(self) -> None:
        status, _, body = call(
            self.app,
            method="POST",
            path="/api/v1/echo",
            headers={**BROWSER_HEADERS, "content-type": "application/json"},
            body=b'{"hello":"world"}',
        )
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["body_len"], 17)

    def test_audit_records_decisions(self) -> None:
        call(self.app, headers=BROWSER_HEADERS)
        recent = self.app.guard.audit.recent(1)
        self.assertEqual(len(recent), 1)
        self.assertIn("score", recent[0])
        self.assertNotEqual(recent[0]["identity"], "198.51.100.9")  # redacted


if __name__ == "__main__":
    unittest.main()
