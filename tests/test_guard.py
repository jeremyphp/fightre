"""Guard integration tests: request in, verdict out."""

from __future__ import annotations

import json
import unittest

from fightre.config import Config
from fightre.guard import Guard, Request
from fightre.policy import Action

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

AGENT_HEADERS = {
    "user-agent": (
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
        "HeadlessChrome/131.0.0.0 Safari/537.36 Playwright/1.49.1"
    ),
    "accept": "application/json",
    "accept-encoding": "gzip, deflate, br",
}


def make_guard(**sections) -> Guard:
    payload = {
        "security": {"secret": "guard-test-secret", "audit_path": ""},
        "tarpit": {"base_ms": 1, "per_point_ms": 0, "max_ms": 2, "jitter_ms": 0},
    }
    payload.update(sections)
    return Guard(Config.from_dict(payload))


def make_request(path: str = "/api/v1/items", headers=None, **kwargs) -> Request:
    return Request(
        method=kwargs.pop("method", "GET"),
        path=path,
        headers=headers if headers is not None else dict(BROWSER_HEADERS),
        client_ip=kwargs.pop("client_ip", "203.0.113.7"),
        **kwargs,
    )


class GuardTests(unittest.TestCase):
    def setUp(self) -> None:
        self.guard = make_guard()

    def test_clean_browser_is_allowed(self) -> None:
        verdict = self.guard.evaluate(make_request())
        self.assertEqual(verdict.decision.action, Action.ALLOW)
        self.assertIn("client.missing_attestation", verdict.report.names)
        self.assertLess(verdict.report.score, 30)

    def test_valid_attestation_grants_trust(self) -> None:
        blob = self.guard.attestation.build("jti-x", {"ua": CHROME_UA, "webgl_renderer": "ANGLE"})
        request = make_request(headers={**BROWSER_HEADERS, "cookie": f"fightre_att={blob}"})
        verdict = self.guard.evaluate(request)
        self.assertTrue(verdict.attestation.ok)
        self.assertGreater(verdict.attestation.trust, 0)
        self.assertEqual(verdict.report.score, 0)

    def test_scripted_client_is_challenged(self) -> None:
        verdict = self.guard.evaluate(make_request(headers={"user-agent": "curl/8.5.0"}))
        self.assertEqual(verdict.decision.action, Action.CHALLENGE)
        response = self.guard.build_response(verdict)
        self.assertIsNotNone(response)
        self.assertEqual(response.status, 429)
        payload = json.loads(response.body)
        self.assertIn("token", payload["challenge"])

    def test_agent_triage_gets_honey_schema(self) -> None:
        verdict = self.guard.evaluate(make_request("/openapi.json", AGENT_HEADERS))
        self.assertEqual(verdict.decision.action, Action.TARPIT)
        response = self.guard.build_response(verdict)
        payload = json.loads(response.body)
        self.assertEqual(payload["openapi"], "3.0.3")
        self.assertIn("/api/v2/internal/keys", payload["paths"])

    def test_agent_following_bait_stays_in_maze(self) -> None:
        verdict = self.guard.evaluate(
            make_request("/api/v2/internal/keys", AGENT_HEADERS)
        )
        self.assertEqual(verdict.decision.action, Action.TARPIT)
        self.assertEqual(verdict.decision.band, "maze")
        response = self.guard.build_response(verdict)
        payload = json.loads(response.body)
        self.assertIn("keys", payload)
        canary = payload["keys"][0]["kid"]
        self.assertIsNotNone(self.guard.canaries.get(canary))

    def test_canary_echo_is_hard_blocked(self) -> None:
        canary = self.guard.canaries.issue("tenant:42")
        verdict = self.guard.evaluate(make_request(query=f"key={canary.token}"))
        self.assertEqual(verdict.decision.action, Action.BLOCK)
        self.assertIn("data.canary_echo", verdict.report.names)

    def test_honeypot_never_blocks(self) -> None:
        verdict = self.guard.evaluate(make_request("/.env", {"user-agent": "curl/8.5.0"}))
        self.assertEqual(verdict.decision.action, Action.TARPIT)
        self.assertEqual(verdict.decision.band, "maze")
        response = self.guard.build_response(verdict)
        self.assertEqual(response.status, 200)

    def test_forged_cookie_is_blocked(self) -> None:
        request = make_request(headers={**BROWSER_HEADERS, "cookie": "fightre_att=Zm9yZ2Vk.AAAA"})
        verdict = self.guard.evaluate(request)
        self.assertEqual(verdict.decision.action, Action.BLOCK)
        self.assertIn("client.attestation_forged", verdict.report.names)

    def test_spoofed_edge_headers_blocked(self) -> None:
        request = make_request(
            headers={**BROWSER_HEADERS, "x-fightre-ja3": "771,4865-4866,0-23,29,0"}
        )
        verdict = self.guard.evaluate(request)
        self.assertEqual(verdict.decision.action, Action.BLOCK)
        self.assertIn("proto.edge_signature_invalid", verdict.report.names)

    def test_trusted_edge_blocklist(self) -> None:
        import time

        from fightre.fingerprint import edge_signature, ja3_digest

        digest = ja3_digest(771, [4865], [0], [29], [0])
        guard = make_guard(
            blocklist_ja3=[digest],
            security={"secret": "s", "audit_path": "", "edge_secret": "edge-secret"},
        )
        ts = str(int(time.time()))
        signature = edge_signature("edge-secret", ts, digest, "h2", "198.51.100.4")
        request = Request(
            method="GET",
            path="/api/v1/items",
            headers={
                **BROWSER_HEADERS,
                "x-fightre-ja3": digest,
                "x-fightre-h2": "h2",
                "x-fightre-edge-ts": ts,
                "x-fightre-edge-sig": signature,
            },
            client_ip="198.51.100.4",
        )
        verdict = guard.evaluate(request)
        self.assertIn("proto.ja3_known_bot", verdict.report.names)

    def test_signed_path_without_signature(self) -> None:
        guard = make_guard(signed_paths=["/api/partner"])
        verdict = guard.evaluate(make_request("/api/partner/items"))
        self.assertIn("app.missing_signature", verdict.report.names)

    def test_sequence_scan_detects_crawling(self) -> None:
        guard = make_guard(sequence_paths=5)
        triggered = False
        for index in range(6):
            verdict = guard.evaluate(make_request(f"/api/v1/items/{index}"))
            triggered = triggered or "app.sequence_scan" in verdict.report.names
        self.assertTrue(triggered)

    def test_verdict_is_serialisable(self) -> None:
        verdict = self.guard.evaluate(make_request("/openapi.json", AGENT_HEADERS))
        payload = verdict.as_dict()
        self.assertEqual(payload["action"], "tarpit")
        self.assertIn("signals", payload)
        self.assertIn("attestation", payload)


if __name__ == "__main__":
    unittest.main()
