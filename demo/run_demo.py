"""End-to-end demo: a live FightRE-protected service versus simulated clients.

Run:  python demo/run_demo.py

It starts the demo WSGI app on a free port, then plays nine scenarios through the
real HTTP stack -- including a full proof-of-work + attestation dance, an
REA-style agent that follows the honey-schema, and a canary echo.  Nothing is
mocked; the table you see is what the guard decided.
"""

from __future__ import annotations

import json
import os
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from http.cookiejar import CookieJar
from typing import Dict, List, Optional, Tuple

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fightre.attest import AttestationVerifier  # noqa: E402
from fightre.challenge import solve_pow  # noqa: E402
from fightre.config import Config  # noqa: E402
from fightre.demoapp import demo_app  # noqa: E402
from fightre.guard import Guard  # noqa: E402
from fightre.signing import RequestSigner  # noqa: E402
from fightre.wsgi import FightREWSGIMiddleware  # noqa: E402

BROWSER_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate, br",
    "Sec-CH-UA": '"Chromium";v="131", "Not_A Brand";v="24"',
    "Sec-CH-UA-Mobile": "?0",
    "Sec-CH-UA-Platform": '"Windows"',
    "Sec-Fetch-Site": "none",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Dest": "document",
    "Upgrade-Insecure-Requests": "1",
}

AGENT_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
        "HeadlessChrome/131.0.0.0 Safari/537.36 Playwright/1.49.1"
    ),
    "Accept": "application/json",
    "Accept-Language": "en-US",
    "Accept-Encoding": "gzip, deflate, br",
    "Sec-CH-UA": '"Chromium";v="131"',
    "Sec-CH-UA-Platform": '"Linux"',
    "Sec-Fetch-Site": "none",
    "Sec-Fetch-Mode": "cors",
    "Sec-Fetch-Dest": "empty",
}

CLEAN_ENV = {
    "ua": BROWSER_HEADERS["User-Agent"],
    "webdriver": False,
    "cdp": False,
    "native_clean": True,
    "webgl_renderer": "ANGLE (NVIDIA GeForce RTX 3060 Direct3D11 vs_5_0 ps_5_0)",
    "consistent": True,
    "devtools_open": False,
    "hardware_concurrency": 16,
    "plugins": 5,
    "platform": "Win32",
    "touch": False,
    "honeypot_filled": False,
}


class Client:
    """Tiny cookie-aware HTTP client."""

    def __init__(self, base: str) -> None:
        self.base = base
        self.jar = CookieJar()
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.jar)
        )
        self.cookies: Dict[str, str] = {}

    def request(
        self,
        method: str,
        path: str,
        headers: Optional[Dict[str, str]] = None,
        body: Optional[bytes] = None,
        timeout: float = 10.0,
    ) -> Tuple[int, Dict[str, str], bytes, float]:
        started = time.perf_counter()
        request = urllib.request.Request(
            self.base + path, data=body, method=method, headers=headers or {}
        )
        try:
            with self.opener.open(request, timeout=timeout) as response:
                payload = response.read()
                elapsed = (time.perf_counter() - started) * 1000
                return response.status, dict(response.headers), payload, elapsed
        except urllib.error.HTTPError as error:
            payload = error.read()
            elapsed = (time.perf_counter() - started) * 1000
            return error.code, dict(error.headers or {}), payload, elapsed


def start_server(config: Config) -> Tuple[object, str, Guard]:
    from wsgiref.simple_server import WSGIRequestHandler, make_server

    class QuietHandler(WSGIRequestHandler):
        def log_message(self, *args):  # noqa: D102 - keep the demo output clean
            pass

    guard = Guard(config)
    app = FightREWSGIMiddleware(demo_app, config, guard=guard)
    httpd = make_server("127.0.0.1", 0, app, handler_class=QuietHandler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    return httpd, f"http://127.0.0.1:{httpd.server_port}", guard


def scenario_rows() -> List[str]:
    return []


def run() -> int:
    config = Config.from_dict(
        {
            "signed_paths": ["/api/v1/partner"],
            "api_keys": {"partner-a": "partner-secret-9f2c"},
            "security": {"secret": "demo-secret-not-for-production", "audit_path": ""},
            "tarpit": {"base_ms": 120, "per_point_ms": 40, "max_ms": 1200, "jitter_ms": 0},
        }
    )
    httpd, base, guard = start_server(config)
    rows: List[Tuple[str, str, str, str, str]] = []

    def record(name: str, status: int, body: bytes, elapsed: float, headers: Dict[str, str]) -> None:
        audit = guard.audit.recent(1)[0] if guard.audit.recent(1) else {}
        action = headers.get("x-fightre-action") or audit.get("action") or "allow"
        score = f"{audit.get('score', 0):.0f}"
        text = body[:800].decode("utf-8", "ignore")
        if action == "challenge":
            note = "PoW required"
        elif '"openapi"' in text:
            note = "fabricated schema"
        elif action in ("tarpit", "deceive"):
            note = "synthetic data (canary inside)"
        elif action == "block":
            note = "hard block"
        else:
            note = "pass"
        if elapsed > 200:
            note += f", {elapsed:.0f}ms"
        rows.append((name, str(status), str(action), score, note))

    print(f"FightRE demo - {base}")
    print("=" * 78)

    # 1. honest browser: challenge -> PoW -> attestation -> normal traffic
    browser = Client(base)
    status, headers, body, elapsed = browser.request("GET", "/_fightre/challenge", BROWSER_HEADERS)
    challenge = json.loads(body)["challenge"]
    nonce = solve_pow(challenge["jti"], challenge["difficulty"])
    attestation = AttestationVerifier(config.resolve_secret(), 3600, 30).build(
        challenge["jti"], CLEAN_ENV
    )
    browser.request(
        "POST",
        "/_fightre/attest",
        {**BROWSER_HEADERS, "Content-Type": "application/json"},
        json.dumps({"token": challenge["token"], "nonce": nonce, "attestation": attestation}).encode(),
    )
    status, headers, body, elapsed = browser.request("GET", "/api/v1/items", BROWSER_HEADERS)
    record("honest browser (PoW + attestation)", status, body, elapsed, headers)

    # 2. scripted client
    curl = Client(base)
    status, headers, body, elapsed = curl.request(
        "GET", "/api/v1/items", {"User-Agent": "curl/8.5.0", "Accept": "*/*"}
    )
    record("curl script", status, body, elapsed, headers)

    # 3. REA-style agent asks for the schema
    agent = Client(base)
    status, headers, body, elapsed = agent.request("GET", "/openapi.json", AGENT_HEADERS)
    record("REA agent: schema triage", status, body, elapsed, headers)

    # 4. agent follows the honey-schema
    status, headers, body, elapsed = agent.request("GET", "/api/v2/internal/keys", AGENT_HEADERS)
    record("REA agent: eats the bait", status, body, elapsed, headers)
    bait = json.loads(body)["keys"][0]["kid"]

    # 5. agent uses what it learned
    status, headers, body, elapsed = agent.request(
        "GET", f"/api/v1/items?key={urllib.parse.quote(bait)}", AGENT_HEADERS
    )
    record("REA agent: replays canary", status, body, elapsed, headers)

    # 6. forged attestation
    forger = Client(base)
    status, headers, body, elapsed = forger.request(
        "GET", "/api/v1/items", {**BROWSER_HEADERS, "Cookie": "fightre_att=Zm9yZ2Vk.AAAA"}
    )
    record("forged attestation", status, body, elapsed, headers)

    # 7. unsigned edge fingerprint headers
    spoof = Client(base)
    status, headers, body, elapsed = spoof.request(
        "GET",
        "/api/v1/items",
        {**BROWSER_HEADERS, "X-FightRE-JA3": "771,4865-4866-4867,0-23-65281,29-23,0"},
    )
    record("spoofed JA3 edge header", status, body, elapsed, headers)

    # 8. honeypot path
    scanner = Client(base)
    status, headers, body, elapsed = scanner.request(
        "GET", "/.env", {"User-Agent": "Go-http-client/1.1"}
    )
    record("scanner hits /.env", status, body, elapsed, headers)

    # 9. signed request, replayed
    signer = RequestSigner(config.api_keys)
    sign_headers = {**BROWSER_HEADERS, "Content-Type": "application/json"}
    auth, signature = signer.sign("partner-a", "POST", "/api/v1/partner/ping", b'{"ping":1}')
    sign_headers["Authorization"] = auth
    sign_headers["X-FightRE-Sign"] = signature
    partner = Client(base)
    first, h1, b1, e1 = partner.request(
        "POST", "/api/v1/partner/ping", sign_headers, b'{"ping":1}'
    )
    record("signed request (fresh)", first, b1, e1, h1)
    second, h2, b2, e2 = partner.request(
        "POST", "/api/v1/partner/ping", sign_headers, b'{"ping":1}'
    )
    record("signed request (replayed)", second, b2, e2, h2)

    httpd.shutdown()
    httpd.server_close()

    widths = (34, 6, 10, 6, 20)
    print(
        f"{'scenario':<{widths[0]}} {'HTTP':>{widths[1]}} {'action':<{widths[2]}} "
        f"{'score':>{widths[3]}}  note"
    )
    print("-" * 78)
    for name, status, action, score, note in rows:
        print(f"{name:<{widths[0]}} {status:>{widths[1]}} {action:<{widths[2]}} {score:>{widths[3]}}  {note}")
    print("-" * 78)
    summary = guard.audit.summary()
    print(f"canaries issued: {len(guard.canaries)}   decisions: {summary['decisions']}")
    print(f"by action: {summary['by_action']}")
    print("leak attribution:", guard.decepter.collect_leaks(bait)[:1] or "none")
    return 0


if __name__ == "__main__":
    raise SystemExit(run())
