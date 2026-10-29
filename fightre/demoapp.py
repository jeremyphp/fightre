"""Demo application: a tiny WSGI service that FightRE protects.

Used by ``fightre serve`` and by ``demo/run_demo.py`` so the README can show real
HTTP exchanges instead of screenshots.
"""

from __future__ import annotations

import json
import os
from typing import Callable, Dict, List, Tuple

from . import __version__
from .guard import Response

ITEMS = [
    {"id": "itm_1041", "name": "Starter plan", "price": 19, "status": "active"},
    {"id": "itm_1042", "name": "Team plan", "price": 79, "status": "active"},
    {"id": "itm_1043", "name": "Enterprise plan", "price": 249, "status": "paused"},
]

INDEX_HTML = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>FightRE demo</title>
<style>
  body {{ font: 15px/1.5 system-ui, sans-serif; margin: 3rem auto; max-width: 44rem; }}
  code {{ background: #f4f4f5; padding: .1rem .3rem; border-radius: 4px; }}
  #state {{ padding: .6rem .9rem; border-radius: 6px; background: #eef6ff; }}
</style>
</head>
<body>
  <h1>FightRE demo service</h1>
  <p id="state">attestation: pending…</p>
  <p>The page bootstraps a proof-of-work challenge through <code>fightre.js</code>.</p>
  <p>API: <a href="/api/v1/items">/api/v1/items</a> · honeypot:
     <a href="/admin/users">/admin/users</a> · schema: <a href="/openapi.json">/openapi.json</a></p>
  <script src="/fightre.js"></script>
</body>
</html>
"""


def _read_client() -> bytes:
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "client", "fightre.js")
    try:
        with open(path, "rb") as fh:
            return fh.read()
    except OSError:
        return b"/* fightre.js missing */"


def _send(start_response, response: Response):
    status = {200: "200 OK", 404: "404 Not Found"}.get(response.status, "200 OK")
    headers: List[Tuple[str, str]] = [(str(k), str(v)) for k, v in response.headers.items()]
    headers.append(("content-length", str(len(response.body))))
    start_response(status, headers)
    return [response.body]


def demo_app(environ: Dict[str, object], start_response: Callable):
    path = str(environ.get("PATH_INFO") or "/")
    method = str(environ.get("REQUEST_METHOD") or "GET").upper()

    if path == "/" and method == "GET":
        body = INDEX_HTML.format().encode("utf-8")
        return _send(
            start_response,
            Response(200, body, {"content-type": "text/html; charset=utf-8"}),
        )
    if path == "/fightre.js":
        return _send(
            start_response,
            Response(200, _read_client(), {"content-type": "application/javascript; charset=utf-8"}),
        )
    if path == "/healthz":
        return _send(start_response, Response.json(200, {"ok": True, "version": __version__}))
    if path == "/api/v1/items":
        return _send(start_response, Response.json(200, {"items": ITEMS, "total": len(ITEMS)}))
    if path == "/api/v1/me":
        return _send(start_response, Response.json(200, {"user": "demo", "plan": "team"}))
    if path == "/api/v1/partner/ping":
        return _send(start_response, Response.json(200, {"pong": True, "signed": True}))
    if path == "/admin/users":
        # Never linked from the UI: reaching this means someone is guessing paths.
        return _send(start_response, Response.json(200, {"users": [], "total": 0}))

    return _send(start_response, Response.json(404, {"error": "not_found"}))


__all__ = ["ITEMS", "demo_app"]
