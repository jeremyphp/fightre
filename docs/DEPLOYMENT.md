# Deployment

## 1. Requirements

- Python 3.9+ (tested on 3.9–3.13)
- No runtime dependencies: FightRE is standard library only
- A reverse proxy or edge that terminates TLS
- A shared secret (`FIGHTRE_SECRET` or `security.secret`)

```bash
pip install -e .            # from a checkout
fightre selftest            # verify the primitives
fightre serve --port 8080   # guarded demo service
```

## 2. Framework integration

### ASGI (FastAPI, Starlette, Litestar)

```python
from fastapi import FastAPI
from fightre import Config, FightREMiddleware

app = FastAPI()
app.add_middleware(FightREMiddleware, config=Config.load("fightre.json"))
```

`FightREMiddleware` is pure ASGI, so it also works with Litestar's
`ASGIMiddleware` wrapper and with raw ASGI apps.

### WSGI (Flask, Django, plain WSGI)

```python
from fightre import Config
from fightre.wsgi import FightREWSGIMiddleware

application = FightREWSGIMiddleware(application, Config.load("fightre.json"))
```

WSGI cannot see header order or duplicates; the L2 header-order signal simply
never fires there. Everything else is identical.

### Which routes to mount

Mount on API and HTML routes. Skip websocket upgrades and multi-gigabyte upload
endpoints: the adapter buffers bodies up to `max_body_bytes` (1 MiB default) and
answers `413` beyond that.

## 3. Configuration

All fields are optional; defaults are safe.

| key | default | meaning |
| --- | --- | --- |
| `bands` | allow 0 / challenge 30 / deceive 55 / tarpit 70 / block 90 | score thresholds |
| `weights` | `{}` | per-signal weight overrides, e.g. `{"proto.bot_user_agent": 55}` |
| `honeypots` | common paths | paths no real client links to |
| `blocklist_ja3` | `[]` | JA3 digests (hex) treated as automation |
| `signed_paths` | `[]` | path prefixes that must carry a valid signature |
| `api_keys` | `{}` | `key-id → HMAC secret` for machine clients |
| `hard_block` | 6 signal names | decisive signals, bypass bands |
| `challenge.*` | ttl 120s, difficulty 18 | PoW tuning |
| `rate.*` | 0.5/s, burst 40 | per-identity token bucket |
| `tarpit.*` | 350ms + 60ms/point, cap 4s | deception latency |
| `security.secret` | env `FIGHTRE_SECRET` | HMAC root secret |
| `security.edge_secret` | `""` | shared secret with the edge |
| `security.trust_proxy` | `false` | trust `X-Forwarded-For` |
| `security.audit_path` | `""` | JSONL audit trail |
| `security.redact_ip` | `true` | hash identities with a daily salt |
| `poison_enabled` | `true` | serve fabricated OpenAPI/honey endpoints |
| `bypass_paths` | `/healthz`, `/favicon.ico` | never scored |

Generate a secret with `fightre keygen`. Never commit it; load it from the
platform's secret store ( Kubernetes Secret, AWS Secrets Manager, systemd
`EnvironmentFile` with 0600 ).

## 4. Edge fingerprints (optional, recommended)

FightRE never terminates TLS. If your edge can compute a JA3/JA4 hash or an
HTTP/2 SETTINGS fingerprint, forward it -- **signed**:

```
X-FightRE-JA3:        771,4865-4866-4867-49195-49199,0-23-65281,29-23-24,0
X-FightRE-H2:         1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p
X-FightRE-Edge-Ts:    1720000000
X-FightRE-Edge-Sig:   <hex HMAC-SHA256>
```

The signature covers `edge1|ts|ja3|h2|client-ip`, with a 120 s clock window.
Unsigned or invalid fingerprint headers are a hard block, because otherwise any
client could forge a clean fingerprint.

Generate a test signature:

```bash
fightre edge-sign --secret "$EDGE_SECRET" --ip 203.0.113.9 \
  --ja3 "771,4865-4866,0-23,29,0" --h2 "1:65536|15663105|0|m,a,s,p"
```

Edge options that can emit JA3: Envoy's TLS inspector (filter state
`ja3_hash`), HAProxy with a Lua sample fetch, Cloudflare Workers/Enterprise
bot-management fields, or an OpenResty `ssl_client_hello` phase. Whatever you
use, sign the headers at the edge; do not trust them from the internet.

## 5. Client attestation

Serve `client/fightre.js` from your own origin (it is also served by the demo at
`/fightre.js`) and include it on pages that need the fast path:

```html
<script src="/fightre.js"></script>
```

On load it requests `/_fightre/challenge`, solves the PoW (≈0.2–1 s at
difficulty 18), and posts a signed environment attestation. The server answers
with an `HttpOnly` cookie valid for `attest_ttl_seconds` (default 1 h). No
cookies are set for API clients that never call the endpoints.

If you use a strict Content-Security-Policy, add the script's hash or nonce as
usual; the file has no external imports.

## 6. Rollout plan

1. **Observe** (week 1): `security.audit_path` on, bands set high e.g.
   `{"block": 101}` so nothing is enforced. Watch `fightre explain audit.jsonl`.
2. **Challenge** (week 2): enable the challenge band. Verify mobile web and
   older browsers recover; raise `challenge.difficulty` only after that.
3. **Deceive** (week 3): enable `poison_enabled`. Confirm your real clients never
   request `/_fightre` decoy paths (they are not linked anywhere).
4. **Block**: leave block reserved for hard-block signals and genuinely hostile
   scores. Blocking is the least informative response; deception is usually
   better value.

## 7. Audit trail and privacy

`audit/fightre.jsonl` gets one line per decision: timestamp, request id, hashed
identity, path, score, action, signal names. Identities are SHA-256 of
`daily-salt + ip`, so logs correlate within a day and cannot be reversed into
IPs. No headers, bodies or user data are stored. Rotate/delete on your normal
retention schedule.

```bash
fightre explain audit/fightre.jsonl -v
```

## 8. Capacity and shared state

- Memory per identity: a few hundred bytes (bucket + deque). 50k identities is
  single-digit MB.
- Replay defence and rate limits are per process. With N workers behind a load
  balancer, either enable sticky sessions by client IP, or supply a shared
  store: `NonceStore.consume` and `RateLimiter.allow` are the two seams to
  reimplement (Redis `SET NX EX` for nonces, a Redis token bucket for limits).
- Attestation itself is stateless and needs no shared store.

## 9. Kubernetes / health checks

`/healthz` is bypassed by default, so liveness and readiness probes are never
challenged. Keep FightRE off the ingress path for metrics endpoints, or add them
to `bypass_paths`.

## 10. Troubleshooting

| symptom | likely cause |
| --- | --- |
| everything is challenged | `trust_proxy` mismatch (all clients share one IP) or clock skew |
| attestation never validates | secret changed between workers, or `FIGHTRE_SECRET` differs per replica |
| legitimate users blocked | `hard_block` includes a signal your product triggers (check `fightre explain`) |
| honeypot fires in monitoring | synthetic checks are hitting decoy paths; add them to `bypass_paths` |
