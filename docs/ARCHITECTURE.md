# Architecture

## 1. Request pipeline

```
                 ┌──────────────────────────────────────────────────────────┐
 HTTP request ──▶│ adapter (ASGI / WSGI)                                    │
                 │   ├─ snapshot: method, path, headers(+order), body, ip    │
                 │   ├─ /_fightre/challenge  → issue PoW challenge          │
                 │   ├─ /_fightre/attest     → verify PoW + attestation     │
                 │   └─ bypass list (e.g. /healthz)                          │
                 └───────────────┬──────────────────────────────────────────┘
                                 ▼
                 ┌──────────────────────────────────────────────────────────┐
                 │ Guard.evaluate(request)                                  │
                 │  L1 rate limiter · path-diversity tracker                │
                 │  L2 header analysis · edge fingerprint (HMAC) · agent     │
                 │  L3 attestation cookie (HMAC, TTL)                       │
                 │  L4 request signature · honeypots · honey-schema          │
                 │  L5 canary echo detection                                │
                 │        ↓                                                  │
                 │  RiskEngine (noisy-OR)  →  score 0..100 + reasons         │
                 │        ↓                                                  │
                 │  Policy (bands, hard-block list, maze cap) → Decision     │
                 └───────────────┬──────────────────────────────────────────┘
                                 ▼
        allow ──▶ app     challenge ──▶ 429 + PoW      deceive/tarpit ──▶ 200 synthetic
                                 block ──▶ 403 (no detail)     + audit record (JSONL)
```

## 2. Modules

| Module | Layer | Responsibility |
| --- | --- | --- |
| `fightre/signals.py` | all | signal catalogue: name, layer, weight, description |
| `fightre/scoring.py` | all | noisy-OR aggregation, explanation, critical floor |
| `fightre/policy.py` | all | bands → action, hard blocks, "never block bait" cap |
| `fightre/guard.py` | all | orchestration, per-request verdict, response builders |
| `fightre/headers.py` | L2 | UA/client-hints contradiction, order anomalies, smuggling |
| `fightre/fingerprint.py` | L2 | JA3/JA4-style ingestion, edge HMAC verification |
| `fightre/agent_detect.py` | L2/L4 | REA toolchain markers, introspection, artifact probing |
| `fightre/challenge.py` | L3 | PoW issue/verify/solve, single-use nonce store |
| `fightre/attest.py` | L3 | environment attestation, per-challenge key, env analysis |
| `fightre/signing.py` | L4 | HMAC request signing, clock skew, replay defence |
| `fightre/ratelimit.py` | L1 | token buckets per identity |
| `fightre/decoy.py` | L4 | honey-schema, fabricated endpoints, fake credentials |
| `fightre/deception.py` | L4 | synthetic payloads, tarpit delays, attribution |
| `fightre/canary.py` | L5 | canary tokens, zero-width watermarking |
| `fightre/report.py` | - | JSONL audit trail, salted identity hashing |
| `fightre/middleware.py` / `wsgi.py` | - | framework adapters |
| `fightre/artifacts.py` | L0 | pre-deployment build audit |
| `fightre/cli.py` | - | `serve / audit / signals / selftest / keygen / explain / edge-sign` |
| `fightre/client/fightre.js` | L3 | browser env collection, SHA-256 PoW, attestation |

## 3. Scoring model

Each signal is evidence with a weight `w ∈ [0, 100]`, interpreted as a
probability that the client is not genuine. Independent evidence combines as:

```
p = 1 - Π (1 - w_i / 100)
score = max(0, 100·p - trust)
```

Properties that matter operationally:

- **bounded**: no number of weak signals reaches 100 without a strong one;
- **associative**: detectors can run in any order and in parallel;
- **explainable**: `RiskReport.reasons` lists every contributing signal with its
  weight, so a support engineer can answer "why was I blocked?" without guessing.

`trust` comes from a valid attestation (+30 by default) or a valid request
signature (+30). A signal marked `critical` raises the floor to 88 regardless of
the arithmetic, because some evidence is decisive on its own.

## 4. Decision policy

| band | score | action | response |
| --- | --- | --- | --- |
| allow | 0–29 | pass through | real response |
| challenge | 30–54 | 429 | PoW token; real browsers recover in <1s |
| deceive | 55–69 | 200 | synthetic data with canary |
| tarpit | 70–89 | 200 after delay | synthetic data with canary |
| block | 90–100 | 403 | `{"error":"forbidden"}`, nothing else |

Two overrides sit on top of the bands:

- **hard block** (`app.replay_detected`, `client.attestation_forged`,
  `proto.edge_signature_invalid`, `data.canary_echo`, smuggling probes). These
  are decisive regardless of trust or an allow-list.
- **maze cap**: hitting bait (`app.honeypot_endpoint`,
  `app.decoy_schema_access`) never escalates to a block. A blocked agent learns
  it was detected and restarts; a deceived agent keeps spending budget and takes
  our canaries with it.

Bands, weights and both lists are configuration, not code (`fightre/presets/`).

## 5. State and concurrency

All state is in-process and thread-safe:

| state | structure | bound |
| --- | --- | --- |
| solved challenges | `NonceStore` (TTL dict) | 200k entries |
| signature nonces | `NonceStore` | 200k entries |
| rate buckets | `RateLimiter` dict | 50k identities |
| path diversity | `SequenceTracker` deques | 20k identities × 60s |
| canaries | `CanaryRegistry` | TTL 90 days |

Multi-worker deployments: enable sticky sessions (attestation is stateless, but
rate limits and replay stores are not) or point the stores at Redis via the
`NonceStore` interface. Cross-worker replay defence is the only thing that
strictly requires shared state; it is documented in `docs/DEPLOYMENT.md`.

## 6. Performance

`Guard.evaluate` is arithmetic over a header dict plus at most a few HMACs:
roughly 20–40 µs per request on a laptop-class CPU, excluding tarpit sleeps.
Tarpits are bounded by `tarpit.max_ms` so they cannot be turned into a
self-inflicted denial of service.

## 7. Failure modes

| failure | behaviour | rationale |
| --- | --- | --- |
| missing secret | ephemeral secret generated, challenges invalid after restart | never block traffic because of misconfiguration |
| bad config bands | `ValueError` at startup | fail fast, not at request time |
| audit disk full | write swallowed, request unaffected | telemetry must not break serving |
| oversized body | `413` from the adapter | signature cannot cover a truncated body |
| exception in evaluate | request fails closed (500) | a silent fail-open is a bypass; wrap the middleware to fail open if availability dominates |

## 8. Extending

**New signal**: add a `SignalSpec` to `fightre/signals.py`, emit it from the
layer that owns the evidence, add a test asserting the score contribution. No
schema migration, no new dependency.

**New adapter**: build a `Request` (method, path, headers, raw pairs, body, ip),
call `Guard.evaluate`, then `Guard.build_response`. `None` means "pass through".
The ASGI and WSGI adapters are ~100 lines each and are the template.
