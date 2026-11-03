# Quick start

Five commands from clone to a working demo. No network access, no services, no
credentials required.

## Requirements

```
Python 3.9+          (3.11+ recommended)
No runtime dependencies
```

## 1. Install

```bash
git clone https://github.com/jeremyphp/fightre
cd fightre
pip install -e .
```

## 2. Verify the crypto primitives

```bash
fightre selftest
```

This checks the challenge signing, attestation HMAC and request signature
primitives against known-answer vectors. If this fails, nothing else will work —
do not proceed.

## 3. Run the demo

```bash
python demo/run_demo.py
```

A real WSGI service, real HTTP, real proof-of-work, no network egress. Expected
shape of the output:

```
scenario                             HTTP action      score  note
------------------------------------------------------------------------------
honest browser (PoW + attestation)    200 allow           0  pass
curl script                           429 challenge      40  PoW required
REA agent: schema triage              200 tarpit         83  fabricated schema
REA agent: eats the bait              200 tarpit         92  synthetic data (canary inside)
REA agent: replays canary             403 block          91  hard block
```

Read the four actions as the intended semantics:

| Action | Meaning |
|---|---|
| `allow` | passed every check that applies |
| `challenge` | must solve proof-of-work and attest |
| `tarpit` | served a plausible, fabricated, canary-bearing response |
| `block` | hard block; accumulated trust cannot override this |

## 4. Audit your own build

```bash
fightre audit ./dist
```

Scores what a static analyser obtains from your artifact for free: source maps,
symbols, committed secrets, published schemas, internal hosts. CI-friendly:

```bash
fightre audit ./dist --fail-over 70     # exit non-zero above 70
fightre audit ./dist --markdown         # for a PR comment
fightre audit ./dist --json             # for tooling
```

Turn this on in CI before you turn on anything else. It is the cheapest finding
you will ever fix.

## 5. Integrate

**ASGI** (FastAPI / Starlette / Litestar):

```python
from fightre import Config, FightREMiddleware

app.add_middleware(FightREMiddleware, config=Config.load("fightre.json"))
```

**WSGI** (Flask / Django / plain):

```python
from fightre.wsgi import FightREWSGIMiddleware

application = FightREWSGIMiddleware(application, Config.load("fightre.json"))
```

**Browser**: serve `fightre/client/fightre.js` from your own origin. It collects
environment signals, solves the SHA-256 proof-of-work and posts a signed
attestation; the server replies with an `HttpOnly` cookie.

Generate a secret first:

```bash
fightre keygen        # prints FIGHTRE_SECRET=...
```

## Rollout order

Do not switch to enforcement on day one.

```
1. fightre audit in CI                      (day 0, zero risk)
2. mode: "observe" behind the real traffic  (day 1)
3. read the signal log for ~1 week          (day 2-7)
4. tune weights, allowlist known clients    (day 7)
5. mode: "enforce"                          (day 8)
```

Step 2–3 exist because privacy browsers and TLS-inspecting corporate egress will
produce false positives, and you need the log before you can tell which ones.

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `fightre selftest` fails | Python too old, or broken build | 3.9+; reinstall |
| Every request scores 0 | `FIGHTRE_SECRET` not set, signing disabled | `fightre keygen`, export it |
| Legit users loop on the challenge | cookies blocked on your origin | check `HttpOnly`/`SameSite` and that the JS loads from the same origin |
| `fightre stores` reports errors | Redis unreachable | stores fall back to local; fix connectivity, inspect `errors` |
| L2 signals never fire | middleware cannot see TLS/header order | add the edge signer (see `docs/DEPLOYMENT.md`) |

## Next

- [Design rationale](docs/DESIGN-RATIONALE.md) — what each layer can and cannot conclude
- [Threat model](docs/THREAT-MODEL.md) — the adversary this is built against
- [Deployment](docs/DEPLOYMENT.md) — configuration reference and edge integration
- [Signal catalogue](docs/SIGNALS.md) — every signal, its weight and trigger
