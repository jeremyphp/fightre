# FightRE

**Five-layer anti-reverse-engineering defence for web services — built for the age of AI agents.**

[![ci](https://github.com/your-org/fightre/actions/workflows/ci.yml/badge.svg)](https://github.com/your-org/fightre/actions/workflows/ci.yml)
[![license: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![python](https://img.shields.io/badge/python-3.9%2B-blue.svg)](pyproject.toml)
[![dependencies](https://img.shields.io/badge/runtime%20dependencies-0-success.svg)](pyproject.toml)

REA showed how quickly an LLM with the right toolchain can take software apart.
FightRE is the defence layer built for that world: it raises the cost of every
verified fact, poisons the evidence chain, and makes anything extracted traceable.

You cannot make a binary unreadable on someone else's machine. What you *can* do
is make the extraction expensive, make the automation contradict itself, and
make anything that leaks traceable back to the session that leaked it.

FightRE is that, as one small Python package with **zero runtime dependencies**
and a browser client, plus a build audit that tells you what an agent would
harvest from your artifact in five minutes.

**Jump to:** [Background](#background-what-rea-actually-is) ·
[What it does](#what-fightre-does-about-it) · [Demo](#see-it-work) ·
[Quick start](#install-and-integrate) · [Docs](#documentation)

```
$ fightre serve            # guarded demo service
$ fightre audit ./dist     # what would REA get from this build?
$ fightre native ./dist    # symbols, DWARF/PDB, PIE/NX/RELRO posture
$ fightre selfcheck        # is this process being instrumented?
$ fightre manifest sign ./dist --out build.manifest.json
$ fightre selftest         # verify the crypto primitives
```

---

## Background: what REA actually is

In October 2026 a project called REA ("Reverse Engineer Anything") reached
roughly **70–80k stars in three days** and topped GitHub Trending. It is not a
disassembler. It is an **MCP server that lets an LLM drive a complete RE
toolchain** — Ghidra, IDA, Hopper, JEB, Rizin, JADX, Frida, GDB, Playwright,
Chrome DevTools Protocol, mitmproxy, tshark, binwalk — and records every
observation as *evidence* with confidence and provenance.

Three properties explain the impact:

1. **It runs locally.** The target is never uploaded, so there is no cloud-side
   point where a vendor could detect "this binary is being reversed". Defence has
   to live inside your artifact, your protocol, your service and your data.
2. **Expertise stops being the bottleneck.** You state the goal in English; the
   agent selects engines, correlates findings and writes the narrative.
3. **The output is semantic.** It returns "this is how the clipboard bridge
   works" plus citations, not a wall of assembly — and it carries an obligation
   ledger of what is still unproven.

That third property is also its weakness: **the agent is only as good as the
evidence it can collect.** Poison the evidence and the reconstruction is
confidently wrong.

Deep dive on the pipeline and its seams: **[docs/REA.md](docs/REA.md)**.

## What FightRE does about it

| Seam | Why it is exploitable | FightRE |
| --- | --- | --- |
| **Cost per verified fact** | every fact costs a tool call, a token budget and wall time | proof-of-work challenge, per-identity budgets, bounded tarpits |
| **Evidence consistency** | the agent trusts what it observes and cites it | fabricated OpenAPI + decoy endpoints with plausible-but-wrong data |
| **Provenance** | extracted records travel into reports, repos and datasets | canary tokens, zero-width watermarks, cross-worker attribution |
| **What ships** | symbols, maps, schemas and secrets are free analysis input | `fightre audit`, `fightre native`, signed build manifests |
| **Where the truth lives** | client code is readable; server code is not | attested sessions gate the logic that actually matters |

## The idea in one table

| Layer | Question it answers | Mechanism |
| --- | --- | --- |
| **L0 artifact** | What does my build give away for free? | `fightre audit`: source maps, debug symbols, committed secrets, published schemas, internal hosts |
| **L1 network** | Is this one identity behaving like a machine? | token-bucket budgets, path-diversity crawler detection |
| **L2 protocol** | Does the wire match the claimed client? | User-Agent ↔ `sec-ch-ua` contradictions, header order, duplicate/smuggled headers, JA3/HTTP2 fingerprints (HMAC-signed by the edge) |
| **L3 client** | Is this really a browser? | proof-of-work challenge, environment attestation (webdriver, CDP leaks, patched natives, software renderers, consistency), per-challenge HMAC key |
| **L4 application** | Is it using the API the way a client does? | HMAC request signing, nonce replay defence, honeypot endpoints, introspection detection, **fabricated API schemas** |
| **L5 data** | Where did this copy come from? | canary tokens in synthetic responses, zero-width watermarks in strings, leak attribution |

## See it work

The repo ships an end-to-end demo (`python demo/run_demo.py`): a real WSGI
service, real HTTP, real proof-of-work. Actual output:

```
scenario                             HTTP action      score  note
------------------------------------------------------------------------------
honest browser (PoW + attestation)    200 allow           0  pass
curl script                           429 challenge      40  PoW required
REA agent: schema triage              200 tarpit         83  fabricated schema, 655ms
REA agent: eats the bait              200 tarpit         92  synthetic data (canary inside), 1018ms
REA agent: replays canary             403 block          91  hard block
forged attestation                    403 block          88  hard block
spoofed JA3 edge header               403 block          88  hard block
scanner hits /.env                    200 tarpit         91  synthetic data (canary inside), 961ms
signed request (fresh)                200 allow           0  pass
signed request (replayed)             403 block          88  hard block
------------------------------------------------------------------------------
canaries issued: 2
leak attribution: [{'token': 'cnry_7ae0...', 'owner': 'decoy:/api/v2/internal/keys:127.0.0.1'}]
```

Three design decisions show up in that table:

1. **The agent is not blocked at the door.** It gets a `200` with a fabricated
   `openapi.json`, then fabricated keys — each carrying a canary. Blocking an
   agent teaches it to change; deceiving it spends its budget and taints its
   notes.
2. **Using the bait is fatal.** The moment the canary comes back, the verdict is
   a hard block that no amount of trust can override.
3. **Honest browsers never notice.** A clean Chrome session solves the challenge
   once, gets an `HttpOnly` attestation cookie, and sees zero friction.

## Poison the evidence chain

REA's own design principle is *evidence first*: findings carry identity,
confidence, authority and unknowns. That is exactly what makes it attackable —
an agent that records a wrong authentication model writes a wrong report.

`fightre/decoy.py` fabricates a plausible internal surface:

```
GET /openapi.json              -> a full OpenAPI 3.0 document (wrong on purpose)
GET /api/v2/internal/keys      -> RSA keys with a canary kid
GET /api/v2/internal/config    -> a database URL, feature flags, build id
POST /api/v2/admin/impersonate -> an admin session token (canary)
```

Every credential is a registered canary. If it is ever replayed to the service
(`data.canary_echo`) the client is hard-blocked; if it shows up in a leaked
dataset, `CanaryRegistry.find()` attributes it to the exact identity, path and
time. Decoy paths are not linked from anywhere, so a legitimate client cannot
reach them by accident.

## Audit your build before an agent does

Static analysis is the cheapest half of REA's pipeline. Most of what it needs is
usually shipped by accident:

```
$ fightre audit examples/leaky-dist
FightRE artifact audit - E:\fightrea\examples\leaky-dist
  exposure : 88.3/100 - an agent would reconstruct this service quickly
  files    : 5 (1.1 KiB)
  severity : critical=2  high=3  medium=1  low=1

  [CRITICAL] sourcemap              assets\app.js.map
             A source map reconstructs the original TypeScript/JS, comments included.
             fix: Delete *.map from the deployed artifact (build with sourcemaps off).
  [CRITICAL] private-key            deploy\signing.pem:1
  [HIGH    ] dotenv                 .env
  [HIGH    ] generic-secret         assets\app.js:5
  [HIGH    ] generic-secret         config.json:2
  [MEDIUM  ] sourcemap-reference    assets\app.js:17
  [LOW     ] internal-host          assets\app.js:4
```

Exit code is CI-friendly (`--fail-over 70`), output can be Markdown (`--markdown`)
or JSON (`--json`).

## Beyond the browser: native, runtime, tamper

Three more commands cover what the HTTP layer cannot see.

**`fightre native`** parses ELF, PE and Mach-O headers (no disassembly) and scores
what a static analyser gets for free:

```
$ fightre native ./dist
  binaries : 3 (skipped 12)
  score    : 83.2/100 (worst binary)

  binary              arch       strip  dwarf  pie  nx   relro  score
  ...\dist\app        x86-64     no     no     no   no   no     83.2
  ...\dist\libcore.so aarch64    yes    yes    yes  yes  yes    0.0
```

**`fightre selfcheck`** answers "is this process being instrumented?" — attached
tracer, Frida agent in `/proc/self/maps`, default Frida ports, library preload.
Failures become the same `client.*` signals the server already understands.

**`fightre manifest`** signs a path/size/SHA-256 inventory of a build and verifies
it later; modified, missing and added files are all reported. Ship the manifest,
verify at startup, and every untouched deployment can prove it.

Reference guards for **Android** (root, Frida, debugger, emulator, Xposed) and
**iOS** (jailbreak, `P_TRACED`, Frida, App Attest) live in
[`native/`](native/README.md), with the Play Integrity / App Attest interfaces
where the hardware root of trust actually is. The design rule is consistent:
client checks are advisory, the server enforces.

## One binary, many workers

`redis.enabled` swaps the in-memory nonce, rate-limit, canary and path-diversity
stores for Redis — through a built-in RESP client, so still zero dependencies.
Replay defence and canary attribution become cluster-wide; if Redis disappears,
each store falls back to its local twin and keeps serving.

```bash
$ fightre stores --config fightre.json
{"backend": "redis", "ok": true, "errors": 0}
```

## Install and integrate

```bash
pip install -e .          # Python 3.9+, no runtime dependencies
fightre keygen            # FIGHTRE_SECRET=...
```

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

**Browser**: serve `fightre/client/fightre.js` from your origin. It collects
environment signals, solves the SHA-256 proof-of-work (≈0.2–1 s) and posts a
signed attestation; the server replies with an `HttpOnly` cookie.

Full guide: [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) ·
[configuration reference](docs/DEPLOYMENT.md#3-configuration).

## How the score works

Each detector emits a named signal with a weight in `0..100`, read as
"probability this is not genuine". Independent evidence combines with noisy-OR:

```
score = max(0, 100 · (1 − Π(1 − wᵢ/100)) − trust)
```

- **bounded** — a pile of weak signals cannot silently become a block;
- **associative** — detectors run in any order, in parallel;
- **explainable** — every decision lists its signals, weights and layer:

```python
score=86.4 action=tarpit
  - L2-protocol proto.bot_user_agent +40 (marker 'headlesschrome')
  - L2-protocol proto.agent_runtime +50 (User-Agent contains 'playwright')
  - L4-app app.introspection_probe +34 (/openapi.json)
  - L3-client client.missing_attestation +16 (no attestation cookie)
```

Five bands map score to action — `allow`, `challenge` (429 + PoW), `deceive`
(200 synthetic), `tarpit` (200 synthetic, delayed), `block` (403, no detail) —
with two overrides:

- **hard block**: forged attestation, replayed signature, smuggling probe,
  unsigned edge fingerprint, canary echo. Decisive, immune to trust.
- **maze cap**: bait is never blocked. A blocked agent restarts; a deceived agent
  keeps spending budget and carries your canaries out into the world.

Bands, weights and both lists live in `fightre/presets/*.json`.

## Project layout

```
fightre/            the package (stdlib only)
  guard.py          request → verdict
  signals.py        51 signals across 5 layers
  scoring.py        noisy-OR + explanation
  policy.py         bands, hard blocks, maze rule
  headers.py        UA/client-hints, order, smuggling
  fingerprint.py    JA3/HTTP2 ingestion, edge HMAC
  agent_detect.py   REA toolchain markers
  challenge.py      PoW, nonce store
  attest.py         environment attestation
  signing.py        HMAC request signing
  decoy.py          honey-schema
  deception.py      synthetic payloads, tarpit
  canary.py         tokens + zero-width watermarks
  artifacts.py      build audit
  native.py         ELF/PE/Mach-O hygiene audit
  instrumentation.py debugger/Frida self-check
  manifest.py       signed build inventory
  stores.py         memory / Redis shared state
  redis.py          zero-dependency RESP2 client
  client/fightre.js browser attestation
native/             Android + iOS reference guards, mobile guide
demo/run_demo.py    live end-to-end scenarios
docs/               threat model, architecture, deployment, signals
tests/              145 unit tests
```

## Design principles

- **Zero dependencies.** One `pip install`, no supply chain, no build step.
- **Explainable or it does not ship.** Every action can be traced to named
  evidence; `fightre explain audit.jsonl` summarises real traffic.
- **Never punish a human.** Challenge before deceive, deceive before block;
  waivers and allow-lists exist for a reason.
- **Privacy by default.** Client identities are hashed with a daily salt; no
  headers or bodies are written to the audit log.
- **Assumes disclosure.** The source is public and every mechanism must survive
  an attacker reading it.

## Limits (read this before buying the pitch)

- A determined analyst with the binary and unlimited time will still win. FightRE
  raises cost and pollutes evidence; it is not DRM.
- Attestation proves *a browser-like runtime ran our JS*, not that a human is
  present. Treat its trust as a discount on suspicion.
- Signals are heuristics. Tune weights against your own traffic; expect false
  positives on unusual-but-legitimate clients (old browsers, corporate proxies,
  accessibility tooling).
- Rate limits, replay defence and canary attribution are per process unless
  `redis.enabled` is set; without shared state, multi-worker deployments need
  sticky sessions ([docs/DEPLOYMENT.md](docs/DEPLOYMENT.md#8-capacity-and-shared-state)).

## Roadmap

- ~~Redis-backed nonce/rate stores for multi-worker deployments~~ (0.2.0)
- ~~native artifact audit, instrumentation self-check, build manifests~~ (0.2.0)
- Rust/C++ runtime shim for native builds: in-process integrity checks and
  hardware-attestation plumbing for desktop apps.
- Per-session response polymorphism: every response carries a different
  watermark, so a single leaked record identifies the session, not just the tenant.
- Weight auto-tuning from audit logs (false-positive feedback loop).

## Responsible use

FightRE defends software you own or operate. It must not be used to interfere
with someone else's tools or forensic evidence, or to obstruct authorised
security research. See [SECURITY.md](SECURITY.md) and
[docs/THREAT-MODEL.md](docs/THREAT-MODEL.md).

## Documentation

- [REA explained](docs/REA.md) — the pipeline, its four capability jumps, the seams
- [Threat model](docs/THREAT-MODEL.md) — what REA can do, capability-by-capability
- [Architecture](docs/ARCHITECTURE.md) — pipeline, scoring, state, extension points
- [Deployment](docs/DEPLOYMENT.md) — frameworks, edge fingerprints, rollout plan
- [Signal catalogue](docs/SIGNALS.md) — all 51 signals, generated from code
- [FAQ](docs/FAQ.md) — DRM, legality, false positives, licensing
- [Native & mobile](native/README.md) — binary audit, self-check, Android/iOS guards

## License

Apache-2.0 — see [LICENSE](LICENSE) and [NOTICE](NOTICE).

We chose Apache-2.0 over MIT for a practical reason: it carries an explicit
patent grant and a patent-retaliation clause. A security component that companies
embed in production should not leave patent risk ambiguous, and the trademark
clause stops the name from being used to endorse a fork.

---

[中文说明](README.zh-CN.md)
