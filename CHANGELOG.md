# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-10-29

### Added

- **Shared state for multi-worker deployments**: a zero-dependency RESP2 client
  (`fightre/redis.py`) and Redis-backed nonce, rate-limit, canary and
  path-diversity stores (`fightre/stores.py`). Every store degrades to its local
  twin when the server is unreachable, and counts the failure.
- **Native binary audit** (`fightre native`): parses ELF, PE and Mach-O headers
  and reports symbol tables, DWARF/PDB leakage, missing PIE/NX/RELRO/CFG, with a
  per-binary exposure score.
- **Runtime self-check** (`fightre selfcheck`): detects attached debuggers
  (`TracerPid`, `sys.gettrace`), Frida agents in process maps and default ports,
  and library preload hijacks. Failures map to the same signal catalogue.
- **Signed build manifests** (`fightre manifest sign|verify`): tamper detection
  for distributed builds (modified, missing, added files).
- **Android and iOS reference guards** (`native/android`, `native/ios`) with
  root/jailbreak, Frida, debugger, emulator and hook-framework checks, plus
  Play Integrity / App Attest interfaces.
- New client signals: `client.debugger_attached`,
  `client.instrumentation_detected`, `client.preload_hijack`,
  `client.root_or_jailbreak`.
- `fightre stores` connectivity command; `--json`/`--markdown` output for native
  audit; `manifest verify` exits non-zero on tamper.
- 43 new tests (145 total), including an in-process fake Redis server.

### Changed

- Project license is now **Apache-2.0** (patent grant, patent retaliation and
  trademark clauses) instead of MIT; see `LICENSE` and `NOTICE`.
- `Guard` now accepts a `Stores` bundle; challenges and request signatures share
  the same configured nonce backend.
- WSGI keeps `raw_pairs` empty (no header order available), so L2 ordering never
  fires there by accident.

## [0.1.0] - 2026-10-29

### Added

- Five-layer request guard: network rate/path diversity, protocol header and
  fingerprint analysis, client attestation, application signing/honeypots,
  data canaries.
- Proof-of-work challenge and per-challenge HMAC attestation
  (`/_fightre/challenge`, `/_fightre/attest`).
- Explainable noisy-OR risk scoring with weighted, layered signals.
- Policy bands (`allow`, `challenge`, `deceive`, `tarpit`, `block`) with
  hard-block overrides and a "never block the bait" maze rule.
- Honey-schema: a fabricated OpenAPI document and decoy endpoints that poison
  agent-collected evidence and issue canary tokens.
- Canary registry and zero-width watermarking for leak attribution.
- HMAC request signing with clock-skew and replay defence.
- Edge fingerprint ingestion (JA3 and HTTP/2) with HMAC-signed edge headers.
- Tarpit with bounded delay and synthetic JSON payloads.
- JSONL audit trail with daily-salted identity hashing and a `fightre explain`
  summariser.
- Artifact audit (`fightre audit`) for REA exposure: source maps, debug symbols,
  committed secrets, published schemas, internal hosts.
- Browser client (`fightre/client/fightre.js`): environment collection,
  synchronous SHA-256 proof-of-work, attestation.
- ASGI and WSGI middleware, demo service, end-to-end demo script, 102 unit
  tests, CI workflow.

[0.1.0]: https://github.com/your-org/fightre/releases/tag/v0.1.0
