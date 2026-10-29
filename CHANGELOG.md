# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
