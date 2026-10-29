# Threat model: what REA can do, and what FightRE can do about it

## 1. What changed in 2026

REA ("Reverse Engineer Anything") turned reverse engineering from a specialist
craft into an agent workflow. The public toolchain is an MCP server that exposes
roughly 170 tools over static analysers (Ghidra, IDA, Hopper, JEB, Rizin),
decompilers (JADX, apktool, ILSpy), dynamic instrumentation (Frida, GDB, CDP),
browser automation (Playwright), traffic capture (mitmproxy, tshark, HAR) and a
reconstruction layer that writes an obligation ledger of what still needs proof.

Two properties matter for defence:

1. **It is local-first.** REA analyses samples on the operator's machine and
   never uploads the target. A cloud-side "is this being reverse engineered?"
   detector cannot see it; any defence must live inside the artifact, the
   protocol, the service and the data.
2. **It is evidence-driven.** Every finding carries identity, confidence,
   authority and unresolved unknowns. The agent is only as good as the evidence
   it can collect. This is the exploitable seam: *poison the evidence and the
   reconstruction is confidently wrong.*

## 2. Attacker capabilities

| Capability | Typical tooling | What it gets |
| --- | --- | --- |
| Static inspection | Ghidra, IDA, Rizin, `strings`, APK/ASAR unpacking | algorithms, hardcoded keys, endpoints, feature flags |
| Decompilation | JADX, ILSpy, hex-rays | near-source logic of client code |
| Dynamic instrumentation | Frida, gdb, CDP, Xposed | runtime values, decrypted payloads, function hooks |
| Network capture | mitmproxy, tshark, HAR | full API conversation, auth flows, replayable requests |
| Browser automation | Playwright, headless Chrome | DOM, JS bundles, screenshots, scripted flows |
| Schema discovery | OpenAPI/Swagger, GraphQL introspection | the complete API model in one request |
| Reconstruction | REA evidence ledger + LLM | a plausible open reimplementation and a report |

## 3. What defence can and cannot achieve

FightRE is explicit about this, because overselling it is how security products
lose trust:

- **Can**: raise the cost per unit of extracted knowledge, make automation
  misattribute or contradict itself, make leaks attributable, and remove the
  free material (source maps, symbols, committed secrets) that agents harvest in
  minutes.
- **Cannot**: make a binary that runs on someone else's machine unreadable. With
  unrestricted local access and unlimited time, a determined analyst wins. Any
  product claiming otherwise is selling DRM, not security.
- **Therefore**: the highest-leverage controls are *architectural* -- keep the
  secret logic server-side, keep secrets out of the client, make the client
  useless without a live, attested, rate-limited session.

## 4. Capability → layer mapping

| REA capability | FightRE layer | Mechanism | Residual risk |
| --- | --- | --- | --- |
| Static harvesting of builds | L0 artifact + native audit | `fightre audit` and `fightre native` flag maps, symbols, DWARF/PDB, secrets, schemas, internal hosts | An analyst can still read minified code and stripped assembly |
| Tampered install (patched binary) | L0 manifest | signed path/size/SHA-256 inventory; modified, missing and added files detected | The verifier itself can be patched |
| Desktop/mobile process instrumentation | L3 runtime | `fightre selfcheck` and the Android/iOS guards detect tracers, Frida agents, preloads, root/jailbreak | Stealth tooling hides its traces |
| Client logic reconstruction | L3 client + L4 app | attestation, PoW cost, server-side gating, per-session data | Hooks can fake env signals |
| Frida / debugger attachment | L3 client | `webdriver`, CDP artefacts, native-function integrity, consistency checks | Stealth tooling hides its traces |
| mitmproxy / HAR capture | L2 protocol + L4 app | TLS pinning guidance, request signing, nonce replay defence, short-lived attestation | Rooted device can bypass pinning |
| Browser automation | L2 + L3 | headless markers, missing fetch metadata, header order, PoW challenge | Stealth browsers exist; treat as friction |
| Schema discovery | L4 app | introspection detection + fabricated `openapi.json` | Agent may cross-check inconsistencies |
| API scraping at scale | L1 + L4 | rate budgets, path-diversity detection, quotas | Distributed scraping needs edge cooperation |
| Leak / resale of data | L5 data | canary tokens, zero-width watermarks, attribution registry | Watermarks can be stripped if looked for |
| Evidence compilation | all | contradictory synthetic evidence, canaries that fire on reuse | Sophisticated agents may flag contradictions |

## 5. Trust boundaries

```
[ client device ] --TLS--> [ edge ] --HTTP--> [ FightRE ] --> [ app ] --> [ data ]
      untrusted              semi-trusted        trust anchor
```

- The client is hostile by default. Everything it sends may be forged.
- The edge is trusted only when it signs fingerprint headers with a shared
  secret (`X-FightRE-Edge-Sig`). Unsigned fingerprint headers are themselves a
  signal (`proto.edge_signature_invalid`, hard block).
- The application is trusted. FightRE never calls upstream services to validate
  a client; it decides from what it observed plus its own HMAC state.
- Persistent state (nonce stores, canaries, rate buckets) is per process. A
  multi-worker deployment needs sticky routing or a shared store; see
  `docs/DEPLOYMENT.md`.

## 6. Assumptions

1. TLS terminates before the application (FightRE does not parse ClientHello).
2. The operator can configure a shared secret and a real clock; attestation and
   signatures are time-bounded.
3. Attackers can read this repository. Security by obscurity is not a control
   here -- every mechanism must survive disclosure. That is why weights, bands
   and thresholds are configurable and documented.
4. Traffic is HTTP/JSON-ish. Binary protocols need their own adapters.

## 7. Non-goals and prohibited uses

FightRE is a defensive component for software you own or operate. It does not:

- inject code into, or tamper with, another party's software or analysis tools;
- delete logs, disable EDR, or otherwise interfere with forensic evidence;
- fingerprint or track end users beyond the request lifecycle (identities are
  hashed with a daily salt and never stored raw by default);
- "protect" content you have no right to license.

Using it to obstruct legitimate security research, incident response, or
interoperability testing is out of scope and contrary to the project's intent.
See `SECURITY.md` and the responsible-use section of the README.

## 8. References

- REA upstream: <https://github.com/morluto/rea>
- REA Python port and tool inventory: <https://pypi.org/project/rea-mcp/>
- Background coverage: <https://eu.36kr.com/zh/p/4020977643671686>
