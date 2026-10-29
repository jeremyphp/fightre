# REA, explained — and what FightRE does about it

> Background for anyone who found this repository after seeing REA on GitHub
> Trending: what the tool actually is, why it works, where its leverage comes
> from, and which parts of it are attackable.

## TL;DR

REA is not a new disassembler. It is an **orchestration layer** that lets an LLM
drive a complete reverse-engineering toolchain (Ghidra, IDA, Frida, JADX,
Playwright, mitmproxy, tshark, binwalk) through the Model Context Protocol, and
records every observation as structured *evidence* with confidence and
provenance.

That combination changes the economics of reverse engineering in three ways:

1. **Expertise is no longer the bottleneck.** You describe the goal; the agent
   picks the tools.
2. **Coverage is no longer the bottleneck.** The agent can afford to inspect
   every function, every route, every string.
3. **The output is semantic.** It does not hand you x86; it hands you a report
   that says "this is how the clipboard bridge works", with citations.

FightRE cannot make code unreadable. It attacks the three things this pipeline
depends on: **cost per verified fact**, **consistency of the evidence**, and
**provenance of anything extracted**. That is what the layers in this repository
implement.

## 1. What happened

REA ("Reverse Engineer Anything") appeared in October 2026 and reached roughly
70–80k GitHub stars within three days, topping GitHub Trending. A Python port
(`rea-mcp`) shipped the same tool surface as an MCP server with ~169 tools and
153 CLI commands. The important properties for defenders:

- **It runs locally.** Analysis happens on the operator's machine; the target is
  never uploaded. There is no cloud-side point where you could detect it.
- **It is tool-agnostic.** Built-in static providers handle ELF/PE/Mach-O, Go,
  Rust, .NET, APK, WASM, SQLite, Electron/ASAR, HAR/PCAP; external engines
  (IDA, Ghidra, Hopper, JEB, Kuna, Frida, Playwright, CDP, tshark, binwalk) are
  attached when present.
- **It is evidence-first.** Every result carries identity, confidence,
  authority, limitations and unresolved unknowns, and the agent keeps an
  obligation ledger of what still needs proof.

## 2. How the pipeline works

```
┌──────────────┐   MCP (stdio/HTTP)   ┌──────────────────┐   adapters   ┌─────────────────────┐
│  LLM agent   │ ◀──────────────────▶ │  REA MCP server  │ ◀──────────▶ │ static providers     │
│ Claude Code  │                      │  tool catalogue  │              │ IDA / Ghidra / JEB   │
│ Cursor/Codex │                      │  evidence store  │              │ Frida / Playwright   │
│ OpenCode     │                      │  snapshot cache  │              │ mitmproxy / tshark   │
└──────────────┘                      └──────────────────┘              └─────────────────────┘
        │                                     │
        │  "how does the clipboard bridge     │  observations, derivations,
        │   work?"                            │  inferences + unknowns
        ▼                                     ▼
   reconstructed source + a report with citations and confidence
```

The loop is: **triage → inventory → decompile → trace → correlate → reconstruct**.
Each step narrows uncertainty; the ledger records what is proven and what is
still a guess.

## 3. Why this is different from classic reverse engineering

Classic RE has three costs: expertise, time, and bookkeeping. Automation attacked
time; LLMs attack expertise and bookkeeping simultaneously. The practical
consequences:

| Old assumption | Under REA |
| --- | --- |
| "The binary is stripped, so it is hard." | Symbols help, but the agent reads structure and strings and writes its own names. |
| "The client logic is obfuscated." | Obfuscation raises tokens, not comprehension; the model still summarises behaviour. |
| "Anti-debugging stops analysis." | The static path never runs the binary; anti-debug only matters for dynamic steps. |
| "A human must connect the findings." | The agent produces the narrative, with evidence IDs. |
| "Detection requires seeing the tool." | It runs on the attacker's machine; nothing crosses your network. |

## 4. The four capability jumps

1. **Tool selection.** The MCP catalogue is discoverable; the model picks the
   right engine for the file type without a human deciding.
2. **Breadth.** Per-function analysis is cheap enough to run everywhere, so
   nothing is skipped for being boring.
3. **Semantic compression.** Raw output is summarised into claims a human (or
   another agent) can act on; the evidence stays attached.
4. **Reproducibility.** Snapshots and evidence export mean a second run does not
   start from zero, and findings are portable between sessions.

## 5. Where the seams are

If you accept that the code will eventually be read, the defensible surface
shrinks to four things:

| Seam | Why it matters | What can be done |
| --- | --- | --- |
| **Cost per verified fact** | Every fact costs tokens, time and tool calls | proof-of-work, quotas, tarpits, rate limits |
| **Evidence consistency** | The agent trusts what it observes | fabricated schemas, decoy endpoints, contradictory decoys |
| **Provenance** | Extracted data travels | canary tokens, watermarking, attribution |
| **Server-side truth** | What never ships cannot be reversed | move logic and secrets behind an attested session |

## 6. What FightRE does, stage by stage

| REA stage | What the agent wants | FightRE response |
| --- | --- | --- |
| Static triage of your build | symbols, DWARF/PDB, source maps, secrets | `fightre audit` + `fightre native` remove and score that material |
| Client reconstruction | readable bundles and logic | PoW + attestation gate the valuable flows; server keeps the truth |
| Dynamic instrumentation | Frida/CDP attach, hooks | `fightre selfcheck`, Android/iOS guards, attestation signals |
| Network capture | clean HTTP conversation | request signing, nonce replay defence, edge-signed fingerprints |
| API discovery | `openapi.json`, GraphQL schema | honey-schema: a complete, wrong API document; every credential is a canary |
| Data extraction | bulk reads | quotas, sequence detection, synthetic records with watermarks |
| Reconstruction & reuse | consistent evidence | decoys contradict the real model; canary reuse hard-blocks the session |

The design rule that ties it together: **client-side checks are advisory, the
server decides.** A patched client can lie about `navigator.webdriver`; it cannot
forge an HMAC it never received, and it cannot un-leak a canary.

## 7. Red-team checklist

Use this to evaluate a deployment, not just FightRE:

- [ ] Can an unauthenticated client fetch a schema or docs that describe the real API?
- [ ] Can a captured request be replayed after 5 minutes? After a day?
- [ ] Can a headless browser reach the valuable endpoint with default settings?
- [ ] Does a scanner learn it was detected (403) or keep consuming plausible data?
- [ ] If one record leaks, can you name the session and the time?
- [ ] Does a stripped, PIE, NX build leave any symbol or PDB path behind?
- [ ] Does the server still enforce limits if the client ignores them?
- [ ] Can a support engineer explain any block from the audit log alone?

## 8. What this project deliberately does not do

- It does not attack the analyst's machine, install rootkits, wipe logs, or
  interfere with forensic evidence.
- It does not promise DRM. A determined analyst with the binary and time wins.
- It does not rely on secrecy: the whole implementation is public, and every
  mechanism is expected to survive disclosure.

## References

- REA upstream: <https://github.com/morluto/rea>
- Python port and tool inventory: <https://pypi.org/project/rea-mcp/>
- Coverage of the launch: <https://eu.36kr.com/zh/p/4020977643671686>
