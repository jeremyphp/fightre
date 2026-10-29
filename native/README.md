# Native and mobile companion

The web guard in `fightre/` protects a service. This directory covers the two
places it cannot reach:

- **your own binaries** — what static analysis gets for free (`fightre native`)
- **your own app process** — whether it is being instrumented right now
  (`fightre/selfcheck`, plus the Android/iOS reference guards in this folder)

And one thing that makes both stronger: a signed inventory of what you shipped
(`fightre manifest`), so a modified file is detectable.

## 1. Binary hygiene — `fightre native`

```bash
$ fightre native ./dist
binary              arch     strip  dwarf   pie    nx     relro  score
./dist/app          x86-64   no     no      no     no     no     83.2
./dist/libcore.so   aarch64  yes    yes     yes    yes    yes     0.0
```

It parses ELF, PE and Mach-O headers directly (no disassembly) and reports:

| finding | why it matters for REA |
| --- | --- |
| `symbol-table` | function names without any analysis work |
| `debug-info` | variable names, types, source line numbers |
| `dwarf-leak` (Mach-O `__DWARF`) | source-level reconstruction |
| `pdb-path` (PE) | build machine paths, symbol server hints |
| `no-nx` / `no-pie` / `no-relro` / `no-cfg` | cheaper exploitation and patching |

Fix commands are printed with every finding. `--json` and `--markdown` exist for
CI (`--fail-over 60`).

## 2. Runtime self-check — `fightre selfcheck`

```bash
$ fightre selfcheck
  PASS  tracer           no tracer attached
  PASS  frida-maps       no instrumentation agent in process maps
  PASS  preload          no library preload variables set
  FAIL  frida-port       Frida default port open: 27042
  PASS  python-trace     no Python trace function installed
```

Run it at startup in desktop or on-prem builds. `fightre.instrumentation.to_signals()`
converts failures into the same signal catalogue the server uses, so a desktop
app can feed them into `RiskEngine` and degrade gracefully (disable export,
require re-auth, refuse to decrypt) instead of crashing.

What it does **not** do: scan other processes, patch memory, or hide anything.
It only reads its own process state.

## 3. Build manifest — `fightre manifest`

```bash
fightre manifest sign ./dist --key-id release-2026 --out dist/build.manifest.json
fightre manifest verify dist/build.manifest.json --root ./dist
```

The manifest is an HMAC-signed inventory (path, size, SHA-256). Ship it next to
the build; verify at startup. It detects modified, missing and added files. The
verifier itself can be patched by a determined attacker — the point is that they
must now patch two things, and that every unmodified deployment can prove it.

## 4. Android reference guard

`native/android/FightREGuard.kt` implements, as plain Kotlin with no
dependencies:

- root indicators (su paths, Magisk/SuperSU packages, `test-keys`)
- Frida (default ports, agent in `/proc/self/maps`, `frida-server` process)
- debugger (`Debug.isDebuggerConnected`, `waitForDebugger`)
- emulator heuristics (build props, sensors, CPU ABI)
- hook frameworks (Xposed/LSPosed/Substrate packages)
- a slot for **Play Integrity** — the only check that is not client-side

It returns the same signal names and weights as the server catalogue, so the
client can sign them into an attestation payload and the server can make the
decision. That split is deliberate: **client checks are advisory, the server
enforces.**

## 5. iOS reference guard

`native/ios/FightREGuard.swift` covers jailbreak indicators (paths, URL schemes,
sandbox escape probes), `P_TRACED` debugger detection, Frida port probing, and an
`App Attest` interface (`DCAppAttestService`, iOS 14+). App Attest is the
equivalent of Play Integrity: a hardware-backed statement that the request came
from an unmodified build of your app on genuine Apple hardware.

## 6. What hardware attestation changes

Everything above is client-side and therefore patchable. Play Integrity and App
Attest move the anchor into the platform:

1. the client asks the platform for an attestation bound to a server nonce;
2. the server verifies the signature chain and the nonce;
3. only then does the server grant a session that can decrypt valuable data.

FightRE deliberately does not bundle a vendor SDK. The reference guards expose a
single interface — `attest(nonce): String?` — and the server side is your
existing verification endpoint. That keeps the package dependency-free and lets
you choose the vendor.

## 7. Honest limits

- Client checks raise cost; a stealth build will defeat most of them.
- Root/jailbreak detection has false positives on developer devices, custom
  ROMs and accessibility setups. Use it to *reduce trust*, never as a hard
  account ban.
- Symbol stripping is not obfuscation. It removes free information; it does not
  make the code unreadable.
- Use these checks only on devices and software you are authorised to examine.
