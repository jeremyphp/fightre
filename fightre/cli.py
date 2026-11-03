"""FightRE command line interface.

    fightre serve    # run the guarded demo service
    fightre audit    # inspect a build artifact the way an agent would
    fightre signals  # list the signal catalogue
    fightre selftest # verify the crypto/scoring primitives
    fightre keygen   # generate a production secret
    fightre explain  # summarise an audit log
"""

from __future__ import annotations

import argparse
import json
import os
import secrets
import sys
from typing import Dict, List, Optional

from . import __version__, artifacts
from . import signals as signal_lib
from .config import Config
from .guard import Guard


# --------------------------------------------------------------------------
# serve
# --------------------------------------------------------------------------
def cmd_serve(args: argparse.Namespace) -> int:
    from wsgiref.simple_server import make_server

    from .demoapp import demo_app
    from .wsgi import FightREWSGIMiddleware

    config = Config.load(args.config)
    guard = Guard(config)
    app = FightREWSGIMiddleware(demo_app, config, guard=guard)
    httpd = make_server(args.host, args.port, app)

    secret_state = "ephemeral (dev only)" if config.ephemeral_secret else "configured"
    print(f"FightRE {__version__} demo on http://{args.host}:{httpd.server_port}")
    print(f"  secret     : {secret_state}")
    print(f"  poison     : {config.poison_enabled}")
    print(f"  bands      : {json.dumps(guard.policy.bands)}")
    print("  endpoints  : /  /api/v1/items  /admin/users  /openapi.json")
    print("  internal   : /_fightre/challenge  /_fightre/attest")
    print("Ctrl+C to stop.")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped")
    finally:
        httpd.server_close()
    return 0


# --------------------------------------------------------------------------
# audit
# --------------------------------------------------------------------------
def cmd_audit(args: argparse.Namespace) -> int:
    try:
        report = artifacts.audit(args.path, max_files=args.max_files)
    except NotADirectoryError:
        print(f"not a directory: {args.path}", file=sys.stderr)
        return 2

    if args.markdown:
        target = args.out or "fightre-audit.md"
        with open(target, "w", encoding="utf-8") as fh:
            fh.write(report.to_markdown())
        print(f"markdown report written to {target}")

    if args.json:
        print(report.to_json())
    elif not args.markdown or not args.quiet:
        counts = report.by_severity
        print(f"FightRE artifact audit - {report.root}")
        print(f"  exposure : {report.score}/100 - {report.verdict}")
        print(f"  files    : {report.files_scanned} ({report.bytes_scanned / 1024:.1f} KiB)")
        print(
            "  severity : "
            + "  ".join(f"{k}={counts.get(k, 0)}" for k in artifacts.SEVERITY_ORDER)
        )
        if report.findings:
            print()
            for finding in report.findings[: args.limit]:
                location = finding.path + (f":{finding.line}" if finding.line else "")
                print(f"  [{finding.severity.upper():8}] {finding.rule:22} {location}")
                print(f"             {finding.detail}")
                print(f"             fix: {finding.fix}")
            if len(report.findings) > args.limit:
                print(f"  ... {len(report.findings) - args.limit} more (use --limit 0 for all)")
        else:
            print("\n  no findings - nothing here reads like free source code.")

    return 1 if report.score >= args.fail_over else 0


# --------------------------------------------------------------------------
# signals
# --------------------------------------------------------------------------
def cmd_signals(args: argparse.Namespace) -> int:
    rows = signal_lib.describe()
    if args.markdown:
        print("| signal | layer | weight | hard-block | description |")
        print("| --- | --- | --- | --- | --- |")
        for row in rows:
            hard = "yes" if row["critical"] else ""
            print(
                f"| `{row['name']}` | {row['layer']} | {row['weight']} | {hard} | "
                f"{row['description']} |"
            )
        return 0
    if args.json:
        print(json.dumps(rows, indent=2, ensure_ascii=False))
        return 0
    current = ""
    for row in rows:
        layer = str(row["layer"])
        if layer != current:
            current = layer
            print(f"\n{layer}")
        flag = "  [critical]" if row["critical"] else ""
        print(f"  {str(row['name']):30} {row['weight']:>5}{flag}")
        if args.verbose:
            print(f"      {row['description']}")
    print(f"\n{len(rows)} signals")
    return 0


# --------------------------------------------------------------------------
# selftest
# --------------------------------------------------------------------------
def cmd_selftest(_args: argparse.Namespace) -> int:
    from . import signals as sig
    from .attest import AttestationVerifier
    from .canary import CanaryRegistry, embed, extract
    from .challenge import ChallengeIssuer, pow_matches, solve_pow
    from .policy import Action, Policy
    from .scoring import RiskEngine

    checks: List[str] = []
    failures: List[str] = []

    def check(name: str, condition: bool) -> None:
        (checks if condition else failures).append(name)
        print(f"  {'PASS' if condition else 'FAIL'}  {name}")

    issuer = ChallengeIssuer("selftest-secret", ttl_seconds=60, difficulty=12)
    challenge = issuer.issue("selftest")
    nonce = solve_pow(challenge["jti"], challenge["difficulty"])
    check("proof-of-work solves", nonce is not None and pow_matches(challenge["jti"], nonce, 12))
    parsed = issuer.verify(challenge["token"])
    check("challenge verifies", parsed is not None and parsed.jti == challenge["jti"])
    ok, reason = issuer.check_solution(parsed, nonce)
    check("challenge accepts solution", ok and reason == "ok")
    replay_ok, _ = issuer.check_solution(parsed, nonce)
    check("challenge rejects replay", not replay_ok)

    verifier = AttestationVerifier("selftest-secret", ttl_seconds=60, trust=30)
    blob = verifier.build(challenge["jti"], {"ua": "Mozilla/5.0 Chrome/131", "webgl_renderer": "ANGLE"})
    result = verifier.verify(blob)
    check("attestation verifies", result.ok and result.trust == 30)
    forged = verifier.verify(blob[:-4] + "AAAA")
    check("attestation rejects tampering", not forged.ok)

    engine = RiskEngine()
    report = engine.score([sig.make("proto.bot_user_agent")])
    check("scoring is noisy-OR", abs(report.score - 40.0) < 0.01)
    combined = engine.score([sig.make("proto.bot_user_agent"), sig.make("client.headless_ua")])
    check("independent evidence compounds", 65.0 < combined.score < 70.0)

    policy = Policy()
    hard = engine.score([sig.make("app.replay_detected")])
    check("hard block overrides trust", policy.decide(hard).action is Action.BLOCK)

    registry = CanaryRegistry()
    canary = registry.issue("test-owner")
    check("canary round-trips", registry.find(f"id={canary.token}")[0].owner == "test-owner")
    marked = embed("hello", "tenant-7")
    check("watermark survives copy", extract(marked) == "tenant-7")

    print(f"\n{len(checks)} passed, {len(failures)} failed")
    return 0 if not failures else 1


# --------------------------------------------------------------------------
# keygen
# --------------------------------------------------------------------------
def cmd_keygen(_args: argparse.Namespace) -> int:
    secret = secrets.token_urlsafe(36)
    print("FIGHTRE_SECRET=" + secret)
    print()
    print("Put it in the environment, or in your config:")
    print(json.dumps({"security": {"secret": secret}}, indent=2))
    return 0


# --------------------------------------------------------------------------
# native
# --------------------------------------------------------------------------
def cmd_native(args: argparse.Namespace) -> int:
    from . import native

    report = native.audit_paths(args.paths, max_files=args.max_files)
    if args.markdown:
        target = args.out or "fightre-native.md"
        with open(target, "w", encoding="utf-8") as handle:
            handle.write(report.to_markdown())
        print(f"markdown report written to {target}")
    if args.json:
        print(json.dumps(report.as_dict(), indent=2, ensure_ascii=False))
    else:
        print(f"FightRE native audit - {report.root}")
        print(f"  binaries : {len(report.binaries)} (skipped {report.skipped})")
        print(f"  score    : {report.score}/100 (worst binary)")
        if report.binaries:
            print()
            print(f"  {'binary':<34} {'arch':<10} {'strip':<6} {'dwarf':<6} {'pie':<4} {'nx':<4} {'relro':<6} score")
            for binary in report.binaries:
                h = binary.hardening
                label = binary.path if len(binary.path) <= 34 else "..." + binary.path[-31:]
                print(
                    f"  {label:<34} {binary.arch:<10} "
                    f"{_flag(h.get('symbols_stripped')):<6} {_flag(h.get('debug_info_removed')):<6} "
                    f"{_flag(h.get('pie')):<4} {_flag(h.get('nx')):<4} "
                    f"{_flag(h.get('relro')):<6} {binary.score}"
                )
            for binary in report.binaries:
                for finding in binary.findings:
                    print(f"\n  [{finding.severity.upper():8}] {finding.rule:14} {binary.path}")
                    print(f"             {finding.detail}")
                    print(f"             fix: {finding.fix}")
    return 1 if report.score >= args.fail_over else 0


def _flag(value: object) -> str:
    if value is None:
        return "?"
    return "yes" if value else "no"


# --------------------------------------------------------------------------
# selfcheck
# --------------------------------------------------------------------------
def cmd_selfcheck(args: argparse.Namespace) -> int:
    from . import instrumentation

    checks = instrumentation.collect(probe_ports=not args.no_ports)
    summary = instrumentation.summarize(checks)
    if args.json:
        print(json.dumps({"summary": summary, "checks": [c.as_dict() for c in checks]}, indent=2))
    else:
        for check in checks:
            print(f"  {'PASS' if check.ok else 'FAIL'}  {check.name:20} {check.detail}")
        print()
        print("clean" if summary["clean"] else f"{len(summary['failed'])} check(s) failed")
    if args.strict and not summary["clean"]:
        return 1
    return 0


# --------------------------------------------------------------------------
# manifest
# --------------------------------------------------------------------------
def cmd_manifest(args: argparse.Namespace) -> int:
    from . import manifest as mf

    secret = args.secret or os.environ.get("FIGHTRE_MANIFEST_SECRET", "")
    if not secret:
        print("error: pass --secret or set FIGHTRE_MANIFEST_SECRET", file=sys.stderr)
        return 2

    if args.action == "sign":
        built = mf.build_manifest(args.target)
        mf.sign(built, args.key_id, secret)
        target = args.out or os.path.join(args.target, "build.manifest.json")
        built.save(target)
        print(f"signed {len(built.entries)} entries -> {target}")
        return 0

    result = mf.verify_file(args.target, root=args.root, secret=secret)
    print(json.dumps(result.as_dict(), indent=2))
    return 0 if result.ok else 1


# --------------------------------------------------------------------------
# stores
# --------------------------------------------------------------------------
def cmd_stores(args: argparse.Namespace) -> int:
    from .stores import build_stores

    config = Config.load(args.config)
    stores = build_stores(config, config.resolve_secret())
    health = stores.health()
    print(json.dumps(health, indent=2))
    return 0 if health.get("ok") else 1


# --------------------------------------------------------------------------
# edge-sign
# --------------------------------------------------------------------------
def cmd_edge_sign(args: argparse.Namespace) -> int:
    """Sign the fingerprint headers an edge would inject (for testing)."""
    import time as _time

    from .fingerprint import edge_signature

    ts = args.ts or str(int(_time.time()))
    signature = edge_signature(args.secret, ts, args.ja3, args.h2, args.ip)
    print(json.dumps({"X-FightRE-Edge-Ts": ts, "X-FightRE-Edge-Sig": signature}, indent=2))
    return 0


# --------------------------------------------------------------------------
# explain
# --------------------------------------------------------------------------
def cmd_explain(args: argparse.Namespace) -> int:
    if not os.path.exists(args.path):
        print(f"no such file: {args.path}", file=sys.stderr)
        return 2
    actions: Dict[str, int] = {}
    signals: Dict[str, int] = {}
    total = 0
    tail: List[dict] = []
    with open(args.path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except ValueError:
                continue
            total += 1
            actions[event.get("action", "?")] = actions.get(event.get("action", "?"), 0) + 1
            for name in event.get("signals", []):
                signals[name] = signals.get(name, 0) + 1
            tail.append(event)
            if len(tail) > args.limit:
                tail.pop(0)

    print(f"events: {total}")
    print("by action: " + ", ".join(f"{k}={v}" for k, v in sorted(actions.items())))
    top = sorted(signals.items(), key=lambda kv: -kv[1])[:10]
    if top:
        print("top signals:")
        for name, count in top:
            print(f"  {count:>5}  {name}")
    if tail and args.verbose:
        print("\nrecent:")
        for event in tail:
            print(
                f"  {event.get('action'):9} score={event.get('score'):>6} "
                f"{event.get('method')} {event.get('path')}"
            )
    return 0


# --------------------------------------------------------------------------
# parser
# --------------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="fightre",
        description="Five-layer anti-reverse-engineering defence for web services.",
    )
    parser.add_argument("-V", "--version", action="version", version=f"FightRE {__version__}")
    sub = parser.add_subparsers(dest="command")

    serve = sub.add_parser("serve", help="run the guarded demo service")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8080)
    serve.add_argument("--config", default=None, help="path to a JSON config")
    serve.set_defaults(func=cmd_serve)

    audit = sub.add_parser("audit", help="audit a build artifact for RE exposure")
    audit.add_argument("path")
    audit.add_argument("--json", action="store_true")
    audit.add_argument("--markdown", action="store_true")
    audit.add_argument("--out", default=None)
    audit.add_argument("--quiet", action="store_true")
    audit.add_argument("--limit", type=int, default=20)
    audit.add_argument("--max-files", type=int, default=20_000)
    audit.add_argument("--fail-over", type=float, default=100.0,
                       help="exit non-zero when the score reaches this value")
    audit.set_defaults(func=cmd_audit)

    native_p = sub.add_parser("native", help="audit ELF/PE/Mach-O hardening and symbols")
    native_p.add_argument("paths", nargs="+")
    native_p.add_argument("--json", action="store_true")
    native_p.add_argument("--markdown", action="store_true")
    native_p.add_argument("--out", default=None)
    native_p.add_argument("--max-files", type=int, default=20_000)
    native_p.add_argument("--fail-over", type=float, default=100.0)
    native_p.set_defaults(func=cmd_native)

    selfcheck = sub.add_parser("selfcheck", help="check this process for debuggers/instrumentation")
    selfcheck.add_argument("--json", action="store_true")
    selfcheck.add_argument("--strict", action="store_true")
    selfcheck.add_argument("--no-ports", action="store_true")
    selfcheck.set_defaults(func=cmd_selfcheck)

    man = sub.add_parser("manifest", help="sign or verify a build manifest")
    man.add_argument("action", choices=["sign", "verify"])
    man.add_argument("target", help="directory to sign, or manifest file to verify")
    man.add_argument("--key-id", default="release")
    man.add_argument("--secret", default="")
    man.add_argument("--out", default=None)
    man.add_argument("--root", default=None)
    man.set_defaults(func=cmd_manifest)

    stores = sub.add_parser("stores", help="check the shared-state backend")
    stores.add_argument("--config", default=None)
    stores.set_defaults(func=cmd_stores)

    sig = sub.add_parser("signals", help="list the signal catalogue")
    sig.add_argument("--json", action="store_true")
    sig.add_argument("--markdown", action="store_true")
    sig.add_argument("-v", "--verbose", action="store_true")
    sig.set_defaults(func=cmd_signals)

    selftest = sub.add_parser("selftest", help="verify crypto and scoring primitives")
    selftest.set_defaults(func=cmd_selftest)

    keygen = sub.add_parser("keygen", help="generate a production secret")
    keygen.set_defaults(func=cmd_keygen)

    edge = sub.add_parser("edge-sign", help="sign edge fingerprint headers (testing)")
    edge.add_argument("--secret", required=True)
    edge.add_argument("--ja3", default="")
    edge.add_argument("--h2", default="")
    edge.add_argument("--ip", required=True)
    edge.add_argument("--ts", default="")
    edge.set_defaults(func=cmd_edge_sign)

    explain = sub.add_parser("explain", help="summarise a JSONL audit log")
    explain.add_argument("path")
    explain.add_argument("--limit", type=int, default=10)
    explain.add_argument("-v", "--verbose", action="store_true")
    explain.set_defaults(func=cmd_explain)
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "func", None):
        parser.print_help()
        return 0
    return int(args.func(args))


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
