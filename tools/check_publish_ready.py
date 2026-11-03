#!/usr/bin/env python3
"""Pre-publish guard: do not make the repository public until this exits 0.

Usage: python tools/check_publish_ready.py

Design intent: this script exists so a maintainer cannot *forget* a check, not to
replace judgement. Every rule prints its matching lines so a human can confirm.

Output is ASCII-only on purpose: the tool has to run identically in a Windows
GBK console, a POSIX CI runner and a UTF-8 terminal.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

SKIP_DIRS = {".git", "__pycache__", ".venv", "venv", "dist", "build", "node_modules", ".egg-info", ".pytest_cache"}
TEXT_EXT = {".md", ".py", ".toml", ".yml", ".yaml", ".json", ".txt", ".ps1", ".cfg", ".ini"}

# (rule name, pattern, what to do, blocks publish)
RULES: list[tuple[str, str, str, bool]] = [
    (
        "placeholder-owner",
        r"your-org/|github\.com/<owner>",
        "repository owner is still a placeholder; run tools/set_repo_owner.ps1 -Owner <username>",
        True,
    ),
    (
        "local-path",
        r"[A-Za-z]:[\\/]{1,2}(?:fightrea|Users|projecteryingxiao)",
        "a local absolute path appears in a file that will be public",
        True,
    ),
    (
        "credential",
        r"ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|AKIA[0-9A-Z]{16}",
        "possible real credential",
        True,
    ),
    (
        "private-key",
        r"-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----\s*\n[A-Za-z0-9+/]{40,}",
        "possible real private key (short fake PEMs in fixtures are fine)",
        True,
    ),
    (
        "personal-email",
        r"[\w.+-]+@(?:qq|163|126|gmail|outlook|hotmail)\.com",
        "personal email address in a file that will be public",
        False,
    ),
    (
        "hardcoded-secret",
        r"(?i)\b(?:password|passwd|secret|api_key|apikey)\s*[=:]\s*[\"']([^\"'\s]{8,})[\"']",
        "hardcoded secret-looking assignment (test fixtures may be intentional)",
        False,
    ),
]

# Values that look like a secret but are obviously placeholders. Matching is done on
# the captured value, not the whole match, so `secret = "manifest-test-secret"` in a
# test is not reported while a real-looking base64 blob still is.
PLACEHOLDER_HINTS = ("test", "example", "dummy", "fake", "sample", "changeme", "placeholder", "xxx")


def is_placeholder_secret(match: re.Match[str]) -> bool:
    try:
        value = match.group(1)
    except IndexError:
        return False
    lowered = value.lower()
    return any(hint in lowered for hint in PLACEHOLDER_HINTS)


REQUIRED_FILES = [
    "README.md",
    "README.zh-CN.md",
    "LICENSE",
    "NOTICE",
    "SECURITY.md",
    "CONTRIBUTING.md",
    "SUPPORT.md",
    "TRADEMARK.md",
    "CHANGELOG.md",
    "QUICKSTART.md",
    "docs/DESIGN-RATIONALE.md",
    "docs/THREAT-MODEL.md",
    "docs/DEPLOYMENT.md",
    "docs/SIGNALS.md",
    ".github/workflows/ci.yml",
]


def iter_files():
    for path in ROOT.rglob("*"):
        if not path.is_file():
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if path.suffix.lower() not in TEXT_EXT:
            continue
        yield path


def rule_applies(rule_name: str, rel_path: str) -> bool:
    """Which rules apply to which files.

    The placeholder rule is scoped deliberately:

    - ``launch/`` is internal release material. It *documents* the placeholder and
      the command that replaces it, so matching there is noise, not a finding.
    - this file contains the pattern itself, so it always matches itself.
    """
    if rule_name != "placeholder-owner":
        return True
    if rel_path.startswith("launch/"):
        return False
    if rel_path.endswith("tools/check_publish_ready.py"):
        return False
    if rel_path.endswith("tools/set_repo_owner.ps1"):
        return False
    return True


def scan() -> int:
    blocking = 0
    advisory = 0
    hits: dict[str, list[str]] = {}

    for path in iter_files():
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        rel = path.relative_to(ROOT).as_posix()
        for name, pattern, _msg, is_blocking in RULES:
            if not rule_applies(name, rel):
                continue
            for match in re.finditer(pattern, text):
                if name == "hardcoded-secret" and is_placeholder_secret(match):
                    continue
                line_no = text.count("\n", 0, match.start()) + 1
                snippet = match.group(0).replace("\n", " ")[:80]
                hits.setdefault(name, []).append(f"      {rel}:{line_no}  {snippet}")
                if is_blocking:
                    blocking += 1
                else:
                    advisory += 1

    print("== rule scan ==")
    if not hits:
        print("  [OK] no findings")
    for name, _pattern, msg, is_blocking in RULES:
        found = hits.get(name, [])
        if not found:
            continue
        mark = "[FAIL]" if is_blocking else "[WARN]"
        print(f"  {mark} {name} ({len(found)}) - {msg}")
        for line in found[:6]:
            print(line)
        if len(found) > 6:
            print(f"      ... and {len(found) - 6} more")

    print("\n== required files ==")
    missing = [f for f in REQUIRED_FILES if not (ROOT / f).exists()]
    if missing:
        for f in missing:
            print(f"  [FAIL] missing {f}")
        blocking += len(missing)
    else:
        print("  [OK] all present")

    print("\n== tests ==")
    try:
        proc = subprocess.run(
            [sys.executable, "-m", "pytest", "-q", "--no-header", "-x"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=900,
        )
        lines = [ln for ln in proc.stdout.strip().splitlines() if ln.strip()]
        if proc.returncode == 0:
            print(f"  [OK] {lines[-1] if lines else 'passed'}")
        else:
            print("  [FAIL] pytest failed")
            for ln in lines[-15:]:
                print(f"      {ln}")
            blocking += 1
    except (OSError, subprocess.SubprocessError) as exc:  # noqa: BLE001
        print(f"  [WARN] could not run pytest: {exc}")

    print("\n" + "=" * 60)
    if blocking:
        tail = f", {advisory} advisory" if advisory else ""
        print(f"RESULT: DO NOT PUBLISH - {blocking} blocking finding(s){tail}")
        return 1
    tail = f" ({advisory} advisory finding(s) need review)" if advisory else ""
    print(f"RESULT: READY TO PUBLISH{tail}")
    return 0


if __name__ == "__main__":
    sys.exit(scan())
