"""Artifact audit — what would an REA-style agent harvest from this build?

This is the "install it on your computer / in CI" half of FightRE.  Before you
deploy, run::

    fightre audit ./dist

It answers one question: *if an AI agent pointed its toolchain at this artifact
right now, what would it get in five minutes?*  Source maps, debug symbols,
committed secrets, schema documents and internal hostnames are exactly the
material REA feeds to its static analysers -- and they are all avoidable.

The audit is heuristic by design: it is a checklist that runs in CI, not a
proof.  Every finding carries the concrete fix in the same line.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

SEVERITY_WEIGHTS = {"critical": 45.0, "high": 24.0, "medium": 9.0, "low": 3.0}
SEVERITY_ORDER = ("critical", "high", "medium", "low")

_SECRET_PATTERNS: Sequence[Tuple[str, str, str]] = (
    ("private-key", r"-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----", "critical"),
    ("aws-access-key", r"\bAKIA[0-9A-Z]{16}\b", "critical"),
    ("gcp-key", r'"type"\s*:\s*"service_account"', "critical"),
    ("jwt", r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{8,}\b", "high"),
    ("generic-secret",
     r"(?i)\b(api[_-]?key|secret|token|password|passwd|private[_-]?key)\b['\"]?\s*[:=]\s*['\"][A-Za-z0-9/_+\-]{16,}['\"]",
     "high"),
    ("slack-token", r"xox[baprs]-[0-9A-Za-z-]{10,}", "high"),
)

_TECH = {
    ".map": ("sourcemap", "critical", "Delete *.map from the deployed artifact (build with sourcemaps off)."),
    ".pdb": ("debug-symbols", "high", "Do not ship Windows debug symbols to production."),
    ".dSYM": ("debug-symbols", "high", "Do not ship Apple debug symbols to production."),
    ".har": ("capture-artifact", "high", "Remove recorded HTTP captures from the artifact."),
    ".pcap": ("capture-artifact", "high", "Remove packet captures from the artifact."),
    ".asar": ("electron-asar", "medium", "ASAR is not protection: use integrity checks and avoid shipping secrets."),
}

_TEXT_EXT = {
    ".js", ".mjs", ".cjs", ".ts", ".json", ".html", ".css", ".map", ".env", ".yaml", ".yml",
    ".xml", ".txt", ".md", ".py", ".java", ".kt", ".swift", ".cs", ".go", ".rb", ".php", ".sh",
    ".toml", ".ini", ".cfg", ".properties", ".pem", ".key", ".crt", ".sql", ".gradle",
}

_INTERNAL_HOST_RE = re.compile(
    r"https?://(?:localhost|127\.0\.0\.1|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}"
    r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|[a-z0-9.-]+\.internal)\b",
    re.IGNORECASE,
)

_SOURCE_MAP_RE = re.compile(r"[#@]\s*sourceMappingURL=([^\s*]+)")
_SCHEMA_NAMES = ("openapi.json", "openapi.yaml", "swagger.json", "swagger.yaml", "graphql.schema.json")


@dataclass
class Finding:
    rule: str
    severity: str
    path: str
    detail: str
    fix: str
    line: int = 0

    @property
    def weight(self) -> float:
        return SEVERITY_WEIGHTS.get(self.severity, 1.0)

    def as_dict(self) -> Dict[str, object]:
        return {
            "rule": self.rule,
            "severity": self.severity,
            "path": self.path,
            "line": self.line,
            "detail": self.detail,
            "fix": self.fix,
        }


@dataclass
class AuditReport:
    root: str
    files_scanned: int = 0
    bytes_scanned: int = 0
    findings: List[Finding] = field(default_factory=list)

    @property
    def score(self) -> float:
        survival = 1.0
        for finding in self.findings:
            survival *= 1.0 - min(0.99, finding.weight / 100.0)
        return round(100.0 * (1.0 - survival), 1)

    @property
    def by_severity(self) -> Dict[str, int]:
        counts = {severity: 0 for severity in SEVERITY_ORDER}
        for finding in self.findings:
            counts[finding.severity] = counts.get(finding.severity, 0) + 1
        return counts

    @property
    def verdict(self) -> str:
        score = self.score
        if score >= 70:
            return "an agent would reconstruct this service quickly"
        if score >= 40:
            return "partially exposed: fix the critical findings first"
        if score >= 15:
            return "mostly hardened: a few leaks remain"
        return "hardened against artifact-level harvesting"

    def as_dict(self) -> Dict[str, object]:
        return {
            "root": self.root,
            "score": self.score,
            "verdict": self.verdict,
            "files_scanned": self.files_scanned,
            "bytes_scanned": self.bytes_scanned,
            "by_severity": self.by_severity,
            "findings": [f.as_dict() for f in self.findings],
        }

    def to_markdown(self) -> str:
        lines = [
            "# FightRE artifact audit",
            "",
            f"**Target:** `{self.root}`  ",
            f"**Exposure score:** {self.score}/100 — {self.verdict}  ",
            f"**Files scanned:** {self.files_scanned} ({self.bytes_scanned / 1024:.1f} KiB)",
            "",
            "| severity | count |",
            "| --- | --- |",
        ]
        for severity in SEVERITY_ORDER:
            lines.append(f"| {severity} | {self.by_severity.get(severity, 0)} |")

        if not self.findings:
            lines += ["", "No findings. Nothing here reads like free source code."]
            return "\n".join(lines) + "\n"

        lines += ["", "## Findings", ""]
        for severity in SEVERITY_ORDER:
            group = [f for f in self.findings if f.severity == severity]
            if not group:
                continue
            lines += [f"### {severity.upper()} ({len(group)})", ""]
            for finding in group:
                location = finding.path + (f":{finding.line}" if finding.line else "")
                lines.append(f"- **{finding.rule}** — `{location}`")
                lines.append(f"  - {finding.detail}")
                lines.append(f"  - fix: {finding.fix}")
            lines.append("")
        return "\n".join(lines)

    def to_json(self) -> str:
        return json.dumps(self.as_dict(), indent=2, ensure_ascii=False)


def _iter_files(root: str, max_files: int, skip_dirs: Sequence[str]) -> Iterable[str]:
    skipped = {d.lower() for d in skip_dirs}
    count = 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d.lower() not in skipped]
        for name in filenames:
            if count >= max_files:
                return
            count += 1
            yield os.path.join(dirpath, name)


def _text_of(path: str, limit: int = 1_000_000) -> Optional[str]:
    try:
        if os.path.getsize(path) > limit:
            return None
        with open(path, "rb") as fh:
            raw = fh.read(limit)
    except OSError:
        return None
    if b"\x00" in raw[:2048]:
        return None
    try:
        return raw.decode("utf-8", "ignore")
    except Exception:  # pragma: no cover - decode with errors never raises
        return None


def audit(
    root: str,
    max_files: int = 20_000,
    skip_dirs: Sequence[str] = (".git", "node_modules", "__pycache__", ".venv", "venv"),
) -> AuditReport:
    """Scan *root* and return an exposure report."""
    report = AuditReport(root=os.path.abspath(root))
    if not os.path.isdir(root):
        raise NotADirectoryError(root)

    for path in _iter_files(root, max_files, skip_dirs):
        rel = os.path.relpath(path, report.root)
        lower = path.lower()
        ext = os.path.splitext(lower)[1]

        report.files_scanned += 1
        try:
            report.bytes_scanned += os.path.getsize(path)
        except OSError:
            pass

        # 1. whole-file technology findings
        if ext in _TECH:
            rule, severity, fix = _TECH[ext]
            detail = {
                "sourcemap": "A source map reconstructs the original TypeScript/JS, comments included.",
                "debug-symbols": "Symbols restore function names and line numbers in the binary.",
                "capture-artifact": "A recorded capture replays the whole API conversation.",
                "electron-asar": "ASAR archives unpack with one command.",
            }.get(rule, "Artefact is directly useful to a static analyser.")
            report.findings.append(Finding(rule, severity, rel, detail, fix))

        if os.path.basename(lower).startswith(".env"):
            report.findings.append(
                Finding(
                    "dotenv",
                    "high",
                    rel,
                    "Environment files in an artifact usually carry live credentials.",
                    "Ship configuration from the platform, never a .env file.",
                )
            )

        if os.path.basename(lower) in _SCHEMA_NAMES:
            report.findings.append(
                Finding(
                    "published-schema",
                    "medium",
                    rel,
                    "A private schema document hands the agent the full API model.",
                    "Generate schemas at build time for internal use only; do not deploy them.",
                )
            )

        # 2. content findings (text only)
        if ext not in _TEXT_EXT and os.path.basename(lower) not in _SCHEMA_NAMES:
            continue
        text = _text_of(path)
        if text is None:
            continue

        for rule, pattern, severity in _SECRET_PATTERNS:
            match = re.search(pattern, text)
            if match:
                line = text[: match.start()].count("\n") + 1
                report.findings.append(
                    Finding(
                        rule,
                        severity,
                        rel,
                        f"Possible credential at line {line}: {match.group(0)[:32]}...",
                        "Remove the value, rotate the credential, load it from a secret store.",
                        line=line,
                    )
                )

        for match in _SOURCE_MAP_RE.finditer(text):
            line = text[: match.start()].count("\n") + 1
            report.findings.append(
                Finding(
                    "sourcemap-reference",
                    "medium",
                    rel,
                    f"Bundle points at {match.group(1)[:60]!r}",
                    "Strip sourceMappingURL comments in the production build.",
                    line=line,
                )
            )

        host = _INTERNAL_HOST_RE.search(text)
        if host:
            line = text[: host.start()].count("\n") + 1
            report.findings.append(
                Finding(
                    "internal-host",
                    "low",
                    rel,
                    f"Internal endpoint leaked: {host.group(0)[:60]}",
                    "Keep internal hostnames server-side; use the public gateway in clients.",
                    line=line,
                )
            )

    report.findings.sort(
        key=lambda f: (SEVERITY_ORDER.index(f.severity), f.path, f.line)
    )
    return report


__all__ = ["AuditReport", "Finding", "audit", "SEVERITY_ORDER"]
