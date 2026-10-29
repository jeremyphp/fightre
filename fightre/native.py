"""Native artifact audit: what a static analyser gets from your binary.

REA's cheapest path into a native app is not Frida -- it is ``strings`` plus a
symbol table. A stripped, PIE, NX, RELRO binary with no DWARF and no PDB path
turns "read the function names" into "reconstruct from assembly", which is an
order of magnitude more expensive.

This module parses ELF, PE and Mach-O headers directly (stdlib ``struct``) and
reports three things per file: hardening posture, leftover debug material, and
build-path leaks. No disassembly, no heuristics about code -- just the facts
that decide whether an analyst starts with names or with addresses.
"""

from __future__ import annotations

import os
import re
import struct
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

SEVERITY_WEIGHTS = {"critical": 45.0, "high": 22.0, "medium": 9.0, "low": 3.0}
SEVERITY_ORDER = ("critical", "high", "medium", "low")
MAX_FILE_BYTES = 512 * 1024 * 1024
MAX_SCAN_BYTES = 64 * 1024 * 1024

ELF_MAGIC = b"\x7fELF"
MACHO_MAGICS = (b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xfe\xed\xfa\xce")
PE_MAGIC = b"MZ"

ELF_MACHINES = {
    3: "i386", 8: "mips", 20: "ppc", 21: "ppc64", 40: "arm", 62: "x86-64",
    183: "aarch64", 243: "riscv", 258: "loongarch",
}

MACHO_CPUS = {7: "i386", 0x01000007: "x86-64", 12: "arm", 0x0100000C: "arm64"}

PT_GNU_STACK = 0x6474E551
PT_GNU_RELRO = 0x6474E552
PF_X = 0x1


@dataclass
class NativeFinding:
    rule: str
    severity: str
    path: str
    detail: str
    fix: str

    @property
    def weight(self) -> float:
        return SEVERITY_WEIGHTS.get(self.severity, 1.0)

    def as_dict(self) -> Dict[str, object]:
        return {
            "rule": self.rule,
            "severity": self.severity,
            "path": self.path,
            "detail": self.detail,
            "fix": self.fix,
        }


@dataclass
class BinaryReport:
    path: str
    kind: str
    arch: str = "unknown"
    bits: int = 0
    hardening: Dict[str, bool] = field(default_factory=dict)
    findings: List[NativeFinding] = field(default_factory=list)
    error: str = ""

    @property
    def score(self) -> float:
        survival = 1.0
        for finding in self.findings:
            survival *= 1.0 - min(0.99, finding.weight / 100.0)
        return round(100.0 * (1.0 - survival), 1)

    def as_dict(self) -> Dict[str, object]:
        return {
            "path": self.path,
            "kind": self.kind,
            "arch": self.arch,
            "bits": self.bits,
            "hardening": dict(self.hardening),
            "score": self.score,
            "error": self.error,
            "findings": [f.as_dict() for f in self.findings],
        }


@dataclass
class NativeReport:
    root: str
    binaries: List[BinaryReport] = field(default_factory=list)
    skipped: int = 0

    @property
    def score(self) -> float:
        if not self.binaries:
            return 0.0
        return round(max(b.score for b in self.binaries), 1)

    @property
    def by_severity(self) -> Dict[str, int]:
        counts = {severity: 0 for severity in SEVERITY_ORDER}
        for binary in self.binaries:
            for finding in binary.findings:
                counts[finding.severity] = counts.get(finding.severity, 0) + 1
        return counts

    def as_dict(self) -> Dict[str, object]:
        return {
            "root": self.root,
            "score": self.score,
            "by_severity": self.by_severity,
            "skipped": self.skipped,
            "binaries": [b.as_dict() for b in self.binaries],
        }

    def to_markdown(self) -> str:
        lines = [
            "# FightRE native audit",
            "",
            f"**Target:** `{self.root}`  ",
            f"**Worst binary score:** {self.score}/100  ",
            f"**Binaries:** {len(self.binaries)} (skipped {self.skipped})",
            "",
            "| binary | arch | strip | dwarf/pdb | pie | nx | relro | score |",
            "| --- | --- | --- | --- | --- | --- | --- | --- |",
        ]
        for binary in self.binaries:
            flags = binary.hardening
            lines.append(
                "| `{}` | {} | {} | {} | {} | {} | {} | {} |".format(
                    binary.path.replace("|", "\\|"),
                    binary.arch,
                    _mark(flags.get("symbols_stripped")),
                    _mark(flags.get("debug_info_removed")),
                    _mark(flags.get("pie")),
                    _mark(flags.get("nx")),
                    _mark(flags.get("relro")),
                    binary.score,
                )
            )
        for binary in self.binaries:
            if not binary.findings:
                continue
            lines += ["", f"## {binary.path}", ""]
            for finding in binary.findings:
                lines.append(f"- **{finding.severity}** `{finding.rule}` — {finding.detail}")
                lines.append(f"  - fix: {finding.fix}")
        return "\n".join(lines) + "\n"


def _mark(value: Optional[bool]) -> str:
    if value is None:
        return "?"
    return "yes" if value else "no"


# --------------------------------------------------------------------------
# ELF
# --------------------------------------------------------------------------
def _parse_elf(data: bytes, path: str) -> BinaryReport:
    report = BinaryReport(path=path, kind="elf")
    if len(data) < 52:
        report.error = "truncated ELF header"
        return report
    bits = 64 if data[4] == 2 else 32
    endian = "<" if data[5] == 1 else ">"
    report.bits = bits
    try:
        if bits == 64:
            e_type, e_machine = struct.unpack_from(endian + "HH", data, 16)
            e_phoff, e_shoff = struct.unpack_from(endian + "QQ", data, 32)
            e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx = struct.unpack_from(
                endian + "HHHHH", data, 54
            )
        else:
            e_type, e_machine = struct.unpack_from(endian + "HH", data, 16)
            e_phoff, e_shoff = struct.unpack_from(endian + "II", data, 28)
            e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx = struct.unpack_from(
                endian + "HHHHH", data, 42
            )
    except struct.error:
        report.error = "malformed ELF header"
        return report

    report.arch = ELF_MACHINES.get(e_machine, f"machine-{e_machine}")
    sections = _elf_sections(data, endian, bits, e_shoff, e_shentsize, e_shnum, e_shstrndx)
    has_symtab = any(name == ".symtab" and size > 0 for name, _, size in sections)
    has_debug = any(name.startswith(".debug") and size > 0 for name, _, size in sections)
    pt_types = _elf_program_types(data, endian, bits, e_phoff, e_phentsize, e_phnum)
    stack_exec = any(ptype == PT_GNU_STACK and (flags & PF_X) for ptype, flags in pt_types)
    has_relro = any(ptype == PT_GNU_RELRO for ptype, _ in pt_types)

    report.hardening = {
        "symbols_stripped": not has_symtab,
        "debug_info_removed": not has_debug,
        "pie": e_type == 3,
        "nx": not stack_exec,
        "relro": has_relro,
        "aslr": e_type == 3,
    }

    report.findings = _findings_from_hardening(report)
    return report


def _elf_sections(
    data: bytes, endian: str, bits: int, offset: int, entry_size: int, count: int, str_index: int
) -> List[Tuple[str, int, int]]:
    """Return ``(name, type, size)`` for each section header."""
    if offset <= 0 or count <= 0 or entry_size <= 0:
        return []
    headers = []
    for index in range(min(count, 4096)):
        base = offset + index * entry_size
        try:
            if bits == 64:
                name_offset, sh_type = struct.unpack_from(endian + "II", data, base)
                sh_offset, sh_size = struct.unpack_from(endian + "QQ", data, base + 24)
            else:
                name_offset, sh_type = struct.unpack_from(endian + "II", data, base)
                sh_offset, sh_size = struct.unpack_from(endian + "II", data, base + 16)
        except struct.error:
            break
        headers.append((name_offset, sh_type, sh_offset, sh_size))

    str_offset = str_size = 0
    if 0 <= str_index < len(headers):
        _, _, str_offset, str_size = headers[str_index]
    table = data[str_offset : str_offset + str_size] if str_size else b""

    sections: List[Tuple[str, int, int]] = []
    for name_offset, sh_type, _, sh_size in headers:
        name = ""
        if table and name_offset < len(table):
            end = table.find(b"\x00", name_offset)
            name = table[name_offset : end if end != -1 else None].decode("utf-8", "ignore")
        sections.append((name, sh_type, sh_size))
    return sections


def _elf_program_types(
    data: bytes, endian: str, bits: int, offset: int, entry_size: int, count: int
) -> List[Tuple[int, int]]:
    if offset <= 0 or count <= 0 or entry_size <= 0:
        return []
    result = []
    for index in range(min(count, 1024)):
        base = offset + index * entry_size
        try:
            if bits == 64:
                p_type, p_flags = struct.unpack_from(endian + "II", data, base)
            else:
                p_type = struct.unpack_from(endian + "I", data, base)[0]
                p_flags = struct.unpack_from(endian + "I", data, base + 24)[0]
        except struct.error:
            break
        result.append((p_type, p_flags))
    return result


# --------------------------------------------------------------------------
# Mach-O
# --------------------------------------------------------------------------
def _parse_macho(data: bytes, path: str) -> BinaryReport:
    report = BinaryReport(path=path, kind="macho")
    if len(data) < 28:
        report.error = "truncated Mach-O header"
        return report
    little = data[:4] in (b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe")
    endian = "<" if little else ">"
    bits = 64 if data[:4] in (b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf") else 32
    report.bits = bits
    try:
        _, cputype, _, filetype, ncmds, sizeofcmds, flags = struct.unpack_from(
            endian + "IiiIIII", data, 0
        )
    except struct.error:
        report.error = "malformed Mach-O header"
        return report

    report.arch = MACHO_CPUS.get(cputype & 0xFFFFFFFF, f"cpu-{cputype}")

    offset = 32 if bits == 64 else 28
    cursor = offset
    has_symtab = False
    has_dwarf = False
    end = min(len(data), offset + sizeofcmds)
    for _ in range(min(ncmds, 1024)):
        if cursor + 8 > end:
            break
        cmd, cmdsize = struct.unpack_from(endian + "II", data, cursor)
        if cmdsize < 8:
            break
        if cmd == 0x2:  # LC_SYMTAB
            has_symtab = True
        elif cmd == 0x19 and bits == 64:  # LC_SEGMENT_64
            segname = data[cursor + 8 : cursor + 24].rstrip(b"\x00").decode("ascii", "ignore")
            if segname == "__DWARF":
                has_dwarf = True
        cursor += cmdsize

    report.hardening = {
        "symbols_stripped": not has_symtab,
        "debug_info_removed": not has_dwarf,
        "pie": bool(flags & 0x200000),
        "nx": True,  # 64-bit Apple platforms are always NX
        "relro": True,
        "aslr": bool(flags & 0x200000),
        "cfg": None,  # not applicable
    }
    report.findings = _findings_from_hardening(report)
    if has_dwarf:
        report.findings.append(
            NativeFinding(
                "dwarf-leak",
                "high",
                path,
                "The binary still carries a __DWARF segment (source-level names and lines).",
                "Ship the dSYM separately (dsymutil) and strip it from the app bundle.",
            )
        )
    return report


# --------------------------------------------------------------------------
# PE
# --------------------------------------------------------------------------
_PDB_RE = re.compile(rb"([A-Za-z]:\\[^\x00]{4,160}\.pdb)")


def _parse_pe(data: bytes, path: str) -> BinaryReport:
    report = BinaryReport(path=path, kind="pe")
    if len(data) < 0x40:
        report.error = "truncated DOS header"
        return report
    try:
        pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    except struct.error:
        report.error = "malformed DOS header"
        return report
    if pe_offset + 24 > len(data) or data[pe_offset : pe_offset + 4] != b"PE\x00\x00":
        report.error = "PE signature missing"
        return report

    coff = pe_offset + 4
    machine, _, _, sym_table, sym_count, opt_size, _ = struct.unpack_from("<HHIIIHH", data, coff)
    report.arch = {
        0x14C: "i386", 0x8664: "x86-64", 0xAA64: "arm64", 0x1C0: "arm",
    }.get(machine, f"machine-{machine:x}")

    opt = coff + 20
    magic = struct.unpack_from("<H", data, opt)[0]
    pe32plus = magic == 0x20B
    report.bits = 64 if pe32plus else 32
    dll_offset = opt + 70  # DllCharacteristics: same offset for PE32 and PE32+
    dll_flags = struct.unpack_from("<H", data, dll_offset)[0]
    data_dir = opt + (112 if pe32plus else 96)

    has_pdb = bool(_PDB_RE.search(data[: MAX_SCAN_BYTES])) or b".pdb" in data[: MAX_SCAN_BYTES]
    debug_rva = struct.unpack_from("<I", data, data_dir + 6 * 8)[0] if len(data) >= data_dir + 56 else 0

    report.hardening = {
        "symbols_stripped": sym_table == 0 and sym_count == 0,
        "debug_info_removed": not (has_pdb or debug_rva),
        "pie": bool(dll_flags & 0x0040),  # DYNAMIC_BASE (ASLR)
        "nx": bool(dll_flags & 0x0100),  # NX_COMPAT (DEP)
        "relro": None,
        "aslr": bool(dll_flags & 0x0040),
        "cfg": bool(dll_flags & 0x4000),  # GUARD_CF
    }
    report.findings = _findings_from_hardening(report)
    if has_pdb:
        report.findings.append(
            NativeFinding(
                "pdb-path",
                "high",
                path,
                "A .pdb path is embedded: it leaks the build machine layout and symbol location.",
                "Rebuild with /DEBUG:NONE (or /PDBALTPATH:%_PDB%) for release artifacts.",
            )
        )
    return report


# --------------------------------------------------------------------------
# shared finding builder
# --------------------------------------------------------------------------
STRIP_HINTS = {
    "elf": "strip --strip-all <binary> (or build with -s and no -g)",
    "macho": "strip -S <binary> and ship the dSYM separately",
    "pe": "build release with /DEBUG:NONE and no /Zi",
}


def _findings_from_hardening(report: BinaryReport) -> List[NativeFinding]:
    h = report.hardening
    path = report.path
    hint = STRIP_HINTS.get(report.kind, "strip symbols before shipping")
    findings: List[NativeFinding] = []

    if h.get("symbols_stripped") is False:
        findings.append(
            NativeFinding(
                "symbol-table",
                "critical",
                path,
                "Symbol table present: every function name is visible without disassembly.",
                hint,
            )
        )
    if h.get("debug_info_removed") is False:
        findings.append(
            NativeFinding(
                "debug-info",
                "critical",
                path,
                "Debug information present: variable names, types and line numbers survive.",
                hint,
            )
        )
    if h.get("pie") is False:
        findings.append(
            NativeFinding(
                "no-pie",
                "medium",
                path,
                "Not position independent: fixed addresses make ROP and patching easier.",
                "Build with -fPIE -pie (ELF) or /DYNAMICBASE (PE).",
            )
        )
    if h.get("nx") is False:
        findings.append(
            NativeFinding(
                "no-nx",
                "high",
                path,
                "Executable stack / DEP disabled: injected code can simply run.",
                "Link with -z noexecstack (ELF) or /NXCOMPAT (PE).",
            )
        )
    if h.get("relro") is False:
        findings.append(
            NativeFinding(
                "no-relro",
                "medium",
                path,
                "No GNU_RELRO: GOT entries stay writable after relocation.",
                "Link with -Wl,-z,relro,-z,now.",
            )
        )
    if h.get("cfg") is False:
        findings.append(
            NativeFinding(
                "no-cfg",
                "low",
                path,
                "Control Flow Guard is off: indirect calls are unguarded.",
                "Add /guard:cf when building for Windows.",
            )
        )
    return findings


# --------------------------------------------------------------------------
# entry points
# --------------------------------------------------------------------------
def detect_kind(data: bytes) -> str:
    if data.startswith(ELF_MAGIC):
        return "elf"
    if data[:4] in MACHO_MAGICS:
        return "macho"
    if data.startswith(PE_MAGIC):
        return "pe"
    return ""


def audit_binary(path: str) -> BinaryReport:
    size = os.path.getsize(path)
    if size > MAX_FILE_BYTES:
        raise ValueError(f"{path}: larger than {MAX_FILE_BYTES} bytes")
    with open(path, "rb") as handle:
        data = handle.read()
    kind = detect_kind(data)
    if not kind:
        raise ValueError(f"{path}: not an ELF/PE/Mach-O binary")
    if kind == "elf":
        return _parse_elf(data, path)
    if kind == "macho":
        return _parse_macho(data, path)
    return _parse_pe(data, path)


def audit_paths(paths: Sequence[str], max_files: int = 20_000) -> NativeReport:
    root = paths[0] if len(paths) == 1 else ", ".join(paths[:3])
    report = NativeReport(root=os.path.abspath(root) if len(paths) == 1 else root)
    seen = 0
    for target in paths:
        if os.path.isfile(target):
            seen += 1
            if _try_binary(report, target) is None:
                report.skipped += 1
            continue
        if not os.path.isdir(target):
            continue
        for dirpath, _, filenames in os.walk(target):
            if seen >= max_files:
                break
            for name in filenames:
                if seen >= max_files:
                    break
                seen += 1
                if _try_binary(report, os.path.join(dirpath, name)) is None:
                    report.skipped += 1
    report.binaries.sort(key=lambda b: (-b.score, b.path))
    return report


def _try_binary(report: NativeReport, path: str) -> Optional[BinaryReport]:
    try:
        with open(path, "rb") as handle:
            head = handle.read(8)
    except OSError:
        return None
    if not detect_kind(head):
        return None
    try:
        binary = audit_binary(path)
    except (ValueError, OSError, struct.error):
        return None
    report.binaries.append(binary)
    return binary


__all__ = [
    "BinaryReport",
    "NativeFinding",
    "NativeReport",
    "audit_binary",
    "audit_paths",
    "detect_kind",
]
