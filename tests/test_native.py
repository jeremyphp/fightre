"""Native binary audit tests with hand-built ELF / Mach-O / PE headers."""

from __future__ import annotations

import os
import struct
import tempfile
import unittest

from fightre.native import audit_binary, audit_paths, detect_kind

SHSTR = b"\x00.shstrtab\x00.symtab\x00.debug_info\x00"


def build_elf(pie: bool = True, symtab: bool = True, debug: bool = True,
              nx: bool = True, relro: bool = True) -> bytes:
    data = bytearray(0x280)
    ident = bytearray(16)
    ident[:4] = b"\x7fELF"
    ident[4] = 2  # 64-bit
    ident[5] = 1  # little endian
    ident[6] = 1
    data[:16] = ident
    struct.pack_into(
        "<HHIQQQIHHHHHH", data, 16,
        3 if pie else 2,  # e_type
        62,               # x86-64
        1, 0,
        0x100,            # e_phoff
        0x180,            # e_shoff
        0, 64, 56, 2 if relro else 1, 64, 4, 1,
    )
    # program headers
    base = 0x100
    struct.pack_into("<IIQQQQQQ", data, base, 0x6474E551, 0 if nx else 1, 0, 0, 0, 0, 0, 16)
    if relro:
        struct.pack_into("<IIQQQQQQ", data, base + 56, 0x6474E552, 4, 0, 0, 0, 0, 0, 16)
    data[0x40 : 0x40 + len(SHSTR)] = SHSTR
    if symtab:
        data[0x80 : 0x80 + 24] = b"\x01" * 24
    if debug:
        data[0xA0 : 0xA0 + 16] = b"\x02" * 16

    def section(index: int, name: int, kind: int, offset: int, size: int, entsize: int = 0) -> None:
        struct.pack_into(
            "<IIQQQQIIQQ", data, 0x180 + index * 64,
            name, kind, 0, 0, offset, size, 0, 0, 8, entsize,
        )

    section(0, 0, 0, 0, 0)
    section(1, 1, 3, 0x40, len(SHSTR))
    section(2, 11, 2, 0x80, 24 if symtab else 0, 24)
    section(3, 19, 1, 0xA0, 16 if debug else 0)
    return bytes(data)


def build_macho(pie: bool = True, symtab: bool = True, dwarf: bool = True) -> bytes:
    commands = bytearray()
    # __TEXT segment
    segment = bytearray(72)
    struct.pack_into("<II", segment, 0, 0x19, 72)
    segment[8:24] = b"__TEXT".ljust(16, b"\x00")
    commands += segment
    if symtab:
        symtab_cmd = bytearray(24)
        struct.pack_into("<IIIIII", symtab_cmd, 0, 0x2, 24, 0, 0, 0, 0)
        commands += symtab_cmd
    if dwarf:
        dwarf_seg = bytearray(72)
        struct.pack_into("<II", dwarf_seg, 0, 0x19, 72)
        dwarf_seg[8:24] = b"__DWARF".ljust(16, b"\x00")
        commands += dwarf_seg
    ncmds = 1 + (1 if symtab else 0) + (1 if dwarf else 0)
    header = struct.pack(
        "<IiiIIIII", 0xFEEDFACF, 0x0100000C, 0, 2, ncmds, len(commands),
        0x200000 if pie else 0, 0,
    )
    return header + bytes(commands)


def build_pe(dll_flags: int = 0x0140, pdb: str = "", symbols: bool = False) -> bytes:
    data = bytearray(0x200)
    data[0:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x40)
    data[0x40:0x44] = b"PE\x00\x00"
    struct.pack_into(
        "<HHIIIHH", data, 0x44,
        0x8664, 0, 0, 0x1000 if symbols else 0, 10 if symbols else 0, 0xF0, 0x22,
    )
    opt = 0x58
    struct.pack_into("<H", data, opt, 0x20B)  # PE32+
    struct.pack_into("<H", data, opt + 70, dll_flags)
    if pdb:
        payload = pdb.encode("ascii")
        data[0x150 : 0x150 + len(payload)] = payload
    return bytes(data)


class ElfTests(unittest.TestCase):
    def test_detect_kind(self) -> None:
        self.assertEqual(detect_kind(build_elf()), "elf")
        self.assertEqual(detect_kind(build_macho()), "macho")
        self.assertEqual(detect_kind(build_pe()), "pe")
        self.assertEqual(detect_kind(b"hello"), "")

    def test_leaky_elf_is_flagged(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            path = os.path.join(root, "app")
            with open(path, "wb") as handle:
                handle.write(build_elf(pie=False, nx=False, relro=False))
            report = audit_binary(path)
            rules = {f.rule for f in report.findings}
            self.assertEqual(report.kind, "elf")
            self.assertEqual(report.arch, "x86-64")
            self.assertIn("symbol-table", rules)
            self.assertIn("debug-info", rules)
            self.assertIn("no-pie", rules)
            self.assertIn("no-nx", rules)
            self.assertIn("no-relro", rules)
            self.assertGreaterEqual(report.score, 80)

    def test_hardened_elf_is_clean(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            path = os.path.join(root, "app")
            with open(path, "wb") as handle:
                handle.write(build_elf(symtab=False, debug=False))
            report = audit_binary(path)
            self.assertEqual(report.findings, [])
            self.assertEqual(report.score, 0.0)
            self.assertTrue(report.hardening["symbols_stripped"])

    def test_audit_paths_walks_directory(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            with open(os.path.join(root, "bin"), "wb") as handle:
                handle.write(build_elf())
            with open(os.path.join(root, "notes.txt"), "w", encoding="utf-8") as handle:
                handle.write("not a binary")
            report = audit_paths([root])
            self.assertEqual(len(report.binaries), 1)
            self.assertEqual(report.skipped, 1)
            self.assertGreater(report.score, 0)


class MachOTests(unittest.TestCase):
    def test_macho_findings(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            path = os.path.join(root, "app")
            with open(path, "wb") as handle:
                handle.write(build_macho(pie=False, dwarf=True))
            report = audit_binary(path)
            self.assertEqual(report.kind, "macho")
            self.assertEqual(report.arch, "arm64")
            rules = {f.rule for f in report.findings}
            self.assertIn("symbol-table", rules)
            self.assertIn("dwarf-leak", rules)
            self.assertIn("no-pie", rules)

    def test_stripped_macho(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            path = os.path.join(root, "app")
            with open(path, "wb") as handle:
                handle.write(build_macho(symtab=False, dwarf=False))
            report = audit_binary(path)
            self.assertEqual(report.findings, [])


class PeTests(unittest.TestCase):
    def test_pe_with_pdb_and_no_mitigations(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            path = os.path.join(root, "app.exe")
            with open(path, "wb") as handle:
                handle.write(build_pe(dll_flags=0, pdb=r"C:\build\app.pdb", symbols=True))
            report = audit_binary(path)
            self.assertEqual(report.kind, "pe")
            self.assertEqual(report.arch, "x86-64")
            rules = {f.rule for f in report.findings}
            self.assertIn("pdb-path", rules)
            self.assertIn("no-pie", rules)
            self.assertIn("no-nx", rules)
            self.assertIn("symbol-table", rules)

    def test_hardened_pe(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            path = os.path.join(root, "app.exe")
            with open(path, "wb") as handle:
                handle.write(build_pe(dll_flags=0x4140))
            report = audit_binary(path)
            self.assertNotIn("no-nx", {f.rule for f in report.findings})
            self.assertNotIn("pdb-path", {f.rule for f in report.findings})


if __name__ == "__main__":
    unittest.main()
