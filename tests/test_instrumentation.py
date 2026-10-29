"""Runtime instrumentation self-check tests."""

from __future__ import annotations

import os
import socket
import sys
import tempfile
import unittest

from fightre import instrumentation as instr
from fightre import signals as sig
from fightre.scoring import RiskEngine


def fake_proc(root: str, status: str = "", maps: str = "") -> str:
    proc = os.path.join(root, "proc")
    os.makedirs(os.path.join(proc, "self"), exist_ok=True)
    if status:
        with open(os.path.join(proc, "self", "status"), "w", encoding="utf-8") as handle:
            handle.write(status)
    if maps:
        with open(os.path.join(proc, "self", "maps"), "w", encoding="utf-8") as handle:
            handle.write(maps)
    return proc


class CheckTests(unittest.TestCase):
    def test_tracer_clean(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            proc = fake_proc(root, "Name:\tpython\nTracerPid:\t0\n")
            self.assertTrue(instr.check_tracer(proc).ok)

    def test_tracer_attached(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            proc = fake_proc(root, "Name:\tpython\nTracerPid:\t4242\n")
            check = instr.check_tracer(proc)
            self.assertFalse(check.ok)
            self.assertEqual(check.signal, "client.debugger_attached")

    def test_frida_in_maps(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            proc = fake_proc(root, maps="/usr/lib/libc.so\n/tmp/frida-agent-64.so\n")
            check = instr.check_frida_maps(proc)
            self.assertFalse(check.ok)
            self.assertEqual(check.signal, "client.instrumentation_detected")

    def test_clean_maps(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            proc = fake_proc(root, maps="/usr/lib/libc.so\n")
            self.assertTrue(instr.check_frida_maps(proc).ok)

    def test_preload(self) -> None:
        self.assertFalse(instr.check_preload({"LD_PRELOAD": "/tmp/hook.so"}).ok)
        self.assertTrue(instr.check_preload({}).ok)

    def test_python_trace(self) -> None:
        self.assertTrue(instr.check_python_trace().ok)

        def tracer(frame, event, arg):  # pragma: no cover - never called
            return tracer

        sys.settrace(tracer)
        try:
            check = instr.check_python_trace()
            self.assertFalse(check.ok)
        finally:
            sys.settrace(None)

    def test_debug_modules(self) -> None:
        self.assertFalse(instr.check_debug_modules(["pydevd", "os"]).ok)
        self.assertTrue(instr.check_debug_modules(["os", "json"]).ok)

    def test_frida_port_open(self) -> None:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        port = server.getsockname()[1]
        try:
            check = instr.check_frida_ports(ports=[port], timeout=0.2)
            self.assertFalse(check.ok)
        finally:
            server.close()

    def test_frida_port_closed(self) -> None:
        check = instr.check_frida_ports(ports=[1], timeout=0.05)
        self.assertTrue(check.ok)


class AggregateTests(unittest.TestCase):
    def test_collect_and_signals(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            proc = fake_proc(
                root,
                "TracerPid:\t7\n",
                "/tmp/gum-js-loop-1234\n",
            )
            checks = instr.collect(proc_root=proc, environ={"LD_PRELOAD": "x"}, modules=["pydevd"],
                                   probe_ports=False)
            failed = [c for c in checks if c.triggered]
            self.assertGreaterEqual(len(failed), 3)
            signals = instr.to_signals(checks)
            names = {s.name for s in signals}
            self.assertIn("client.debugger_attached", names)
            self.assertIn("client.instrumentation_detected", names)
            self.assertIn("client.preload_hijack", names)

            report = RiskEngine().score(signals)
            self.assertGreaterEqual(report.score, 85)

    def test_summarize_clean(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            proc = fake_proc(root, "TracerPid:\t0\n", "/usr/lib/libc.so\n")
            summary = instr.summarize(
                instr.collect(proc_root=proc, environ={}, modules=[], probe_ports=False)
            )
            self.assertTrue(summary["clean"])
            self.assertEqual(summary["critical"], 0)

    def test_signal_catalogue_has_new_names(self) -> None:
        for name in (
            "client.debugger_attached",
            "client.instrumentation_detected",
            "client.preload_hijack",
            "client.root_or_jailbreak",
        ):
            self.assertIn(name, sig.LIBRARY)


if __name__ == "__main__":
    unittest.main()
