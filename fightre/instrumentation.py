"""Runtime self-check: is *our own process* being instrumented?

FightRE protects a service from the outside. This module answers the other
question a desktop or mobile build has to ask at startup: has someone attached
a debugger, injected a library, or loaded a Frida agent into this process?

Everything here is read-only introspection of the current process and is safe to
run in production: it reads ``/proc/self``, environment variables and
``sys.modules``, and optionally probes the two well-known local Frida ports. It
does not scan other processes, patch anything, or attempt anti-forensics.

The output maps to the same signal catalogue as the HTTP layer, so a desktop app
can feed it into :class:`fightre.scoring.RiskEngine` and react the same way the
server would.
"""

from __future__ import annotations

import os
import socket
import sys
from dataclasses import dataclass
from typing import Dict, Iterable, List, Mapping, Optional, Sequence

from . import signals as sig
from .signals import Signal

FRIDA_PORTS = (27042, 27043)
FRIDA_MARKERS = ("frida", "gum-js-loop", "gum-js", "linjector", "frida-agent", "gadget")
DEBUG_MODULES = ("pydevd", "debugpy", "ptvsd", "pdb", "ipdb", "pudb")


@dataclass
class Check:
    name: str
    ok: bool
    detail: str = ""
    severity: str = "medium"
    signal: str = ""

    @property
    def triggered(self) -> bool:
        return not self.ok

    def as_dict(self) -> Dict[str, object]:
        return {
            "name": self.name,
            "ok": self.ok,
            "detail": self.detail,
            "severity": self.severity,
            "signal": self.signal,
        }


def _read(path: str, limit: int = 262_144) -> str:
    try:
        with open(path, encoding="utf-8", errors="ignore") as handle:
            return handle.read(limit)
    except OSError:
        return ""


def check_tracer(proc_root: str = "/proc") -> Check:
    status = _read(os.path.join(proc_root, "self", "status"))
    if not status:
        return Check("tracer", True, "no /proc on this platform; check skipped")
    for line in status.splitlines():
        if line.startswith("TracerPid:"):
            value = line.split(":", 1)[1].strip()
            if value not in ("0", ""):
                return Check(
                    "tracer", False, f"TracerPid={value}", "critical", "client.debugger_attached"
                )
    return Check("tracer", True, "no tracer attached")


def check_frida_maps(proc_root: str = "/proc") -> Check:
    maps = _read(os.path.join(proc_root, "self", "maps"))
    if not maps:
        return Check("frida-maps", True, "no /proc on this platform; check skipped")
    for line in maps.splitlines():
        lowered = line.lower()
        for marker in FRIDA_MARKERS:
            if marker in lowered:
                return Check(
                    "frida-maps",
                    False,
                    f"agent mapped: {line.strip()[:110]}",
                    "critical",
                    "client.instrumentation_detected",
                )
    return Check("frida-maps", True, "no instrumentation agent in process maps")


def check_preload(environ: Optional[Mapping[str, str]] = None) -> Check:
    env = os.environ if environ is None else environ
    for key in ("LD_PRELOAD", "DYLD_INSERT_LIBRARIES", "DYLD_FRAMEWORK_PATH"):
        value = (env.get(key) or "").strip()
        if value:
            return Check(
                "preload", False, f"{key}={value[:120]}", "high", "client.preload_hijack"
            )
    return Check("preload", True, "no library preload variables set")


def check_python_trace() -> Check:
    tracer = sys.gettrace()
    if tracer is not None:
        return Check(
            "python-trace",
            False,
            f"sys.gettrace() -> {getattr(tracer, '__qualname__', type(tracer).__name__)}",
            "high",
            "client.debugger_attached",
        )
    return Check("python-trace", True, "no Python trace function installed")


def check_debug_modules(modules: Optional[Iterable[str]] = None) -> Check:
    names = set(modules) if modules is not None else set(sys.modules)
    found = sorted(names & set(DEBUG_MODULES))
    if found:
        return Check(
            "debug-modules", False, "loaded: " + ", ".join(found), "medium", "client.debugger_attached"
        )
    return Check("debug-modules", True, "no debugger modules loaded")


def check_frida_ports(
    host: str = "127.0.0.1", ports: Sequence[int] = FRIDA_PORTS, timeout: float = 0.05
) -> Check:
    open_ports = []
    for port in ports:
        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        probe.settimeout(timeout)
        try:
            if probe.connect_ex((host, port)) == 0:
                open_ports.append(port)
        except OSError:
            pass
        finally:
            probe.close()
    if open_ports:
        return Check(
            "frida-port",
            False,
            "Frida default port open: " + ", ".join(str(p) for p in open_ports),
            "high",
            "client.instrumentation_detected",
        )
    return Check("frida-port", True, "no Frida port listening")


def collect(
    proc_root: str = "/proc",
    environ: Optional[Mapping[str, str]] = None,
    modules: Optional[Iterable[str]] = None,
    probe_ports: bool = True,
) -> List[Check]:
    checks = [
        check_tracer(proc_root),
        check_frida_maps(proc_root),
        check_preload(environ),
        check_python_trace(),
        check_debug_modules(modules),
    ]
    if probe_ports:
        checks.append(check_frida_ports())
    return checks


def to_signals(checks: Iterable[Check]) -> List[Signal]:
    return [
        sig.make(check.signal, check.detail)
        for check in checks
        if check.triggered and check.signal
    ]


def summarize(checks: Iterable[Check]) -> Dict[str, object]:
    checks = list(checks)
    failed = [check for check in checks if check.triggered]
    return {
        "clean": not failed,
        "checks": len(checks),
        "failed": [check.as_dict() for check in failed],
        "critical": sum(1 for check in failed if check.severity == "critical"),
    }


__all__ = [
    "Check",
    "FRIDA_PORTS",
    "check_debug_modules",
    "check_frida_maps",
    "check_frida_ports",
    "check_preload",
    "check_python_trace",
    "check_tracer",
    "collect",
    "summarize",
    "to_signals",
]
