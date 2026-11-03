"""A tiny in-process Redis stand-in for tests.

It speaks enough RESP2 to exercise FightRE's client and stores over a real
socket: PING, AUTH, SELECT, SET (NX/EX), GET, DEL, INCR, EXPIRE, SADD, SCARD.
It is not a Redis implementation -- just enough surface to prove that the
protocol code, key layout, TTLs and cross-"worker" sharing work.
"""

from __future__ import annotations

import socket
import threading
import time
from typing import Dict, Optional, Set


def _read_line(handle) -> Optional[bytes]:
    line = handle.readline()
    if not line:
        return None
    return line


def read_command(handle) -> Optional[list]:
    line = _read_line(handle)
    if line is None:
        return None
    if not line.startswith(b"*"):
        return None
    count = int(line[1:-2])
    args = []
    for _ in range(count):
        header = _read_line(handle)
        if header is None or not header.startswith(b"$"):
            return None
        length = int(header[1:-2])
        payload = handle.read(length + 2)
        args.append(payload[:-2])
    return args


def simple(text: str) -> bytes:
    return b"+" + text.encode() + b"\r\n"


def error(text: str) -> bytes:
    return b"-" + text.encode() + b"\r\n"


def integer(value: int) -> bytes:
    return b":%d\r\n" % int(value)


def bulk(value: bytes) -> bytes:
    return b"$%d\r\n%s\r\n" % (len(value), value)


def nil() -> bytes:
    return b"$-1\r\n"


class FakeRedisServer:
    def __init__(self) -> None:
        self._listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._listener.bind(("127.0.0.1", 0))
        self._listener.listen(32)
        self.port = int(self._listener.getsockname()[1])
        self._values: Dict[bytes, bytes] = {}
        self._sets: Dict[bytes, Set[bytes]] = {}
        self._expiry: Dict[bytes, float] = {}
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None

    # -- lifecycle ---------------------------------------------------------
    def start(self) -> "FakeRedisServer":
        self._thread = threading.Thread(target=self._accept_loop, daemon=True)
        self._thread.start()
        return self

    def stop(self) -> None:
        self._stop.set()
        try:
            self._listener.close()
        except OSError:
            pass

    def __enter__(self) -> "FakeRedisServer":
        return self.start()

    def __exit__(self, *exc_info: object) -> None:
        self.stop()

    # -- server loop -------------------------------------------------------
    def _accept_loop(self) -> None:
        while not self._stop.is_set():
            try:
                connection, _ = self._listener.accept()
            except OSError:
                break
            threading.Thread(target=self._serve, args=(connection,), daemon=True).start()

    def _serve(self, connection: socket.socket) -> None:
        handle = connection.makefile("rb")
        try:
            while True:
                command = read_command(handle)
                if command is None:
                    break
                args = [part.decode("utf-8", "replace") for part in command]
                connection.sendall(self._dispatch(args))
        except OSError:
            pass
        finally:
            try:
                handle.close()
                connection.close()
            except OSError:
                pass

    # -- commands ----------------------------------------------------------
    def _get(self, key: bytes) -> Optional[bytes]:
        expires = self._expiry.get(key)
        if expires is not None and expires <= time.time():
            self._values.pop(key, None)
            self._sets.pop(key, None)
            self._expiry.pop(key, None)
            return None
        return self._values.get(key)

    def _set(self, key: bytes, value: bytes) -> None:
        self._values[key] = value
        self._sets.pop(key, None)

    def _dispatch(self, args: list) -> bytes:
        if not args:
            return error("empty command")
        name = args[0].upper()
        with self._lock:
            if name == "PING":
                return simple("PONG")
            if name in ("AUTH", "SELECT"):
                return simple("OK")
            if name == "SET":
                if len(args) < 3:
                    return error("wrong number of arguments")
                key, value = args[1].encode(), args[2].encode()
                options = [part.upper() for part in args[3:]]
                if "NX" in options and self._get(key) is not None:
                    return nil()
                self._set(key, value)
                if "EX" in options:
                    index = options.index("EX")
                    self._expiry[key] = time.time() + int(args[3 + index + 1])
                return simple("OK")
            if name == "GET":
                value = self._get(args[1].encode())
                return bulk(value) if value is not None else nil()
            if name == "DEL":
                removed = 0
                for raw in args[1:]:
                    key = raw.encode()
                    if key in self._values or key in self._sets:
                        removed += 1
                    self._values.pop(key, None)
                    self._sets.pop(key, None)
                    self._expiry.pop(key, None)
                return integer(removed)
            if name == "INCR":
                key = args[1].encode()
                current = int(self._get(key) or b"0")
                self._set(key, str(current + 1).encode())
                return integer(current + 1)
            if name == "EXPIRE":
                key = args[1].encode()
                if key not in self._values and key not in self._sets:
                    return integer(0)
                self._expiry[key] = time.time() + int(args[2])
                return integer(1)
            if name == "SADD":
                key = args[1].encode()
                bucket = self._sets.setdefault(key, set())
                before = len(bucket)
                bucket.add(args[2].encode())
                return integer(len(bucket) - before)
            if name == "SCARD":
                return integer(len(self._sets.get(args[1].encode(), set())))
            if name == "FLUSHALL":
                self._values.clear()
                self._sets.clear()
                self._expiry.clear()
                return simple("OK")
        return error(f"unknown command {name}")


__all__ = ["FakeRedisServer", "read_command"]
