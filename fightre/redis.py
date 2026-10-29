"""A minimal RESP2 client, so shared state costs no dependency.

FightRE's promise is that ``pip install fightre`` pulls nothing else. Multi-worker
deployments need shared counters and nonces, so instead of depending on a Redis
driver we speak the wire protocol directly. The subset implemented here is the
subset the stores use: ``PING``, ``AUTH``, ``SELECT``, ``SET .. NX EX``, ``GET``,
``DEL``, ``INCR``, ``EXPIRE``, ``SCARD``, ``SADD``.

It is deliberately boring: one connection per command from a small idle pool, a
bounded timeout, and a hard rule that a broken socket is discarded rather than
reused. A server error reply (``-ERR ...``) does not poison the connection.
"""

from __future__ import annotations

import socket
import threading
from typing import Any, List, Optional, Tuple

DEFAULT_TIMEOUT = 1.0


class RedisError(Exception):
    """Base class for Redis failures."""


class RedisServerError(RedisError):
    """The server answered with an error reply; the connection stays usable."""


class RedisProtocolError(RedisError):
    """Malformed or truncated reply; the connection must be discarded."""


class RedisConnection:
    """One TCP connection speaking RESP2."""

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 6379,
        db: int = 0,
        password: str = "",
        timeout: float = DEFAULT_TIMEOUT,
    ) -> None:
        self.host = host
        self.port = int(port)
        self.db = int(db)
        self.password = password
        self.timeout = float(timeout)
        self._sock: Optional[socket.socket] = None
        self._reader = None

    # -- lifecycle ---------------------------------------------------------
    def connect(self) -> "RedisConnection":
        self._sock = socket.create_connection((self.host, self.port), timeout=self.timeout)
        self._sock.settimeout(self.timeout)
        self._sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self._reader = self._sock.makefile("rb")
        if self.password:
            self.execute("AUTH", self.password)
        if self.db:
            self.execute("SELECT", str(self.db))
        return self

    def close(self) -> None:
        try:
            if self._reader is not None:
                self._reader.close()
        except OSError:
            pass
        try:
            if self._sock is not None:
                self._sock.close()
        except OSError:
            pass
        self._sock = None
        self._reader = None

    def __enter__(self) -> "RedisConnection":
        return self.connect()

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    # -- protocol ----------------------------------------------------------
    def execute(self, *args: object) -> Any:
        if self._sock is None:
            self.connect()
        payload = self._encode(args)
        try:
            self._sock.sendall(payload)
        except OSError as exc:  # pragma: no cover - network failure
            raise RedisProtocolError(str(exc)) from exc
        return self._read_reply()

    @staticmethod
    def _encode(args: Tuple[object, ...]) -> bytes:
        parts: List[bytes] = [b"*%d\r\n" % len(args)]
        for arg in args:
            raw = arg if isinstance(arg, bytes) else str(arg).encode("utf-8")
            parts.append(b"$%d\r\n" % len(raw))
            parts.append(raw + b"\r\n")
        return b"".join(parts)

    def _read_line(self) -> bytes:
        assert self._reader is not None
        line = self._reader.readline()
        if not line:
            raise RedisProtocolError("connection closed")
        return line

    def _read_reply(self) -> Any:
        line = self._read_line()
        kind, payload = line[:1], line[1:-2]
        if kind == b"+":
            return payload.decode("utf-8", "replace")
        if kind == b"-":
            raise RedisServerError(payload.decode("utf-8", "replace"))
        if kind == b":":
            return int(payload)
        if kind == b"$":
            length = int(payload)
            if length == -1:
                return None
            assert self._reader is not None
            data = self._reader.read(length + 2)
            if len(data) != length + 2:
                raise RedisProtocolError("truncated bulk reply")
            return data[:-2]
        if kind == b"*":
            count = int(payload)
            if count == -1:
                return None
            return [self._read_reply() for _ in range(count)]
        raise RedisProtocolError(f"unexpected reply prefix {kind!r}")


class RedisClient:
    """Thread-safe pool of RESP connections with error accounting."""

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 6379,
        db: int = 0,
        password: str = "",
        timeout: float = DEFAULT_TIMEOUT,
        max_connections: int = 8,
        prefix: str = "fightre",
    ) -> None:
        self._host = host
        self._port = int(port)
        self._db = int(db)
        self._password = password
        self._timeout = float(timeout)
        self._max = max(1, int(max_connections))
        self.prefix = prefix.strip(":") or "fightre"
        self._idle: List[RedisConnection] = []
        self._lock = threading.Lock()
        self._errors = 0

    # -- introspection -----------------------------------------------------
    @property
    def errors(self) -> int:
        return self._errors

    def key(self, *parts: object) -> str:
        return ":".join([self.prefix] + [str(p) for p in parts])

    # -- command path ------------------------------------------------------
    def command(self, *args: object) -> Any:
        try:
            connection = self._acquire()
        except OSError as exc:
            self._errors += 1
            raise RedisProtocolError(f"connect failed: {exc}") from exc
        try:
            result = connection.execute(*args)
        except RedisServerError:
            self._release(connection)  # connection is still healthy
            self._errors += 1
            raise
        except (OSError, RedisProtocolError, ValueError) as exc:
            self._discard(connection)
            self._errors += 1
            raise RedisProtocolError(str(exc)) from exc
        else:
            self._release(connection)
            return result

    def ping(self) -> bool:
        try:
            return self.command("PING") in ("PONG", b"PONG")
        except RedisError:
            return False

    # -- pool --------------------------------------------------------------
    def _acquire(self) -> RedisConnection:
        with self._lock:
            if self._idle:
                return self._idle.pop()
        return RedisConnection(
            self._host, self._port, self._db, self._password, self._timeout
        ).connect()

    def _release(self, connection: RedisConnection) -> None:
        with self._lock:
            if len(self._idle) < self._max:
                self._idle.append(connection)
                return
        connection.close()

    @staticmethod
    def _discard(connection: RedisConnection) -> None:
        connection.close()

    def close(self) -> None:
        with self._lock:
            idle, self._idle = self._idle, []
        for connection in idle:
            connection.close()


__all__ = [
    "DEFAULT_TIMEOUT",
    "RedisClient",
    "RedisConnection",
    "RedisError",
    "RedisProtocolError",
    "RedisServerError",
]
