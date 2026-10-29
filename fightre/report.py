"""Audit trail: one JSONL record per decision, plus an in-memory ring.

Principles:

* the record explains *why* (signal names and weights), because an
  unexplainable security decision is a support ticket;
* raw client identifiers are hashed with a daily-rotating salt, so the log is
  useful for correlation and useless for surveillance;
* writing a log never raises into the request path.
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import time
from collections import Counter, deque
from dataclasses import dataclass, field
from typing import Deque, Dict, Iterable, List, Optional

from .policy import Decision
from .scoring import RiskReport


def _identity_hash(identity: str, salt: bytes) -> str:
    return hashlib.sha256(salt + identity.encode("utf-8")).hexdigest()[:16]


class Redactor:
    """Hashes client identities with a salt that rotates once per day."""

    def __init__(self, salt: Optional[bytes] = None) -> None:
        self._salt = salt or secrets.token_bytes(16)
        self._day = time.strftime("%Y-%m-%d")

    @property
    def salt(self) -> bytes:
        today = time.strftime("%Y-%m-%d")
        if today != self._day:
            self._salt = secrets.token_bytes(16)
            self._day = today
        return self._salt

    def identity(self, value: str) -> str:
        return _identity_hash(value or "", self.salt)


@dataclass
class AuditEvent:
    ts: float
    request_id: str
    identity: str
    method: str
    path: str
    score: float
    action: str
    signals: List[str] = field(default_factory=list)
    detail: Dict[str, object] = field(default_factory=dict)

    def as_dict(self) -> Dict[str, object]:
        return {
            "ts": round(self.ts, 3),
            "request_id": self.request_id,
            "identity": self.identity,
            "method": self.method,
            "path": self.path,
            "score": round(self.score, 2),
            "action": self.action,
            "signals": self.signals,
            "detail": self.detail,
        }


class AuditLog:
    """JSONL sink plus a bounded ring buffer for ``/healthz`` style summaries."""

    def __init__(self, path: str = "", capacity: int = 512, redact: bool = True) -> None:
        self.path = path
        self.redactor = Redactor()
        self.redact = redact
        self._ring: Deque[AuditEvent] = deque(maxlen=max(16, int(capacity)))

    def record(
        self,
        request_id: str,
        identity: str,
        method: str,
        path: str,
        report: RiskReport,
        decision: Decision,
        detail: Optional[Dict[str, object]] = None,
    ) -> AuditEvent:
        event = AuditEvent(
            ts=time.time(),
            request_id=request_id,
            identity=self.redactor.identity(identity) if self.redact else identity,
            method=method,
            path=path,
            score=report.score,
            action=decision.action.value,
            signals=[s.name for s in report.signals],
            detail=dict(detail or {}),
        )
        self._ring.append(event)
        if self.path:
            try:
                directory = os.path.dirname(os.path.abspath(self.path))
                if directory:
                    os.makedirs(directory, exist_ok=True)
                with open(self.path, "a", encoding="utf-8") as fh:
                    fh.write(json.dumps(event.as_dict(), ensure_ascii=False) + "\n")
            except OSError:
                pass
        return event

    def recent(self, limit: int = 20) -> List[Dict[str, object]]:
        items = list(self._ring)[-max(1, limit):]
        return [event.as_dict() for event in items]

    def summary(self) -> Dict[str, object]:
        actions = Counter(event.action for event in self._ring)
        signals: Counter = Counter()
        for event in self._ring:
            signals.update(event.signals)
        return {
            "decisions": len(self._ring),
            "by_action": dict(actions),
            "top_signals": dict(signals.most_common(10)),
        }


__all__ = ["AuditEvent", "AuditLog", "Redactor"]
