"""Canary tokens and zero-width watermarking (the data layer).

Two mechanisms, both cheap and both about *attribution* rather than access
control:

**Canary tokens** are unique strings served to suspicious clients inside
synthetic responses.  They have no other purpose in the product, so if one ever
comes back to us -- in a support ticket, a scraped dataset, a competitor's
site, a login form -- we know exactly which session leaked it and when.

**Zero-width watermarks** encode an owner label into invisible characters
appended to a text field.  Copy-pasting a leaked record carries the watermark
with it, and ``extract`` recovers the label without any external lookup.

Neither mechanism degrades legitimate data: watermarks are invisible, canaries
only ever appear in decoy payloads.
"""

from __future__ import annotations

import hashlib
import json
import re
import secrets
import threading
import time
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional

CANARY_PREFIX = "cnry_"
TOKEN_RE = re.compile(r"cnry_[0-9a-f]{32}")
ZW_MARK = "\u2060"          # word joiner: framing only
ZW_ZERO = "\u200b"          # zero width space: bit 0
ZW_ONE = "\u200c"           # zero width non-joiner: bit 1
ZW_BITS_RE = re.compile("\u2060([\u200b\u200c]+)\u2060")
MAX_LABEL_BYTES = 24


# --------------------------------------------------------------------------
# canary tokens
# --------------------------------------------------------------------------
@dataclass
class Canary:
    token: str
    owner: str
    created: float = 0.0
    meta: Dict[str, object] = field(default_factory=dict)

    def as_dict(self) -> Dict[str, object]:
        return {"token": self.token, "owner": self.owner, "created": self.created, "meta": self.meta}


class CanaryRegistry:
    """In-memory registry of issued canaries with optional JSONL persistence."""

    def __init__(self, ttl_seconds: int = 60 * 60 * 24 * 90, path: str = "") -> None:
        self.ttl = int(ttl_seconds)
        self.path = path
        self._items: Dict[str, Canary] = {}
        self._lock = threading.Lock()

    def issue(self, owner: str, meta: Optional[Dict[str, object]] = None,
              now: Optional[float] = None) -> Canary:
        stamp = time.time() if now is None else now
        token = CANARY_PREFIX + secrets.token_hex(16)
        canary = Canary(token=token, owner=str(owner)[:64], created=stamp, meta=dict(meta or {}))
        with self._lock:
            self._items[token] = canary
        self._persist(canary)
        return canary

    def get(self, token: str) -> Optional[Canary]:
        with self._lock:
            return self._items.get(token)

    def find(self, text: str) -> List[Canary]:
        """Return registry entries that appear in *text*."""
        found: List[Canary] = []
        for match in TOKEN_RE.finditer(text or ""):
            entry = self.get(match.group(0))
            if entry is not None:
                found.append(entry)
        return found

    def unknown_tokens(self, text: str) -> List[str]:
        """Canary-shaped strings we did not issue (possible forgery/probing)."""
        return [m.group(0) for m in TOKEN_RE.finditer(text or "") if self.get(m.group(0)) is None]

    def expire(self, now: Optional[float] = None) -> int:
        stamp = time.time() if now is None else now
        with self._lock:
            doomed = [t for t, c in self._items.items() if stamp - c.created > self.ttl]
            for token in doomed:
                del self._items[token]
            return len(doomed)

    def __len__(self) -> int:
        return len(self._items)

    def _persist(self, canary: Canary) -> None:
        if not self.path:
            return
        try:
            with open(self.path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(canary.as_dict(), ensure_ascii=False) + "\n")
        except OSError:
            pass  # never let telemetry break a request path


# --------------------------------------------------------------------------
# zero-width watermark
# --------------------------------------------------------------------------
def _label_bytes(label: str) -> bytes:
    return str(label).encode("utf-8")[:MAX_LABEL_BYTES]


def embed(text: str, label: str) -> str:
    """Append an invisible watermark encoding *label* to *text*."""
    raw = _label_bytes(label)
    bits = "".join(f"{byte:08b}" for byte in raw)
    payload = "".join(ZW_ONE if bit == "1" else ZW_ZERO for bit in bits)
    return f"{text}{ZW_MARK}{payload}{ZW_MARK}"


def extract(text: str) -> Optional[str]:
    """Recover the label embedded by :func:`embed` (or ``None``)."""
    if not text:
        return None
    matches = ZW_BITS_RE.findall(text)
    if not matches:
        return None
    bits = matches[-1]
    if not bits or len(bits) % 8:
        return None
    raw = bytes(int(bits[i : i + 8].replace(ZW_ZERO, "0").replace(ZW_ONE, "1"), 2)
                for i in range(0, len(bits), 8))
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return None


def strip(text: str) -> str:
    """Remove every watermark from *text* (used before storing user input)."""
    if not text:
        return text
    return ZW_BITS_RE.sub("", text)


def fingerprint_of(text: str) -> str:
    """Short stable digest, for comparing leaked copies without storing them."""
    return hashlib.sha256((text or "").encode("utf-8")).hexdigest()[:16]


__all__ = [
    "CANARY_PREFIX",
    "Canary",
    "CanaryRegistry",
    "TOKEN_RE",
    "embed",
    "extract",
    "fingerprint_of",
    "strip",
]
