"""Build manifests: detect tampering in distributed builds.

Client-side checks can be patched. A signed manifest moves the question from
"is this binary honest?" to "does this file tree match what we built?". Ship
``build.manifest.json`` next to a desktop or on-prem build, verify it at
startup, and a modified file is detectable even if the check itself lives in
Python (an attacker must patch the verifier too -- raising the bar, not closing
the door).

The manifest is an HMAC-signed inventory: relative path, size, SHA-256. It
contains no secrets, so it is safe to publish alongside the artifact; the key
stays with the build system.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple

MANIFEST_VERSION = 1
_CHUNK = 1024 * 1024


@dataclass
class Entry:
    path: str
    size: int
    sha256: str

    def as_dict(self) -> Dict[str, object]:
        return {"path": self.path, "size": self.size, "sha256": self.sha256}


@dataclass
class Manifest:
    root: str
    created: float
    entries: List[Entry] = field(default_factory=list)
    key_id: str = ""
    signature: str = ""
    version: int = MANIFEST_VERSION

    # -- serialisation -----------------------------------------------------
    def payload(self) -> Dict[str, object]:
        return {
            "version": self.version,
            "created": round(self.created, 3),
            "root": self.root,
            "key_id": self.key_id,
            "entries": [[entry.path, entry.size, entry.sha256] for entry in self.entries],
        }

    def canonical(self) -> bytes:
        return json.dumps(self.payload(), sort_keys=True, separators=(",", ":")).encode("utf-8")

    def as_dict(self) -> Dict[str, object]:
        data = self.payload()
        data["signature"] = self.signature
        return data

    def to_json(self) -> str:
        return json.dumps(self.as_dict(), indent=2, ensure_ascii=False)

    @classmethod
    def from_dict(cls, data: Dict[str, object]) -> "Manifest":
        entries = [
            Entry(path=str(path), size=int(size), sha256=str(digest))
            for path, size, digest in (data.get("entries") or [])  # type: ignore[misc]
        ]
        return cls(
            root=str(data.get("root", "")),
            created=float(data.get("created", 0.0)),
            entries=entries,
            key_id=str(data.get("key_id", "")),
            signature=str(data.get("signature", "")),
            version=int(data.get("version", MANIFEST_VERSION)),
        )

    @classmethod
    def load(cls, path: str) -> "Manifest":
        with open(path, "r", encoding="utf-8") as handle:
            return cls.from_dict(json.load(handle))

    def save(self, path: str) -> None:
        with open(path, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(self.to_json())


@dataclass
class VerifyResult:
    ok: bool
    signature_ok: bool
    missing: List[str] = field(default_factory=list)
    modified: List[str] = field(default_factory=list)
    added: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    def as_dict(self) -> Dict[str, object]:
        return {
            "ok": self.ok,
            "signature_ok": self.signature_ok,
            "missing": self.missing,
            "modified": self.modified,
            "added": self.added,
            "errors": self.errors,
        }


def file_digest(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        while True:
            chunk = handle.read(_CHUNK)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def build_manifest(
    root: str,
    exclude: Sequence[str] = (".git", "node_modules", "__pycache__", ".venv"),
    max_files: int = 50_000,
    now: Optional[float] = None,
) -> Manifest:
    root = os.path.abspath(root)
    if not os.path.isdir(root):
        raise NotADirectoryError(root)
    excluded = {name.lower() for name in exclude}
    entries: List[Entry] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d.lower() not in excluded]
        for name in sorted(filenames):
            if len(entries) >= max_files:
                break
            full = os.path.join(dirpath, name)
            if os.path.islink(full):
                continue
            try:
                size = os.path.getsize(full)
                digest = file_digest(full)
            except OSError:
                continue
            entries.append(
                Entry(path=os.path.relpath(full, root).replace(os.sep, "/"), size=size, sha256=digest)
            )
    entries.sort(key=lambda entry: entry.path)
    return Manifest(root=root, created=time.time() if now is None else now, entries=entries)


def sign(manifest: Manifest, key_id: str, secret: str) -> Manifest:
    if not secret:
        raise ValueError("manifest secret must not be empty")
    manifest.key_id = str(key_id)
    manifest.signature = hmac.new(
        secret.encode("utf-8"), manifest.canonical(), hashlib.sha256
    ).hexdigest()
    return manifest


def verify(
    manifest: Manifest,
    root: Optional[str] = None,
    secret: Optional[str] = None,
    ignore: Sequence[str] = (),
) -> VerifyResult:
    result = VerifyResult(ok=True, signature_ok=True)
    if secret is not None:
        expected = hmac.new(secret.encode("utf-8"), manifest.canonical(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, manifest.signature or ""):
            result.signature_ok = False
            result.ok = False
            result.errors.append("signature mismatch")
    elif not manifest.signature:
        result.signature_ok = False
        result.errors.append("manifest is not signed")

    target = os.path.abspath(root or manifest.root)
    expected_files: Dict[str, Entry] = {entry.path: entry for entry in manifest.entries}
    for entry in manifest.entries:
        full = os.path.join(target, entry.path)
        if not os.path.isfile(full):
            result.missing.append(entry.path)
            continue
        try:
            if os.path.getsize(full) != entry.size or file_digest(full) != entry.sha256:
                result.modified.append(entry.path)
        except OSError:
            result.missing.append(entry.path)

    excluded = {".git", "node_modules", "__pycache__", ".venv"}
    for dirpath, dirnames, filenames in os.walk(target):
        dirnames[:] = [d for d in dirnames if d.lower() not in excluded]
        for name in filenames:
            full = os.path.join(dirpath, name)
            rel = os.path.relpath(full, target).replace(os.sep, "/")
            if rel not in expected_files and rel not in ignore:
                result.added.append(rel)

    result.missing.sort()
    result.modified.sort()
    result.added.sort()
    if result.missing or result.modified:
        result.ok = False
    return result


def verify_file(
    manifest_path: str, root: Optional[str] = None, secret: Optional[str] = None
) -> VerifyResult:
    ignore = (os.path.basename(manifest_path),)
    return verify(Manifest.load(manifest_path), root=root, secret=secret, ignore=ignore)


__all__ = [
    "Entry",
    "MANIFEST_VERSION",
    "Manifest",
    "VerifyResult",
    "build_manifest",
    "file_digest",
    "sign",
    "verify",
    "verify_file",
]
