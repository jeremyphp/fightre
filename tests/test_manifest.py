"""Build manifest signing and tamper detection tests."""

from __future__ import annotations

import json
import os
import tempfile
import unittest

from fightre.manifest import (
    Manifest,
    build_manifest,
    file_digest,
    sign,
    verify,
    verify_file,
)


def write(root: str, name: str, content: str) -> str:
    path = os.path.join(root, name)
    os.makedirs(os.path.dirname(path), exist_ok=True) if os.path.dirname(path) else None
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(content)
    return path


class ManifestTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = self.tmp.name
        write(self.root, "app.py", "print('hi')\n")
        write(self.root, "static/app.js", "console.log(1)\n")
        self.secret = "manifest-test-secret"

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_build_and_verify(self) -> None:
        manifest = build_manifest(self.root)
        self.assertEqual(len(manifest.entries), 2)
        self.assertTrue(all(len(entry.sha256) == 64 for entry in manifest.entries))
        sign(manifest, "release-key", self.secret)
        result = verify(manifest, secret=self.secret)
        self.assertTrue(result.ok, result.errors)
        self.assertTrue(result.signature_ok)
        self.assertEqual(result.modified, [])

    def test_modified_file_detected(self) -> None:
        manifest = build_manifest(self.root)
        sign(manifest, "release-key", self.secret)
        write(self.root, "app.py", "print('tampered')\n")
        result = verify(manifest, secret=self.secret)
        self.assertFalse(result.ok)
        self.assertEqual(result.modified, ["app.py"])

    def test_missing_and_added_files(self) -> None:
        manifest = build_manifest(self.root)
        sign(manifest, "release-key", self.secret)
        os.remove(os.path.join(self.root, "static", "app.js"))
        write(self.root, "backdoor.py", "import os\n")
        result = verify(manifest, secret=self.secret)
        self.assertIn("static/app.js", result.missing)
        self.assertIn("backdoor.py", result.added)
        self.assertFalse(result.ok)

    def test_wrong_secret(self) -> None:
        manifest = build_manifest(self.root)
        sign(manifest, "release-key", self.secret)
        result = verify(manifest, secret="wrong")
        self.assertFalse(result.signature_ok)
        self.assertFalse(result.ok)

    def test_unsigned_manifest(self) -> None:
        manifest = build_manifest(self.root)
        result = verify(manifest)
        self.assertFalse(result.signature_ok)
        self.assertIn("manifest is not signed", result.errors)

    def test_save_load_and_verify_file(self) -> None:
        manifest = build_manifest(self.root)
        sign(manifest, "release-key", self.secret)
        path = os.path.join(self.root, "build.manifest.json")
        manifest.save(path)
        loaded = Manifest.load(path)
        self.assertEqual(loaded.signature, manifest.signature)
        self.assertEqual(len(loaded.entries), 2)
        self.assertTrue(verify_file(path, secret=self.secret).ok)

    def test_manifest_json_shape(self) -> None:
        manifest = build_manifest(self.root)
        sign(manifest, "release-key", self.secret)
        payload = json.loads(manifest.to_json())
        self.assertEqual(payload["version"], 1)
        self.assertIn("signature", payload)
        self.assertEqual(payload["entries"][0][0], "app.py")

    def test_file_digest_stable(self) -> None:
        path = os.path.join(self.root, "app.py")
        self.assertEqual(file_digest(path), file_digest(path))


if __name__ == "__main__":
    unittest.main()
