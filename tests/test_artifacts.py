"""Artifact audit tests."""

from __future__ import annotations

import os
import tempfile
import unittest

from fightre.artifacts import audit


def write(root: str, name: str, content: str) -> str:
    path = os.path.join(root, name)
    os.makedirs(os.path.dirname(path), exist_ok=True) if os.path.dirname(path) else None
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(content)
    return path


class ArtifactAuditTests(unittest.TestCase):
    def test_empty_directory_is_clean(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            write(root, "index.html", "<html><body>hello</body></html>")
            report = audit(root)
            self.assertEqual(report.findings, [])
            self.assertEqual(report.score, 0.0)
            self.assertIn("hardened", report.verdict)

    def test_leaky_bundle_is_flagged(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            write(root, "assets/app.js", "console.log(1);\n//# sourceMappingURL=app.js.map\n")
            write(root, "assets/app.js.map", "{}")
            write(root, "config.json", '{"api_key": "sk_live_abcdefghijklmnop1234"}')
            write(root, "keys.pem", "-----BEGIN PRIVATE KEY-----\nMIIB\n-----END PRIVATE KEY-----\n")
            write(root, "settings.yaml", "db: https://db.internal:5432/app")
            write(root, ".env", "SECRET=abc\n")
            report = audit(root)
            rules = {f.rule for f in report.findings}
            self.assertIn("sourcemap", rules)
            self.assertIn("sourcemap-reference", rules)
            self.assertIn("generic-secret", rules)
            self.assertIn("private-key", rules)
            self.assertIn("internal-host", rules)
            self.assertIn("dotenv", rules)
            self.assertGreaterEqual(report.score, 60)
            self.assertEqual(report.by_severity["critical"] >= 2, True)

    def test_markdown_and_json_render(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            write(root, "app.js.map", "{}")
            report = audit(root)
            markdown = report.to_markdown()
            self.assertIn("sourcemap", markdown)
            self.assertIn("exposure", markdown.lower())
            payload = report.as_dict()
            self.assertEqual(payload["score"], report.score)
            self.assertIn("findings", payload)

    def test_skip_directories(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            write(root, "node_modules/pkg/app.js.map", "{}")
            report = audit(root)
            self.assertEqual(report.findings, [])

    def test_missing_directory_raises(self) -> None:
        with self.assertRaises(NotADirectoryError):
            audit("/nonexistent/path/for/fightre")


if __name__ == "__main__":
    unittest.main()
