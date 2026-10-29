"""Canary token and watermark tests."""

from __future__ import annotations

import unittest

from fightre.canary import CanaryRegistry, TOKEN_RE, embed, extract, fingerprint_of, strip


class CanaryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.registry = CanaryRegistry()

    def test_issue_and_find(self) -> None:
        canary = self.registry.issue("tenant-1", {"path": "/api"})
        self.assertRegex(canary.token, TOKEN_RE)
        found = self.registry.find(f"leaked dump contains {canary.token} here")
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].owner, "tenant-1")
        self.assertEqual(found[0].meta["path"], "/api")

    def test_unknown_tokens_are_not_attributed(self) -> None:
        fake = "cnry_" + "a" * 32
        self.assertEqual(self.registry.find(fake), [])
        self.assertEqual(self.registry.unknown_tokens(fake), [fake])

    def test_tokens_are_unique(self) -> None:
        tokens = {self.registry.issue("t").token for _ in range(50)}
        self.assertEqual(len(tokens), 50)

    def test_expiry(self) -> None:
        self.registry.issue("t", now=1000)
        self.assertEqual(self.registry.expire(now=1000 + 10), 0)
        self.assertEqual(self.registry.expire(now=1000 + 10**9), 1)
        self.assertEqual(len(self.registry), 0)


class WatermarkTests(unittest.TestCase):
    def test_roundtrip(self) -> None:
        marked = embed("quarterly report", "tenant-42")
        self.assertNotEqual(marked, "quarterly report")
        self.assertEqual(extract(marked), "tenant-42")
        self.assertTrue(marked.startswith("quarterly report"))

    def test_watermark_is_invisible(self) -> None:
        marked = embed("data", "tenant-1")
        visible = "".join(ch for ch in marked if ch not in "\u200b\u200c\u2060")
        self.assertEqual(visible, "data")

    def test_strip_removes_watermark(self) -> None:
        marked = embed("data", "tenant-1")
        self.assertEqual(strip(marked), "data")
        self.assertIsNone(extract(strip(marked)))

    def test_no_watermark_returns_none(self) -> None:
        self.assertIsNone(extract("plain text"))
        self.assertIsNone(extract(""))

    def test_fingerprint_is_stable(self) -> None:
        self.assertEqual(fingerprint_of("abc"), fingerprint_of("abc"))
        self.assertNotEqual(fingerprint_of("abc"), fingerprint_of("abd"))


if __name__ == "__main__":
    unittest.main()
