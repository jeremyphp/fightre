"""TLS/HTTP2 fingerprint and request-signing tests."""

from __future__ import annotations

import time
import unittest

from fightre.fingerprint import (
    edge_signature,
    h2_digest,
    ja3_digest,
    ja3_string,
    known_blocked,
    normalize_ja3,
    verify_edge_signature,
)
from fightre.signing import RequestSigner


class FingerprintTests(unittest.TestCase):
    def test_ja3_string_shape(self) -> None:
        value = ja3_string(771, [4865, 4866], [0, 23], [29, 23], [0])
        self.assertEqual(value, "771,4865-4866,0-23,29-23,0")

    def test_ja3_digest_is_md5_hex(self) -> None:
        digest = ja3_digest(771, [4865], [0], [29], [0])
        self.assertEqual(len(digest), 32)
        self.assertRegex(digest, r"^[0-9a-f]{32}$")

    def test_normalize_accepts_hash_or_string(self) -> None:
        digest = ja3_digest(771, [4865], [0], [29], [0])
        self.assertEqual(normalize_ja3(digest), digest)
        self.assertEqual(normalize_ja3("771,4865,0,29,0"), ja3_digest(771, [4865], [0], [29], [0]))
        self.assertEqual(normalize_ja3(""), "")

    def test_h2_digest_is_deterministic(self) -> None:
        first = h2_digest("1:65536", "15663105", "0:0:0:1", "m,a s")
        second = h2_digest("1:65536", "15663105", "0:0:0:1", "m,a s")
        self.assertEqual(first, second)
        self.assertNotEqual(first, h2_digest("", "", "", ""))

    def test_edge_signature_verification(self) -> None:
        ts = str(int(time.time()))
        signature = edge_signature("edge-secret", ts, "771,4865", "abcd", "1.2.3.4")
        self.assertTrue(
            verify_edge_signature("edge-secret", ts, signature, "771,4865", "abcd", "1.2.3.4")
        )
        self.assertFalse(
            verify_edge_signature("edge-secret", ts, signature, "771,4865", "abcd", "9.9.9.9")
        )

    def test_edge_signature_rejects_stale_timestamp(self) -> None:
        old = str(int(time.time()) - 3600)
        signature = edge_signature("edge-secret", old, "j", "h", "1.2.3.4")
        self.assertFalse(verify_edge_signature("edge-secret", old, signature, "j", "h", "1.2.3.4"))

    def test_blocklist(self) -> None:
        digest = ja3_digest(771, [4865], [0], [29], [0])
        self.assertTrue(known_blocked(digest, [digest]))
        self.assertFalse(known_blocked("771,1,2,3,4", [digest]))


class SigningTests(unittest.TestCase):
    def setUp(self) -> None:
        self.signer = RequestSigner({"partner-a": "secret-a"}, clock_skew=60)

    def test_signature_verifies(self) -> None:
        auth, signature = self.signer.sign("partner-a", "POST", "/api/x", b'{"a":1}')
        headers = {"authorization": auth, "x-fightre-sign": signature}
        result = self.signer.verify("POST", "/api/x", headers, b'{"a":1}')
        self.assertTrue(result.ok)
        self.assertEqual(result.key_id, "partner-a")

    def test_replay_is_detected(self) -> None:
        auth, signature = self.signer.sign("partner-a", "POST", "/api/x", b"{}")
        headers = {"authorization": auth, "x-fightre-sign": signature}
        self.assertTrue(self.signer.verify("POST", "/api/x", headers, b"{}").ok)
        second = self.signer.verify("POST", "/api/x", headers, b"{}")
        self.assertFalse(second.ok)
        self.assertEqual(second.reason, "replay")
        self.assertIn("app.replay_detected", {s.name for s in second.signals})

    def test_payload_binding(self) -> None:
        auth, signature = self.signer.sign("partner-a", "POST", "/api/x", b'{"a":1}')
        headers = {"authorization": auth, "x-fightre-sign": signature}
        result = self.signer.verify("POST", "/api/x", headers, b'{"a":2}')
        self.assertFalse(result.ok)
        self.assertEqual(result.reason, "bad-signature")

    def test_clock_skew(self) -> None:
        auth, signature = self.signer.sign("partner-a", "GET", "/x", b"", ts=1000)
        headers = {"authorization": auth, "x-fightre-sign": signature}
        self.assertEqual(self.signer.verify("GET", "/x", headers).reason, "clock-skew")

    def test_unknown_key(self) -> None:
        headers = {"authorization": "FightRE-Key ghost", "x-fightre-sign": "v1:1:a:b"}
        self.assertEqual(self.signer.verify("GET", "/x", headers).reason, "unknown-key")

    def test_absent_signature(self) -> None:
        self.assertEqual(self.signer.verify("GET", "/x", {}).reason, "absent")

    def test_malformed_header(self) -> None:
        headers = {"authorization": "FightRE-Key partner-a", "x-fightre-sign": "v2:1:2:3"}
        self.assertEqual(self.signer.verify("GET", "/x", headers).reason, "malformed")


if __name__ == "__main__":
    unittest.main()
