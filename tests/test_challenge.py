"""Proof-of-work challenge tests."""

from __future__ import annotations

import time
import unittest

from fightre.challenge import (
    ChallengeIssuer,
    NonceStore,
    b64u_decode,
    b64u_encode,
    leading_zero_bits,
    pow_matches,
    solve_pow,
)


class ChallengeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.issuer = ChallengeIssuer("unit-test-secret", ttl_seconds=60, difficulty=10)

    def test_pow_roundtrip(self) -> None:
        issued = self.issuer.issue("subject-1")
        nonce = solve_pow(issued["jti"], issued["difficulty"])
        self.assertIsNotNone(nonce)
        self.assertTrue(pow_matches(issued["jti"], nonce, issued["difficulty"]))

    def test_token_verifies(self) -> None:
        issued = self.issuer.issue("subject-1")
        challenge = self.issuer.verify(issued["token"])
        self.assertIsNotNone(challenge)
        self.assertEqual(challenge.jti, issued["jti"])
        self.assertEqual(challenge.subject, "subject-1")

    def test_tampered_token_rejected(self) -> None:
        issued = self.issuer.issue("subject-1")
        token = issued["token"]
        body, signature = token.split(".")[1], token.split(".")[2]
        forged = f"v1.{body}.{signature[:-2]}AA"
        self.assertIsNone(self.issuer.verify(forged))

    def test_expired_token_rejected(self) -> None:
        issued = self.issuer.issue("subject-1", now=time.time() - 120)
        self.assertIsNone(self.issuer.verify(issued["token"]))

    def test_solution_is_single_use(self) -> None:
        issued = self.issuer.issue("subject-1")
        challenge = self.issuer.verify(issued["token"])
        nonce = solve_pow(issued["jti"], issued["difficulty"])
        ok, reason = self.issuer.check_solution(challenge, nonce)
        self.assertTrue(ok, reason)
        ok2, reason2 = self.issuer.check_solution(challenge, nonce)
        self.assertFalse(ok2)
        self.assertEqual(reason2, "challenge already solved")

    def test_bad_nonce_rejected(self) -> None:
        issued = self.issuer.issue("subject-1")
        challenge = self.issuer.verify(issued["token"])
        self.assertFalse(self.issuer.check_solution(challenge, 1)[0])
        self.assertFalse(self.issuer.check_solution(challenge, "x")[0])

    def test_attest_key_is_deterministic(self) -> None:
        issued = self.issuer.issue("subject-1")
        self.assertEqual(
            b64u_decode(issued["attest_key"]), self.issuer.attest_key(issued["jti"])
        )

    def test_nonce_store_expiry(self) -> None:
        store = NonceStore(ttl_seconds=10)
        self.assertTrue(store.consume("a", now=100))
        self.assertFalse(store.consume("a", now=101))
        self.assertTrue(store.consume("a", now=111))


class BitTests(unittest.TestCase):
    def test_leading_zero_bits(self) -> None:
        self.assertEqual(leading_zero_bits(b"\x00\x00"), 16)
        self.assertEqual(leading_zero_bits(b"\x01"), 7)
        self.assertEqual(leading_zero_bits(b"\xff"), 0)

    def test_b64u_roundtrip(self) -> None:
        raw = b"hello\x00world?"
        self.assertEqual(b64u_decode(b64u_encode(raw)), raw)


if __name__ == "__main__":
    unittest.main()
