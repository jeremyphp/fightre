"""Attestation and environment analysis tests."""

from __future__ import annotations

import time
import unittest

from fightre.attest import AttestationVerifier, analyze_env

CLEAN = {
    "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/131.0.0.0 Safari/537.36",
    "webdriver": False,
    "cdp": False,
    "native_clean": True,
    "webgl_renderer": "ANGLE (NVIDIA GeForce RTX 3060)",
    "consistent": True,
    "devtools_open": False,
    "hardware_concurrency": 16,
    "platform": "Win32",
}

HEADLESS = {
    "ua": "Mozilla/5.0 (X11; Linux x86_64) HeadlessChrome/131.0.0.0 Safari/537.36",
    "webdriver": True,
    "cdp": True,
    "native_clean": False,
    "webgl_renderer": "Google SwiftShader",
    "consistent": False,
    "hardware_concurrency": 1,
}


class AttestationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.verifier = AttestationVerifier("unit-test-secret", ttl_seconds=60, trust=30)

    def test_clean_attestation_verifies(self) -> None:
        blob = self.verifier.build("jti-1", CLEAN)
        result = self.verifier.verify(blob)
        self.assertTrue(result.ok)
        self.assertEqual(result.reason, "ok")
        self.assertAlmostEqual(result.trust, 30.0)
        self.assertEqual(result.jti, "jti-1")

    def test_tampered_attestation_fails(self) -> None:
        blob = self.verifier.build("jti-1", CLEAN)
        result = self.verifier.verify(blob[:-3] + "AAA")
        self.assertFalse(result.ok)
        self.assertEqual(result.reason, "bad-signature")

    def test_stale_attestation_fails(self) -> None:
        blob = self.verifier.build("jti-1", CLEAN, now=time.time() - 120)
        result = self.verifier.verify(blob)
        self.assertFalse(result.ok)
        self.assertEqual(result.reason, "stale")

    def test_wrong_key_fails(self) -> None:
        other = AttestationVerifier("different-secret", ttl_seconds=60)
        blob = other.build("jti-1", CLEAN)
        self.assertFalse(self.verifier.verify(blob).ok)

    def test_malformed_input(self) -> None:
        self.assertEqual(self.verifier.verify("").reason, "missing")
        self.assertEqual(self.verifier.verify("a.b.c").reason, "malformed")


class EnvironmentTests(unittest.TestCase):
    def test_clean_env_has_no_signals(self) -> None:
        found, discount = analyze_env(CLEAN)
        self.assertEqual(found, [])
        self.assertEqual(discount, 0.0)

    def test_headless_env_raises_signals(self) -> None:
        found, discount = analyze_env(HEADLESS)
        names = {s.name for s in found}
        self.assertIn("client.webdriver", names)
        self.assertIn("client.headless_ua", names)
        self.assertIn("client.software_renderer", names)
        self.assertEqual(discount, 1.0)

    def test_empty_env_is_anomalous(self) -> None:
        found, _ = analyze_env({})
        self.assertEqual(found[0].name, "client.env_anomaly")

    def test_honeypot_field_is_critical_evidence(self) -> None:
        env = dict(CLEAN)
        env["honeypot_filled"] = True
        found, _ = analyze_env(env)
        self.assertIn("client.honeypot_clicked", {s.name for s in found})


if __name__ == "__main__":
    unittest.main()
