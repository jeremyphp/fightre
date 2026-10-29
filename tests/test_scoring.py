"""Unit tests for the scoring engine."""

from __future__ import annotations

import unittest

from fightre import signals as sig
from fightre.scoring import CRITICAL_FLOOR, RiskEngine


class ScoringTests(unittest.TestCase):
    def setUp(self) -> None:
        self.engine = RiskEngine()

    def test_empty_signals_score_zero(self) -> None:
        report = self.engine.score([])
        self.assertEqual(report.score, 0.0)
        self.assertEqual(report.action, "allow")

    def test_single_signal_equals_its_weight(self) -> None:
        report = self.engine.score([sig.make("proto.bot_user_agent")])
        self.assertAlmostEqual(report.score, 40.0, places=2)

    def test_noisy_or_compounds(self) -> None:
        report = self.engine.score(
            [sig.make("proto.bot_user_agent"), sig.make("client.headless_ua")]
        )
        # 1 - 0.6 * 0.55 = 0.67
        self.assertAlmostEqual(report.score, 67.0, places=2)

    def test_never_exceeds_one_hundred(self) -> None:
        report = self.engine.score([sig.make(name) for name in sig.LIBRARY])
        self.assertLessEqual(report.score, 100.0)

    def test_critical_signal_sets_floor(self) -> None:
        report = self.engine.score([sig.make("app.replay_detected")])
        self.assertGreaterEqual(report.score, CRITICAL_FLOOR)

    def test_trust_is_subtracted(self) -> None:
        report = self.engine.score([sig.make("proto.bot_user_agent")], trust=30)
        self.assertAlmostEqual(report.score, 10.0, places=2)

    def test_trust_cannot_go_negative(self) -> None:
        report = self.engine.score([], trust=90)
        self.assertEqual(report.score, 0.0)

    def test_weight_override(self) -> None:
        engine = RiskEngine({"proto.bot_user_agent": 80})
        self.assertAlmostEqual(engine.score([sig.make("proto.bot_user_agent")]).score, 80.0)

    def test_duplicate_names_are_deduplicated(self) -> None:
        report = self.engine.score(
            [sig.make("proto.bot_user_agent", "a"), sig.make("proto.bot_user_agent", "b")]
        )
        self.assertEqual(len(report.signals), 1)
        self.assertAlmostEqual(report.score, 40.0)

    def test_reasons_are_explainable(self) -> None:
        report = self.engine.score([sig.make("proto.bot_user_agent", "curl/8")])
        self.assertTrue(any("bot_user_agent" in line for line in report.reasons))
        self.assertIn("score=", report.explain())

    def test_ceiling_caps_score(self) -> None:
        report = self.engine.score([sig.make("app.replay_detected")], ceiling=20)
        self.assertLessEqual(report.score, 20.0)


if __name__ == "__main__":
    unittest.main()
