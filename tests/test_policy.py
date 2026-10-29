"""Unit tests for band policy and hard-block overrides."""

from __future__ import annotations

import unittest

from fightre import signals as sig
from fightre.policy import Action, Policy
from fightre.scoring import RiskEngine


class PolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.engine = RiskEngine()
        self.policy = Policy()

    def decide(self, *names: str):
        return self.policy.decide(self.engine.score([sig.make(n) for n in names]))

    def test_allow_below_challenge(self) -> None:
        self.assertEqual(self.decide().action, Action.ALLOW)
        self.assertEqual(self.decide("proto.accept_encoding_mismatch").action, Action.ALLOW)

    def test_bot_ua_gets_challenge(self) -> None:
        decision = self.decide("proto.bot_user_agent")
        self.assertEqual(decision.action, Action.CHALLENGE)
        self.assertGreaterEqual(decision.difficulty, 14)

    def test_high_score_gets_tarpit(self) -> None:
        decision = self.decide("proto.bot_user_agent", "proto.agent_runtime")
        self.assertEqual(decision.action, Action.TARPIT)
        self.assertGreater(decision.delay_ms, 0)

    def test_hard_block_ignores_band(self) -> None:
        decision = self.decide("app.replay_detected")
        self.assertEqual(decision.action, Action.BLOCK)
        self.assertEqual(decision.band, "hard-block")

    def test_bait_never_blocks(self) -> None:
        # A honeypot hit alone is 80: above the block band, but bait must keep
        # the attacker in the maze rather than teach them they were seen.
        decision = self.decide("app.honeypot_endpoint", "proto.bot_user_agent")
        self.assertEqual(decision.action, Action.TARPIT)
        self.assertEqual(decision.band, "maze")

    def test_custom_bands(self) -> None:
        policy = Policy({"allow": 0, "challenge": 5, "deceive": 10, "tarpit": 20, "block": 30})
        report = self.engine.score([sig.make("proto.missing_browser_headers")])
        self.assertEqual(policy.decide(report).action, Action.DECEIVE)

    def test_bands_must_be_ordered(self) -> None:
        with self.assertRaises(ValueError):
            Policy({"allow": 0, "challenge": 50, "deceive": 20})

    def test_challenge_difficulty_scales(self) -> None:
        low = self.policy.decide(self.engine.score([sig.make("proto.bot_user_agent")]))
        high = self.policy.decide(
            self.engine.score([sig.make("proto.bot_user_agent", weight=54)])
        )
        self.assertGreaterEqual(high.difficulty, low.difficulty)


if __name__ == "__main__":
    unittest.main()
