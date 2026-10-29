"""Policy: score bands -> concrete action.

Five actions, deliberately ordered from cheapest to most hostile:

``allow``     forward the request untouched
``challenge`` answer 429 + a proof-of-work challenge; real browsers recover
``deceive``   answer 200 with synthetic, watermarked data (no real backend call)
``tarpit``    stall the response, then serve the deception path
``block``     answer 403 with a boring, information-free body

The deception-first ordering matters: a scanner that receives 403 learns it was
detected, a scanner that receives plausible fake data keeps going and burns
time -- and takes our canary tokens with it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional

from .scoring import RiskReport


class Action(str, Enum):
    ALLOW = "allow"
    CHALLENGE = "challenge"
    DECEIVE = "deceive"
    TARPIT = "tarpit"
    BLOCK = "block"

    def __str__(self) -> str:  # pragma: no cover - cosmetic
        return self.value


@dataclass
class Decision:
    action: Action
    score: float
    difficulty: int = 0
    delay_ms: int = 0
    band: str = "allow"
    notes: List[str] = field(default_factory=list)

    def as_dict(self) -> Dict[str, object]:
        return {
            "action": self.action.value,
            "score": round(self.score, 2),
            "band": self.band,
            "difficulty": self.difficulty,
            "delay_ms": self.delay_ms,
            "notes": list(self.notes),
        }


_ORDER = [Action.ALLOW, Action.CHALLENGE, Action.DECEIVE, Action.TARPIT, Action.BLOCK]


class Policy:
    """Maps a score onto an action using configured band thresholds."""

    DEFAULT_HARD_BLOCK = (
        "proto.smuggling_probe",
        "proto.edge_signature_invalid",
        "app.replay_detected",
        "app.bad_signature",
        "client.attestation_forged",
        "data.canary_echo",
    )

    # Hitting bait must never escalate to a block: a blocked agent learns it was
    # seen and starts over.  Keep it in the maze instead.
    DEFAULT_NEVER_BLOCK = ("app.decoy_schema_access", "app.honeypot_endpoint")

    def __init__(
        self,
        bands: Optional[Dict[str, float]] = None,
        challenge_min: int = 14,
        challenge_max: int = 26,
        tarpit_base_ms: int = 350,
        tarpit_per_point_ms: int = 60,
        tarpit_max_ms: int = 4000,
        hard_block: Optional[List[str]] = None,
    ) -> None:
        bands = dict(bands or {})
        defaults = {"allow": 0.0, "challenge": 30.0, "deceive": 55.0, "tarpit": 70.0, "block": 90.0}
        defaults.update({k: float(v) for k, v in bands.items()})
        self.bands = defaults
        self.challenge_min = int(challenge_min)
        self.challenge_max = int(challenge_max)
        self.tarpit_base_ms = int(tarpit_base_ms)
        self.tarpit_per_point_ms = int(tarpit_per_point_ms)
        self.tarpit_max_ms = int(tarpit_max_ms)
        self.hard_block = set(hard_block or self.DEFAULT_HARD_BLOCK)
        self.never_block = set(self.DEFAULT_NEVER_BLOCK)
        self._validate()

    def _validate(self) -> None:
        previous = -1.0
        for action in _ORDER:
            threshold = self.bands[action.value]
            if threshold < previous:
                raise ValueError(
                    f"band thresholds must be non-decreasing; {action.value}={threshold} "
                    f"is below the previous band"
                )
            previous = threshold

    def decide(self, report: RiskReport) -> Decision:
        score = report.score
        band = Action.ALLOW
        for action in _ORDER:
            if score >= self.bands[action.value]:
                band = action

        decision = Decision(action=band, score=score, band=band.value)

        # A few signals are decisive on their own: forged attestations, replays,
        # smuggling probes.  They bypass the score so an allow-list or a high
        # trust discount cannot talk us out of them.
        triggered = sorted({s.name for s in report.signals} & self.hard_block)
        if triggered:
            decision.action = Action.BLOCK
            decision.band = "hard-block"
            decision.notes.append("hard block: " + ", ".join(triggered))

        if decision.action is Action.BLOCK and decision.band != "hard-block":
            bait = sorted({s.name for s in report.signals} & self.never_block)
            if bait:
                decision.action = Action.TARPIT
                decision.band = "maze"
                decision.notes.append("bait in use, staying in deception: " + ", ".join(bait))
                over = max(0.0, score - self.bands["tarpit"])
                delay = self.tarpit_base_ms + over * self.tarpit_per_point_ms
                decision.delay_ms = int(min(self.tarpit_max_ms, delay))

        if decision.action is Action.CHALLENGE:
            span = max(1.0, self.bands["deceive"] - self.bands["challenge"])
            progress = min(1.0, max(0.0, (score - self.bands["challenge"]) / span))
            decision.difficulty = int(
                round(self.challenge_min + progress * (self.challenge_max - self.challenge_min))
            )
            decision.notes.append("solve proof-of-work to obtain an attestation")

        if decision.action in (Action.TARPIT, Action.DECEIVE):
            over = max(0.0, score - self.bands["tarpit"])
            delay = self.tarpit_base_ms + over * self.tarpit_per_point_ms
            decision.delay_ms = int(min(self.tarpit_max_ms, delay))
            decision.notes.append("synthetic response with canary payload")

        if decision.action is Action.BLOCK and decision.band != "hard-block":
            decision.notes.append("no diagnostic information returned")

        return decision


__all__ = ["Action", "Decision", "Policy"]
