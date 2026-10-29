"""Risk scoring.

Evidence is combined with a noisy-OR model::

    p = 1 - product(1 - w_i / 100)

This has three properties we care about:

* it never exceeds 100, so no amount of weak evidence silently becomes a block;
* it is associative and order independent, so detectors can run in parallel;
* it is explainable: every term is a named signal with a visible contribution.

Trust (a valid attestation, a strong signature) is subtracted *after* the
noisy-OR, and can never push a request below zero.  A critical signal sets a
floor at ``CRITICAL_FLOOR`` because some evidence is decisive on its own.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Sequence

from . import signals as sig
from .signals import Layer, Signal

CRITICAL_FLOOR = 88.0
MAX_SIGNALS_IN_REASON = 6


def _clamp(value: float, low: float, high: float) -> float:
    return max(low, min(high, value))


@dataclass
class RiskReport:
    """The full, auditable result of evaluating one request."""

    score: float
    signals: List[Signal] = field(default_factory=list)
    trust: float = 0.0
    by_layer: Dict[str, float] = field(default_factory=dict)
    reasons: List[str] = field(default_factory=list)
    action: str = "allow"

    @property
    def names(self) -> List[str]:
        return [s.name for s in self.signals]

    def has(self, name: str) -> bool:
        return any(s.name == name for s in self.signals)

    def as_dict(self) -> Dict[str, object]:
        return {
            "score": round(self.score, 2),
            "action": self.action,
            "trust": round(self.trust, 2),
            "signals": [s.as_dict() for s in self.signals],
            "by_layer": {k: round(v, 2) for k, v in self.by_layer.items()},
            "reasons": list(self.reasons),
        }

    def explain(self) -> str:
        """Human-readable explanation, one line per reason."""
        if not self.reasons:
            return f"score={self.score:.1f} action={self.action} (no signals)"
        head = f"score={self.score:.1f} action={self.action}"
        return "\n".join([head] + [f"  - {r}" for r in self.reasons])


class RiskEngine:
    """Turns a bag of signals into a score plus an explanation."""

    def __init__(self, weights: Optional[Dict[str, float]] = None) -> None:
        self.weights = dict(weights or {})

    def _weight(self, signal: Signal) -> float:
        override = self.weights.get(signal.name)
        return float(override) if override is not None else float(signal.weight)

    def score(
        self,
        found: Sequence[Signal],
        trust: float = 0.0,
        ceiling: Optional[float] = None,
    ) -> RiskReport:
        """Combine signals. ``ceiling`` caps the score (used by allow-lists)."""
        # Deduplicate identical signal names, keeping the strongest detail.
        best: Dict[str, Signal] = {}
        for s in found:
            current = best.get(s.name)
            if current is None or self._weight(s) > self._weight(current):
                best[s.name] = s
        ordered = sorted(best.values(), key=lambda s: -self._weight(s))

        survival = 1.0
        by_layer: Dict[str, float] = {}
        for s in ordered:
            p = _clamp(self._weight(s), 0.0, 99.0) / 100.0
            survival *= 1.0 - p
            by_layer[s.layer.value] = by_layer.get(s.layer.value, 0.0) + self._weight(s)

        raw = 100.0 * (1.0 - survival)
        if any(s.critical for s in ordered):
            raw = max(raw, CRITICAL_FLOOR)
        raw = max(0.0, raw - max(0.0, trust))
        if ceiling is not None:
            raw = min(raw, ceiling)

        reasons: List[str] = []
        for s in ordered[:MAX_SIGNALS_IN_REASON]:
            detail = f" ({s.detail})" if s.detail else ""
            reasons.append(f"{s.layer.value} {s.name} +{self._weight(s):g}{detail}")
        if trust:
            reasons.append(f"trust -{trust:g}")
        if len(ordered) > MAX_SIGNALS_IN_REASON:
            reasons.append(f"... {len(ordered) - MAX_SIGNALS_IN_REASON} more signal(s)")

        return RiskReport(
            score=round(raw, 2),
            signals=ordered,
            trust=float(trust),
            by_layer=by_layer,
            reasons=reasons,
        )

    def evaluate(
        self,
        found: Iterable[Signal],
        trust: float = 0.0,
        ceiling: Optional[float] = None,
    ) -> RiskReport:
        return self.score(list(found), trust=trust, ceiling=ceiling)


def layer_totals(found: Sequence[Signal]) -> Dict[str, float]:
    """Sum of weights per layer, handy for dashboards."""
    out: Dict[str, float] = {layer.value: 0.0 for layer in Layer}
    for s in found:
        out[s.layer.value] = out.get(s.layer.value, 0.0) + s.weight
    return out


__all__ = ["RiskEngine", "RiskReport", "CRITICAL_FLOOR", "layer_totals", "sig"]
