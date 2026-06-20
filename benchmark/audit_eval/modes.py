"""CI evaluation modes — Fast and Standard use zero OpenRouter credits."""

from __future__ import annotations

from enum import Enum


class EvaluationMode(str, Enum):
    """How much of the audit pipeline to exercise."""

    FAST = "fast"
    """Detectors + lint only (no intent invariants, no policy)."""

    STANDARD = "standard"
    """Detectors + lint + intent invariants + optional policy from fixture judgment."""

    FULL = "full"
    """Reserved for future live semantic judge. Disabled by default (no LLM calls)."""

    @property
    def uses_invariants(self) -> bool:
        return self in (EvaluationMode.STANDARD, EvaluationMode.FULL)

    @property
    def uses_policy(self) -> bool:
        return self in (EvaluationMode.STANDARD, EvaluationMode.FULL)

    @property
    def allows_llm(self) -> bool:
        return self == EvaluationMode.FULL
