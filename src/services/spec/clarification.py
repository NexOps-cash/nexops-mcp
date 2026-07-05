"""Deterministic clarification plan from registry field questions."""

from __future__ import annotations

from typing import List

from src.models import ClarificationPlan, ValidationResult
from src.services.spec.capabilities import CAPABILITY_REGISTRY, get_capability


def build_clarification_plan(validation: ValidationResult) -> ClarificationPlan:
    questions: List[str] = []
    for field_name in validation.missing_fields:
        q = _question_for_field(field_name)
        if q and q not in questions:
            questions.append(q)
    return ClarificationPlan(
        status="needs_input",
        missing_fields=list(validation.missing_fields),
        questions=questions,
    )


def _question_for_field(field_name: str) -> str:
    for cap in CAPABILITY_REGISTRY.values():
        for fs in cap.required_fields:
            if fs.name == field_name:
                return fs.question or f"Please provide {field_name}."
    return f"Please provide {field_name}."
