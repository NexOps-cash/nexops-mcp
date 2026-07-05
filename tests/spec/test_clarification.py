"""Tests for clarification plan."""

from src.models import ValidationResult
from src.services.spec.clarification import build_clarification_plan


def test_clarification_from_missing_fields():
    validation = ValidationResult(
        missing_fields=["holders", "weights"],
        is_complete=False,
    )
    plan = build_clarification_plan(validation)
    assert plan.status == "needs_input"
    assert len(plan.questions) == 2
    assert all("holders" in q or "weight" in q.lower() or "holder" in q.lower() for q in plan.questions) or len(plan.questions) == 2
