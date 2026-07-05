"""Tests for orchestrator legacy fallback and merge."""

from src.models import CapabilityInstance, ContractSpecification, SpecStatus
from src.services.spec.orchestrator import apply_legacy_fallback, merge_answers
from src.services.spec.validator import SpecValidator


def test_legacy_fallback_fills_required_only():
    spec = ContractSpecification(
        intent="treasury with weighted multisig after 30 days",
        capabilities=[
            CapabilityInstance(name="weighted_multisig", parameters={}),
            CapabilityInstance(name="linear_decay", parameters={}),
            CapabilityInstance(name="treasury", parameters={}),
        ],
        parameters={"duration_days": 30},
    )
    filled, inferred = apply_legacy_fallback(spec, spec.intent, "high")
    assert "holders" in inferred
    assert filled.status == SpecStatus.CONFIRMED
    assert SpecValidator.validate(filled).is_complete


def test_merge_answers():
    spec = ContractSpecification(
        intent="treasury",
        capabilities=[CapabilityInstance(name="vault", parameters={})],
        parameters={},
    )
    merged = merge_answers(spec, {"asset_type": "BCH"})
    assert merged.parameters["asset_type"] == "BCH"
