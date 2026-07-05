"""Tests for specification validator."""

from src.models import CapabilityInstance, ContractSpecification
from src.services.spec.validator import SpecValidator


def test_validator_missing_fields():
    spec = ContractSpecification(
        intent="treasury",
        capabilities=[
            CapabilityInstance(name="weighted_multisig", parameters={}),
            CapabilityInstance(name="linear_decay", parameters={}),
        ],
        parameters={"duration_days": 30},
    )
    result = SpecValidator.validate(spec)
    assert not result.is_complete
    assert "holders" in result.missing_fields
    assert "weights" in result.missing_fields
    assert "initial_threshold" in result.missing_fields
    assert "final_threshold" in result.missing_fields


def test_validator_no_questions_in_result():
    spec = ContractSpecification(
        intent="treasury",
        capabilities=[CapabilityInstance(name="vault", parameters={})],
        parameters={},
    )
    result = SpecValidator.validate(spec)
    assert "questions" not in result.model_dump()
