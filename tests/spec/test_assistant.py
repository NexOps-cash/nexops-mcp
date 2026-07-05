"""Tests for assistant constraint enforcement (no LLM)."""

from src.models import CapabilityInstance, ContractSpecification, SpecStatus
from src.services.spec.assistant import _strip_unknown_capabilities, _merge_allowed_parameters


def test_strip_unknown_capabilities():
    spec = ContractSpecification(
        intent="test",
        capabilities=[
            CapabilityInstance(name="weighted_multisig", parameters={}),
            CapabilityInstance(name="not_a_real_cap", parameters={}),
        ],
    )
    cleaned = _strip_unknown_capabilities(spec)
    assert len(cleaned.capabilities) == 1
    assert cleaned.capabilities[0].name == "weighted_multisig"


def test_protect_confirmed_fields():
    original = ContractSpecification(
        intent="treasury",
        parameters={"holders": 3},
        status=SpecStatus.CONFIRMED,
    )
    updated = original.model_copy(deep=True)
    updated.parameters["holders"] = 99
    protected = _merge_allowed_parameters(updated, original)
    assert protected.parameters["holders"] == 3
