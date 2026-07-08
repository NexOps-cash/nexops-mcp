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


def test_protect_confirmed_fields_on_confirmed_spec():
    original = ContractSpecification(
        intent="treasury",
        parameters={"holders": 3},
        status=SpecStatus.CONFIRMED,
    )
    updated = original.model_copy(deep=True)
    updated.parameters["holders"] = 99
    protected = _merge_allowed_parameters(updated, original)
    assert protected.parameters["holders"] == 3


def test_merge_preserves_in_progress_parameters():
    original = ContractSpecification(
        intent="treasury",
        parameters={"initial_threshold": 50},
        confirmed_fields=["initial_threshold"],
        status=SpecStatus.NEEDS_INPUT,
    )
    updated = original.model_copy(deep=True)
    updated.parameters = {"duration_days": 30}
    updated.confirmed_fields = ["duration_days"]
    merged = _merge_allowed_parameters(updated, original)
    assert merged.parameters["initial_threshold"] == 50
    assert merged.parameters["duration_days"] == 30
    assert set(merged.confirmed_fields) == {"initial_threshold", "duration_days"}
