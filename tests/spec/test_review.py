"""Tests for specification review."""

from src.models import CapabilityInstance, ContractSpecification, SpecStatus
from src.services.spec.review import confirm_specification, modify_specification, render_specification


def test_review_includes_utxo_section():
    spec = ContractSpecification(
        intent="treasury",
        capabilities=[
            CapabilityInstance(name="treasury", parameters={}),
            CapabilityInstance(name="weighted_multisig", parameters={}),
        ],
        parameters={
            "asset_type": "BCH",
            "holders": 3,
            "weights": [56, 30, 14],
            "initial_threshold": 2,
            "final_threshold": 3,
            "duration_days": 30,
        },
        status=SpecStatus.IN_REVIEW,
    )
    review = render_specification(spec)
    assert review.sections.get("Access Control")
    assert review.sections.get("Operations")
    assert review.utxo_architecture is not None
    assert review.utxo_architecture.transactions


def test_confirm_and_modify_transitions():
    spec = ContractSpecification(intent="treasury", status=SpecStatus.IN_REVIEW)
    confirmed = confirm_specification(spec)
    assert confirmed.status == SpecStatus.CONFIRMED
    reopened = modify_specification(confirmed)
    assert reopened.status == SpecStatus.NEEDS_INPUT
