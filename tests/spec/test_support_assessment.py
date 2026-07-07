"""Tests for composition support assessment (Mode C backend)."""

from src.models import CapabilityInstance, ContractSpecification, PlanningReport
from src.services.spec.support_assessment import assess_composition_support


def _report(cap_names, modules, effective_mode=""):
    return PlanningReport(
        detected_capabilities=cap_names,
        selected_modules=modules,
        effective_mode=effective_mode,
    )


def test_escrow_multisig_is_supported():
    spec = ContractSpecification(
        intent="Create a 2 of 3 escrow",
        capabilities=[
            CapabilityInstance(name="escrow"),
            CapabilityInstance(name="multisig"),
        ],
        parameters={"signers": ["A", "B", "C"], "threshold": 2},
    )
    assessment = assess_composition_support(
        spec,
        _report(["escrow", "multisig"], ["EscrowModule", "MultisigModule"], "escrow"),
    )
    assert assessment.status == "supported"
    assert assessment.can_proceed is True
    assert assessment.suggestions == []


def test_treasury_weighted_decay_is_unsupported():
    spec = ContractSpecification(
        intent="treasury with weighted multisig and linear decay after 30 days",
        capabilities=[
            CapabilityInstance(name="treasury"),
            CapabilityInstance(name="vault"),
            CapabilityInstance(name="weighted_multisig"),
            CapabilityInstance(name="linear_decay"),
        ],
        parameters={"duration_days": 30, "holders": 3, "weights": [50, 30, 20]},
    )
    modules = ["VaultModule", "WeightedMultisigModule", "LinearThresholdModule"]
    assessment = assess_composition_support(
        spec,
        _report(
            ["treasury", "vault", "weighted_multisig", "linear_decay"],
            modules,
            "vault",
        ),
    )
    assert assessment.status == "unsupported"
    assert assessment.can_proceed is False
    assert assessment.can_save_spec is True
    assert assessment.reason
    assert len(assessment.suggestions) > 0
    assert assessment.suppressed_modules == ["WeightedMultisigModule", "LinearThresholdModule"]


def test_split_plus_escrow_conflict():
    spec = ContractSpecification(
        intent="escrow with split payout",
        capabilities=[
            CapabilityInstance(name="escrow"),
            CapabilityInstance(name="split"),
        ],
    )
    assessment = assess_composition_support(
        spec,
        _report(["escrow", "split"], ["EscrowModule", "MultisigModule", "SplitPaymentModule"], "escrow"),
    )
    assert assessment.status in ("unsupported", "experimental")
    assert assessment.can_save_spec is True


def test_single_vault_supported():
    spec = ContractSpecification(
        intent="cold storage vault",
        capabilities=[CapabilityInstance(name="vault")],
        parameters={"asset_type": "BCH"},
    )
    assessment = assess_composition_support(
        spec,
        _report(["vault"], ["VaultModule"], "vault"),
    )
    assert assessment.status == "supported"
    assert assessment.can_proceed is True
