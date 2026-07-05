"""Tests for capability registry."""

from src.services.spec.capabilities import CAPABILITY_REGISTRY, get_capability


def test_registry_has_treasury_capabilities():
    assert "treasury" in CAPABILITY_REGISTRY
    assert "weighted_multisig" in CAPABILITY_REGISTRY
    assert "linear_decay" in CAPABILITY_REGISTRY


def test_weighted_multisig_rich_fields():
    cap = get_capability("weighted_multisig")
    assert cap is not None
    assert len(cap.required_fields) >= 2
    assert cap.recommendations
    assert cap.documentation
    assert cap.examples


def test_no_effective_mode_on_capability():
    cap = get_capability("vault")
    assert cap is not None
    assert not hasattr(cap, "effective_mode")
