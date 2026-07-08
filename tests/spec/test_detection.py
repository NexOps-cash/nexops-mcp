"""Tests for capability detection from free-text prompts."""

from src.models import RawIntent
from src.services.spec.detection import detect_capabilities


def test_cardano_catalyst_dao_maps_to_treasury_weighted():
    spec = detect_capabilities(
        RawIntent(intent="governance dao", capabilities=[], constraints={}),
        original_intent="need a governance voting dao like cardano catlyst",
    )
    names = {c.name for c in spec.capabilities}
    assert "treasury" in names
    assert "vault" in names
    assert "weighted_multisig" in names
    assert "multisig" not in names or "weighted_multisig" in names


def test_plain_multisig_unchanged():
    spec = detect_capabilities(
        RawIntent(intent="multisig", capabilities=["multisig"], constraints={}),
        original_intent="Create a 2 of 3 multisig wallet",
    )
    names = {c.name for c in spec.capabilities}
    assert "multisig" in names
    assert "weighted_multisig" not in names
    assert "treasury" not in names


def test_decay_treasury_still_maps():
    spec = detect_capabilities(
        RawIntent(intent="treasury", capabilities=[], constraints={}),
        original_intent="want a decay treasury",
    )
    names = {c.name for c in spec.capabilities}
    assert "treasury" in names
    assert "vault" in names
    assert "linear_decay" in names


def test_vague_greeting_does_not_default_to_multisig():
    spec = detect_capabilities(
        RawIntent(intent="", capabilities=[], constraints={}),
        original_intent="hi",
    )
    assert spec.capabilities == []


def test_casual_chat_does_not_default_to_multisig():
    spec = detect_capabilities(
        RawIntent(intent="", capabilities=[], constraints={}),
        original_intent="how r u",
    )
    assert spec.capabilities == []


def test_non_interactive_may_still_default_multisig():
    spec = detect_capabilities(
        RawIntent(intent="", capabilities=[], constraints={}),
        original_intent="something vague but long enough",
        allow_generic_multisig_default=True,
    )
    names = {c.name for c in spec.capabilities}
    assert "multisig" in names
