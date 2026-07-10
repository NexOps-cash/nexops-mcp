"""Tests for discovery phase and greeting handling."""

from __future__ import annotations

import pytest

from src.models import CapabilityInstance, ContractSpecification
from src.services.spec.assistant import SpecificationAssistant
from src.services.spec.discovery import (
    has_ambiguous_pattern_choice,
    is_pushback_or_confusion,
    lacks_contract_signal,
    is_in_discovery_phase,
    try_discover_specification,
)
from src.services.spec.constraint_graph import ConstraintGraph
from src.services.spec.graph_extractor import _heuristic_graph
from src.services.spec.orchestrator import run_spec_pipeline
from src.services.spec.validator import SpecValidator
from src.services.spec.validator_v2 import ValidatorV2


def test_lacks_contract_signal_greetings():
    assert lacks_contract_signal("hi") is True
    assert lacks_contract_signal("hello!") is True
    assert lacks_contract_signal("2-of-3 escrow with refund") is False


def test_ambiguous_vesting_or_auction():
    msg = "can we do founders vesting or an auction"
    assert has_ambiguous_pattern_choice(msg) is True
    assert try_discover_specification(ContractSpecification(), msg) is None


def test_pushback_skips_wizard_nudge():
    assert is_pushback_or_confusion("wtf") is True


@pytest.mark.asyncio
async def test_assistant_no_default_nudge_on_wtf():
    spec = ContractSpecification(
        intent="vesting",
        capabilities=[
            CapabilityInstance(name="vault"),
            CapabilityInstance(name="timelock"),
            CapabilityInstance(name="split"),
        ],
        parameters={},
    )
    validation = SpecValidator.validate(spec)
    turn = await SpecificationAssistant.respond(spec, validation, "wtf")
    assert "Founder A" not in turn.message
    assert "reply yes" not in turn.message.lower()


def test_heuristic_graph_greeting_is_empty():
    graph = _heuristic_graph("hi")
    assert graph.intent == "hi"
    assert graph.nodes == [] or len(graph.nodes) <= 1


def test_validator_v2_rejects_empty_graph():
    graph = ConstraintGraph(intent="hi")
    result = ValidatorV2.validate(graph)
    assert not result.is_complete
    assert any("pattern" in i.message.lower() for i in result.blocking_issues)


@pytest.mark.asyncio
async def test_interactive_pipeline_greeting_needs_input():
    spec, clarification, plan, utxo, report, _ = await run_spec_pipeline(
        "hi",
        resolution_mode="interactive",
    )
    assert clarification is not None
    assert plan is None
    assert utxo is None
    assert not spec.capabilities or is_in_discovery_phase(spec)
