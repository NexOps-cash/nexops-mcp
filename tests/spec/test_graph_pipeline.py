"""Tests for graph v2 pipeline and validator."""

from __future__ import annotations

import pytest

from src.models import CapabilityInstance, ContractSpecification
from src.services.spec.clarification_engine import ClarificationEngine
from src.services.spec.constraint_graph import ConstraintGraph, NodeCategory
from src.services.spec.graph_config import use_spec_graph_v2
from src.services.spec.graph_generation_bridge import GraphGenerationBridge
from src.services.spec.graph_pipeline import bootstrap_graph, should_use_graph_pipeline
from src.services.spec.validator_v2 import ValidatorV2


@pytest.mark.asyncio
async def test_bootstrap_graph_heuristic(monkeypatch):
    monkeypatch.setenv("OPENROUTER_API_KEY", "")
    graph, spec, validation, clarification = await bootstrap_graph(
        "2-of-3 escrow with Alice Bob Carol, refund after 7 days"
    )
    assert isinstance(graph, ConstraintGraph)
    assert spec.intent or graph.intent
    assert isinstance(validation.issues, list)


def test_validator_v2_missing_signers():
    spec = ContractSpecification(
        intent="escrow",
        capabilities=[CapabilityInstance(name="escrow"), CapabilityInstance(name="multisig")],
        parameters={},
    )
    graph = ConstraintGraph.from_specification(spec)
    for n in graph.nodes_by_category(NodeCategory.AUTHORIZATION):
        n.params = {}
    result = ValidatorV2.validate(graph)
    assert not result.is_complete
    assert any(i.issue_class.value == "missing" for i in result.blocking_issues)


def test_clarification_batches_low_confidence():
    spec = ContractSpecification(
        intent="escrow",
        capabilities=[CapabilityInstance(name="escrow")],
        parameters={},
    )
    graph = ConstraintGraph.from_specification(spec)
    validation = ValidatorV2.validate(graph)
    batch = ClarificationEngine.build_batch(graph, validation)
    assert isinstance(batch.questions, list)


def test_graph_generation_bridge():
    spec = ContractSpecification(
        intent="split 50/50",
        capabilities=[CapabilityInstance(name="split")],
        parameters={"recipients": ["A", "B"], "shares": [50, 50]},
    )
    graph = ConstraintGraph.from_specification(spec)
    plan, utxo, report, projected = GraphGenerationBridge.resolve_from_graph(graph)
    assert plan.modules
    assert report.effective_mode
    assert projected.parameters.get("shares") == [50, 50]


def test_graph_v2_default_enabled(monkeypatch):
    monkeypatch.delenv("NEXOPS_SPEC_GRAPH_V2", raising=False)
    assert use_spec_graph_v2() is True
    assert should_use_graph_pipeline("interactive") is True
    assert should_use_graph_pipeline("non_interactive") is False
