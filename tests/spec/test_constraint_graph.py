"""Tests for ConstraintGraph models and EP/UTXO mapper."""

from __future__ import annotations

from src.models import CapabilityInstance, ContractSpecification, ExecutionPlan, GenerationModule
from src.services.spec.constraint_graph import (
    ConstraintGraph,
    LifecycleStateName,
    NodeCategory,
)
from src.services.spec.graph_pattern_detection import GraphPatternDetection
from src.services.spec.graph_planner import GraphModulePlanner


def _escrow_spec() -> ContractSpecification:
    return ContractSpecification(
        intent="2-of-3 escrow with 7 day refund",
        capabilities=[
            CapabilityInstance(name="escrow"),
            CapabilityInstance(name="multisig"),
        ],
        parameters={
            "signers": ["Alice", "Bob", "Carol"],
            "threshold": 2,
            "timeout_days": 7,
            "asset_type": "BCH",
        },
    )


def _founder_vesting_spec() -> ContractSpecification:
    return ContractSpecification(
        intent="Founder vesting vault with cliff",
        capabilities=[
            CapabilityInstance(name="vault"),
            CapabilityInstance(name="linear_decay"),
            CapabilityInstance(name="split"),
        ],
        parameters={
            "initial_threshold": 1,
            "final_threshold": 2,
            "duration_days": 365,
            "recipients": ["Founder A", "Founder B"],
            "shares": [60, 40],
            "lifecycle_mode": "vesting",
            "asset_type": "BCH",
        },
    )


def _split_only_spec() -> ContractSpecification:
    return ContractSpecification(
        intent="Split payment 60/40",
        capabilities=[CapabilityInstance(name="split")],
        parameters={
            "recipients": ["Alice", "Bob"],
            "shares": [60, 40],
        },
    )


def test_from_specification_escrow_has_auth_and_time():
    graph = ConstraintGraph.from_specification(_escrow_spec())
    assert graph.intent
    auth = graph.nodes_by_category(NodeCategory.AUTHORIZATION)
    assert len(auth) == 1
    assert auth[0].params["threshold"] == 2
    time_nodes = graph.nodes_by_category(NodeCategory.TIME)
    assert any(t.params.get("timeout_days") == 7 for t in time_nodes)
    branches = graph.nodes_by_category(NodeCategory.BRANCH)
    assert any(b.kind == "Refund" for b in branches)


def test_from_specification_founder_vesting_has_policy_and_lifecycle():
    graph = ConstraintGraph.from_specification(_founder_vesting_spec())
    policies = graph.nodes_by_category(NodeCategory.POLICY)
    assert any(p.kind == "Decay" for p in policies)
    assert any(p.kind == "Distribution" for p in policies)
    lifecycle = graph.nodes_by_category(NodeCategory.LIFECYCLE_STATE)
    assert len(lifecycle) >= 1
    assert any(ls.kind == LifecycleStateName.LOCKED.value for ls in lifecycle)


def test_roundtrip_projection_preserves_capabilities():
    spec = _split_only_spec()
    graph = ConstraintGraph.from_specification(spec)
    projected = graph.to_specification()
    cap_names = {c.name for c in projected.capabilities}
    assert "split" in cap_names
    assert projected.parameters.get("shares") == [60, 40]


def test_from_execution_plan_bridge():
    plan = ExecutionPlan(
        modules=[
            GenerationModule(name="MultisigModule", capability="multisig"),
        ],
        order=["MultisigModule"],
        shared_parameters={"signers": ["A", "B"], "threshold": 2},
    )
    graph = ConstraintGraph.from_execution_plan(plan, intent="escrow multisig")
    assert graph.intent == "escrow multisig"
    assert len(graph.nodes) >= 2


def test_graph_pattern_detection_founder_vesting():
    graph = ConstraintGraph.from_specification(_founder_vesting_spec())
    patterns = GraphPatternDetection.detect_patterns(graph)
    assert "linear_decay" in patterns
    assert "split" in patterns


def test_graph_planner_selects_modules():
    graph = ConstraintGraph.from_specification(_founder_vesting_spec())
    modules, _ = GraphModulePlanner.select_modules(graph)
    names = {m.name for m in modules}
    assert "VestingScheduleModule" in names or "LinearThresholdModule" in names
    assert "SplitModule" in names


def test_to_execution_plan_roundtrip():
    graph = ConstraintGraph.from_specification(_escrow_spec())
    plan, utxo = graph.to_execution_plan()
    assert plan.modules
    assert utxo.transactions
