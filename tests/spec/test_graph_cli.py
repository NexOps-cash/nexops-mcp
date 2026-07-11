"""Tests for graph CLI helpers."""

from src.services.spec.clarification_engine import ClarificationBatch
from src.services.spec.constraint_graph import ConstraintGraph, GraphNode, NodeCategory
from src.services.spec.discovery import has_ambiguous_pattern_choice
from src.services.spec.graph_conversation import (
    _needs_conversational_turn,
    single_clarification_message,
)
from src.services.spec.graph_pipeline import graph_turn_message
from src.services.spec.parameter_extraction import apply_contextual_graph_answer, extract_parameters_for_graph
from src.services.spec.validator_v2 import GraphValidationIssue, GraphValidationResult, IssueClass, IssueSeverity


def test_display_turn_message_discovery_opening():
    from src.services.spec.spec_messaging import opening_message

    msg = opening_message()
    assert "smart contract" in msg.lower() or "nexops" in msg.lower()


def test_graph_turn_message_contract_type_prompt():
    validation = GraphValidationResult(
        issues=[
            GraphValidationIssue(
                issue_class=IssueClass.MISSING,
                severity=IssueSeverity.ERROR,
                message="No contract pattern identified yet",
                field_path="contract_type",
            )
        ],
        is_complete=False,
    )
    msg = graph_turn_message(ClarificationBatch(), validation)
    assert "escrow" in msg.lower()


def test_ambiguous_pattern_stays_conversational():
    text = "shall we create vesting of founder or treasury governance"
    assert has_ambiguous_pattern_choice(text)
    graph = ConstraintGraph(intent=text)
    assert _needs_conversational_turn(graph, text)


def test_single_question_only():
    clarification = ClarificationBatch(
        questions=["Question one?", "Question two?"],
    )
    validation = GraphValidationResult(is_complete=False)
    assert single_clarification_message(clarification, validation) == "Question one?"


def test_contextual_me_recipient():
    graph = ConstraintGraph(intent="split")
    node = GraphNode(
        id="n1",
        category=NodeCategory.POLICY,
        kind="Distribution",
        label="Split",
        params={},
    )
    graph.add_node(node)
    batch = ClarificationBatch(
        questions=["Who should receive the split payouts?"],
        target_node_ids=[node.id],
        field_paths=["recipients"],
    )
    assert apply_contextual_graph_answer(graph, "me", batch)
    assert graph.nodes[0].params["recipients"] == ["Me"]


def test_extract_years_for_graph():
    graph = ConstraintGraph(intent="vesting")
    node = GraphNode(
        id="n1",
        category=NodeCategory.POLICY,
        kind="Decay",
        label="Vesting Duration",
        params={},
    )
    graph.add_node(node)
    params = extract_parameters_for_graph("2 years", graph)
    assert params.get("duration_days") == 730
