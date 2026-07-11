"""Graph v2 orchestration — SSOT pipeline for interactive specification."""

from __future__ import annotations

import logging
import os
from typing import Any, Dict, List, Optional, Tuple

from src.models import ContractSpecification, ExecutionPlan, PlanningReport, SpecStatus, UTXOArchitecture
from src.services.spec.architecture import ArchitectureBuilder
from src.services.spec.clarification_engine import ClarificationBatch, ClarificationEngine
from src.services.spec.confidence_engine import ConfidenceEngine
from src.services.spec.constraint_graph import ConstraintGraph
from src.services.spec.graph_config import graph_benchmark_legacy_only, use_spec_graph_v2
from src.services.spec.graph_extractor import GraphExtractor
from src.services.spec.graph_pattern_detection import GraphPatternDetection
from src.services.spec.graph_planner import GraphModulePlanner
from src.services.spec.phase2_adapter import resolve_effective_mode
from src.services.spec.validator_v2 import GraphValidationResult, ValidatorV2

logger = logging.getLogger("nexops.spec.graph_pipeline")


def should_use_graph_pipeline(resolution_mode: str = "interactive") -> bool:
    """
    Graph SSOT is the default for interactive spec flows only.
    Non-interactive / benchmark paths keep legacy keyword detection unless
    NEXOPS_SPEC_GRAPH_NON_INTERACTIVE=1.
    """
    if resolution_mode != "interactive":
        raw = os.getenv("NEXOPS_SPEC_GRAPH_NON_INTERACTIVE", "0").strip().lower()
        return raw in ("1", "true", "yes", "on") and use_spec_graph_v2()
    return use_spec_graph_v2()


async def bootstrap_graph(
    intent: str,
    *,
    api_key: Optional[str] = None,
    provider: Optional[str] = None,
    openrouter_key: Optional[str] = None,
) -> Tuple[ConstraintGraph, ContractSpecification, GraphValidationResult, ClarificationBatch]:
    graph = await GraphExtractor.extract(
        intent,
        api_key=api_key,
        provider=provider,
        openrouter_key=openrouter_key,
    )
    graph = GraphPatternDetection.apply_to_graph(graph)
    graph = ConfidenceEngine.apply(graph)
    validation = ValidatorV2.validate(graph)
    clarification = ClarificationEngine.build_batch(graph, validation, max_questions=1)
    spec = graph.to_specification()
    spec.intent = intent
    return graph, spec, validation, clarification


async def apply_graph_user_message(
    graph: ConstraintGraph,
    user_message: str,
    *,
    api_key: Optional[str] = None,
    provider: Optional[str] = None,
    openrouter_key: Optional[str] = None,
    last_clarification: Optional[ClarificationBatch] = None,
) -> Tuple[ConstraintGraph, GraphValidationResult, ClarificationBatch]:
    """Re-extract or merge user clarification into graph."""
    from src.services.spec.discovery import has_ambiguous_pattern_choice, lacks_contract_signal
    from src.services.spec.parameter_extraction import (
        extract_parameters_for_graph,
        extract_parameters_from_message,
        apply_contextual_graph_answer,
    )
    from src.services.spec.constraint_graph import NodeCategory

    msg = user_message.strip()
    if msg:
        if graph.intent and msg not in graph.intent:
            graph.intent = f"{graph.intent} {msg}".strip()
        elif not graph.intent:
            graph.intent = msg

    if has_ambiguous_pattern_choice(user_message) or has_ambiguous_pattern_choice(graph.intent or ""):
        validation = ValidatorV2.validate(graph)
        return graph, validation, ClarificationBatch()

    applied_context = apply_contextual_graph_answer(graph, user_message, last_clarification)

    spec = graph.to_specification()
    params = extract_parameters_for_graph(user_message, graph)
    if not params:
        params = extract_parameters_from_message(user_message, spec)

    for node in graph.nodes:
        if node.category == NodeCategory.AUTHORIZATION:
            if params.get("signers"):
                node.params["signers"] = params["signers"]
            if params.get("threshold") is not None:
                node.params["threshold"] = params["threshold"]
            if params.get("holders") is not None:
                node.params["holders"] = params["holders"]
            if params.get("weights"):
                node.params["weights"] = params["weights"]
        elif node.category == NodeCategory.POLICY:
            for key in ("duration_days", "initial_threshold", "final_threshold", "recipients", "shares"):
                if params.get(key) is not None:
                    node.params[key] = params[key]
        elif node.category == NodeCategory.TIME:
            if params.get("timeout_days") is not None:
                node.params["timeout_days"] = params["timeout_days"]

    should_reextract = (
        not params
        and not applied_context
        and not lacks_contract_signal(user_message)
    )
    if should_reextract:
        refined = await GraphExtractor.extract(
            graph.intent,
            user_message=user_message,
            api_key=api_key,
            provider=provider,
            openrouter_key=openrouter_key,
        )
        if refined.nodes:
            graph = _merge_graph_refinement(graph, refined)

    graph = GraphPatternDetection.apply_to_graph(graph)
    graph = ConfidenceEngine.apply(graph)
    validation = ValidatorV2.validate(graph)
    clarification = ClarificationEngine.build_batch(graph, validation, max_questions=1)
    return graph, validation, clarification


def _merge_graph_refinement(base: ConstraintGraph, refined: ConstraintGraph) -> ConstraintGraph:
    """Keep user-filled params; merge in new structure from re-extract."""
    if not base.nodes:
        refined.intent = base.intent or refined.intent
        return refined
    if not refined.nodes:
        return base

    from src.services.spec.constraint_graph import NodeCategory

    for ref_node in refined.nodes:
        matched = None
        for base_node in base.nodes:
            if base_node.category == ref_node.category and (base_node.kind or "") == (ref_node.kind or ""):
                matched = base_node
                break
        if matched:
            for key, value in ref_node.params.items():
                if matched.params.get(key) in (None, "", []):
                    matched.params[key] = value
        else:
            base.add_node(ref_node)
    refined.intent = base.intent or refined.intent
    return base


def build_planning_report(graph: ConstraintGraph) -> Tuple[ExecutionPlan, UTXOArchitecture, PlanningReport]:
    modules, decisions = GraphModulePlanner.select_modules(graph)
    spec = graph.to_specification()
    plan = ExecutionPlan(
        modules=modules,
        order=[m.name for m in modules],
        dependencies={m.name: list(m.depends_on) for m in modules},
        shared_parameters=dict(spec.parameters),
    )
    utxo = ArchitectureBuilder.build(plan, spec)
    report = PlanningReport(
        detected_capabilities=GraphPatternDetection.detect_patterns(graph),
        selected_modules=[m.name for m in modules],
        effective_mode=resolve_effective_mode(utxo, plan),
    )
    return plan, utxo, report


def graph_turn_message(clarification: ClarificationBatch, validation: GraphValidationResult) -> str:
    if validation.is_complete:
        return "Specification complete. Request spec_review to confirm."
    if clarification.questions:
        return clarification.questions[0]
    for issue in validation.blocking_issues:
        if issue.field_path == "contract_type" or issue.message == "No contract pattern identified yet":
            return (
                "What kind of contract are you building? "
                "For example: escrow, treasury vault, founder vesting, auction, or token split."
            )
    return "Tell me more about the contract requirements."
