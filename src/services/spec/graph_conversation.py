"""Conversational layer for graph v2 — natural chat while ConstraintGraph stays SSOT."""

from __future__ import annotations

from typing import Optional, Tuple

from src.models import ContractSpecification, SpecStatus
from src.services.spec.assistant import SpecificationAssistant
from src.services.spec.clarification_engine import ClarificationBatch, ClarificationEngine
from src.services.spec.constraint_graph import ConstraintGraph
from src.services.spec.discovery import (
    has_ambiguous_pattern_choice,
    is_pushback_or_confusion,
    lacks_contract_signal,
)
from src.services.spec.graph_pattern_detection import GraphPatternDetection
from src.services.spec.graph_pipeline import apply_graph_user_message, graph_turn_message
from src.services.spec.intent_pivot import looks_like_spec_replacement, try_pivot_specification
from src.services.spec.validator import SpecValidator
from src.services.spec.validator_v2 import GraphValidationResult, ValidatorV2

from src.services.spec.spec_messaging import (
    apply_parameterization_preferences,
    is_parameterization_request,
    maybe_completion_message,
    opening_message,
)


def _is_discovery_graph(graph: ConstraintGraph) -> bool:
    patterns = GraphPatternDetection.detect_patterns(graph)
    if patterns:
        return False
    meaningful = [
        n
        for n in graph.nodes
        if n.category.value
        in ("Authorization", "Policy", "Branch", "Constraint", "LifecycleState")
    ]
    return not meaningful


def _needs_conversational_turn(graph: ConstraintGraph, user_message: str) -> bool:
    if looks_like_spec_replacement(user_message):
        return True
    if is_parameterization_request(user_message):
        return True
    if lacks_contract_signal(user_message) and _is_discovery_graph(graph):
        return True
    # Only the current message — not stale "founder or treasury" in accumulated intent.
    if has_ambiguous_pattern_choice(user_message):
        return True
    if is_pushback_or_confusion(user_message):
        return True
    if _is_discovery_graph(graph):
        return True
    return False


def single_clarification_message(
    clarification: ClarificationBatch,
    validation: GraphValidationResult,
) -> str:
    if validation.is_complete:
        return "Your specification looks complete. Review the summary below."
    if clarification.questions:
        return clarification.questions[0]
    return graph_turn_message(clarification, validation)


async def respond_graph_turn(
    graph: ConstraintGraph,
    user_message: str,
    *,
    session=None,
    api_key: Optional[str] = None,
    provider: Optional[str] = None,
    openrouter_key: Optional[str] = None,
    last_clarification: Optional[ClarificationBatch] = None,
    is_first_turn: bool = False,
) -> Tuple[ConstraintGraph, ContractSpecification, GraphValidationResult, ClarificationBatch, str]:
    """One interactive turn: conversational discovery or single-field graph clarification."""
    if is_first_turn and lacks_contract_signal(user_message):
        graph = ConstraintGraph(intent=user_message.strip())
        validation = ValidatorV2.validate(graph)
        clarification = ClarificationBatch()
        spec = graph.to_specification()
        spec.status = SpecStatus.NEEDS_INPUT
        return graph, spec, validation, clarification, opening_message()

    if looks_like_spec_replacement(user_message):
        spec = graph.to_specification()
        spec.intent = graph.intent or spec.intent
        pivoted, message = try_pivot_specification(spec, user_message)
        if pivoted is not None:
            graph = ConstraintGraph.from_specification(pivoted)
            graph.intent = pivoted.intent
            graph = _apply_pattern_tags(graph)
            validation = ValidatorV2.validate(graph)
            clarification = ClarificationEngine.build_batch(graph, validation, max_questions=1)
            spec = pivoted
            spec.status = SpecStatus.IN_REVIEW if validation.is_complete else SpecStatus.NEEDS_INPUT
            return graph, spec, validation, clarification, message.strip()

    if _needs_conversational_turn(graph, user_message):
        spec = graph.to_specification()
        spec.intent = graph.intent or spec.intent or user_message.strip()
        legacy_validation = SpecValidator.validate(spec)
        chat_history = list(session.spec_chat_history) if session else []
        turn = await SpecificationAssistant.respond(
            spec,
            legacy_validation,
            user_message,
            api_key=api_key,
            provider=provider or "openrouter",
            openrouter_key=openrouter_key or api_key,
            chat_history=chat_history,
        )
        message = turn.message.strip()
        updated = turn.updated_spec
        updated.intent = updated.intent or graph.intent or user_message.strip()

        ready = maybe_completion_message(updated)
        if ready:
            message = ready

        if updated.capabilities:
            graph = ConstraintGraph.from_specification(updated)
            graph.intent = updated.intent
            graph = _apply_pattern_tags(graph)
            validation = ValidatorV2.validate(graph)
            clarification = ClarificationEngine.build_batch(graph, validation, max_questions=1)
            if (
                clarification.questions
                and not validation.is_complete
                and not _message_asks_field(message, clarification.questions[0])
                and not has_ambiguous_pattern_choice(user_message)
            ):
                message = f"{message}\n\n{clarification.questions[0]}"
            spec = graph.to_specification()
            spec.intent = graph.intent
        else:
            if graph.intent and user_message.strip() not in graph.intent:
                graph.intent = f"{graph.intent} {user_message}".strip()
            elif not graph.intent:
                graph.intent = user_message.strip()
            graph = ConstraintGraph(intent=graph.intent)
            validation = ValidatorV2.validate(graph)
            clarification = ClarificationBatch()
            spec = graph.to_specification()
            spec.intent = graph.intent

        spec.status = SpecStatus.IN_REVIEW if validation.is_complete else SpecStatus.NEEDS_INPUT
        return graph, spec, validation, clarification, message

    graph, validation, clarification = await apply_graph_user_message(
        graph,
        user_message,
        api_key=api_key,
        provider=provider,
        openrouter_key=openrouter_key,
        last_clarification=last_clarification,
    )
    spec = graph.to_specification()
    spec.intent = graph.intent or spec.intent
    spec.status = SpecStatus.IN_REVIEW if validation.is_complete else SpecStatus.NEEDS_INPUT
    message = single_clarification_message(clarification, validation)
    return graph, spec, validation, clarification, message


def _apply_pattern_tags(graph: ConstraintGraph) -> ConstraintGraph:
    from src.services.spec.confidence_engine import ConfidenceEngine
    from src.services.spec.graph_pattern_detection import GraphPatternDetection

    graph = GraphPatternDetection.apply_to_graph(graph)
    return ConfidenceEngine.apply(graph)


def _message_asks_field(message: str, question: str) -> bool:
    m = message.lower()
    q = question.lower()
    for token in ("who", "what", "how many", "when", "which", "threshold", "recipient", "signer"):
        if token in q and token in m:
            return True
    return False
