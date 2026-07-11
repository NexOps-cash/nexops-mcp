"""CLI helpers for Constraint Graph v2 — mirrors spec_controller graph flow."""

from __future__ import annotations

from typing import Optional, Tuple

from src.models import ContractSpecification, SpecStatus
from src.services.session import get_session_manager
from src.services.spec.clarification_engine import ClarificationBatch
from src.services.spec.constraint_graph import ConstraintGraph
from src.services.spec.graph_conversation import respond_graph_turn
from src.services.spec.validator_v2 import GraphValidationResult

DISCOVERY_OPENING = (
    "Hey — I'm NexOps, your contract architect. "
    "Tell me what you're trying to build and we'll shape it together."
)


def persist_graph_session(
    session,
    graph: ConstraintGraph,
    spec: ContractSpecification,
    clarification: Optional[ClarificationBatch] = None,
) -> None:
    session.current_constraint_graph = graph.model_dump()
    session.current_specification = spec
    if clarification is not None:
        session.graph_last_clarification = clarification.model_dump()


def load_last_clarification(session) -> Optional[ClarificationBatch]:
    raw = getattr(session, "graph_last_clarification", None)
    if raw:
        return ClarificationBatch(**raw)
    return None


def load_graph_from_session(session) -> Optional[ConstraintGraph]:
    if session.current_constraint_graph:
        return ConstraintGraph.from_dict(session.current_constraint_graph)
    return None


async def cli_bootstrap(
    intent: str,
    session,
    *,
    api_key: Optional[str] = None,
    provider: Optional[str] = None,
    openrouter_key: Optional[str] = None,
) -> Tuple[ConstraintGraph, ContractSpecification, GraphValidationResult, str]:
    graph, spec, validation, clarification, message = await respond_graph_turn(
        ConstraintGraph(intent=intent.strip()),
        intent,
        session=session,
        api_key=api_key,
        provider=provider,
        openrouter_key=openrouter_key,
        is_first_turn=True,
    )
    persist_graph_session(session, graph, spec, clarification)
    if session is not None:
        mgr = get_session_manager()
        mgr.append_spec_chat(session.session_id, "user", intent)
        mgr.append_spec_chat(session.session_id, "assistant", message)
    return graph, spec, validation, message


async def cli_apply_message(
    session,
    graph: ConstraintGraph,
    user_message: str,
    *,
    api_key: Optional[str] = None,
    provider: Optional[str] = None,
    openrouter_key: Optional[str] = None,
    last_clarification: Optional[ClarificationBatch] = None,
) -> Tuple[ConstraintGraph, ContractSpecification, GraphValidationResult, ClarificationBatch, str]:
    if last_clarification is None and session is not None:
        last_clarification = load_last_clarification(session)
    graph, spec, validation, clarification, message = await respond_graph_turn(
        graph,
        user_message,
        session=session,
        api_key=api_key,
        provider=provider,
        openrouter_key=openrouter_key,
        last_clarification=last_clarification,
    )
    persist_graph_session(session, graph, spec, clarification)
    if session is not None:
        mgr = get_session_manager()
        mgr.append_spec_chat(session.session_id, "user", user_message)
        mgr.append_spec_chat(session.session_id, "assistant", message)
    return graph, spec, validation, clarification, message


def confirm_graph_session(session, graph: ConstraintGraph, spec: ContractSpecification) -> ContractSpecification:
    from src.services.spec.review import confirm_specification

    spec = confirm_specification(spec)
    graph.status = SpecStatus.CONFIRMED
    persist_graph_session(session, graph, spec)
    return spec


def modify_graph_session(session, graph: ConstraintGraph, spec: ContractSpecification) -> ContractSpecification:
    from src.services.spec.review import modify_specification

    spec = modify_specification(spec)
    graph.status = SpecStatus.NEEDS_INPUT
    persist_graph_session(session, graph, spec)
    return spec
