"""Specification conversation controller — spec_turn, review, confirm, modify."""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from src.models import ContractSpecification, MCPRequest, SpecStatus
from src.services.session import get_session_manager
from src.services.spec.assistant import SpecificationAssistant
from src.services.spec.orchestrator import merge_answers, run_spec_pipeline
from src.services.spec.review import confirm_specification, modify_specification, render_specification
from src.services.spec.validator import SpecValidator
from src.services.spec.support_assessment import assess_composition_support
from src.services.spec.planner import ModulePlanner

logger = logging.getLogger("nexops.spec.controller")


def _error(request_id: str, code: str, message: str) -> Dict[str, Any]:
    return {
        "request_id": request_id,
        "type": "error",
        "error": {"code": code, "message": message},
    }


def _load_spec(req: MCPRequest, session) -> Optional[ContractSpecification]:
    payload_spec = req.payload.get("specification")
    if payload_spec:
        return ContractSpecification(**payload_spec)
    if session.current_specification:
        return session.current_specification
    return None


async def spec_turn(req: MCPRequest) -> Dict[str, Any]:
    intent = req.payload.get("user_request") or req.payload.get("intent") or ""
    user_message = req.payload.get("message") or intent
    session_id = req.payload.get("session_id")
    session = get_session_manager().get_or_create(session_id)

    api_key = (req.context or {}).get("api_key")
    provider = (req.context or {}).get("provider")
    openrouter_key = (req.context or {}).get("openrouter_key")

    spec = _load_spec(req, session)
    if spec is None and intent:
        spec, _, _, _, _, _ = await run_spec_pipeline(
            intent,
            resolution_mode="interactive",
            api_key=api_key,
            provider=provider,
            openrouter_key=openrouter_key,
        )
    if spec is None:
        return _error(req.request_id, "MISSING_SPEC", "No specification in session or payload.")

    answers = req.payload.get("answers")
    if answers and isinstance(answers, dict):
        spec = merge_answers(spec, answers)

    validation = SpecValidator.validate(spec)
    if user_message and not validation.is_complete:
        mgr = get_session_manager()
        opening_msg = None
        if not session.spec_chat_history:
            opening_msg = SpecificationAssistant.opening_message(spec)
            mgr.append_spec_chat(session.session_id, "assistant", opening_msg)
        turn = await SpecificationAssistant.respond(
            spec,
            validation,
            user_message,
            api_key=api_key,
            provider=provider,
            openrouter_key=openrouter_key,
            chat_history=session.spec_chat_history,
        )
        mgr.append_spec_chat(session.session_id, "user", user_message)
        mgr.append_spec_chat(session.session_id, "assistant", turn.message)
        spec = turn.updated_spec
        validation = SpecValidator.validate(spec)
        session.current_specification = spec
        display_message = f"{opening_msg}\n\n{turn.message}" if opening_msg else turn.message
        return {
            "request_id": req.request_id,
            "type": "spec_turn",
            "data": {
                "message": display_message,
                "specification": spec.model_dump(),
                "still_missing": turn.still_missing,
                "progress": turn.progress,
                "suggested_default": turn.suggested_default,
                "is_complete": validation.is_complete,
                "session_id": session.session_id,
            },
        }

    if not validation.is_complete and not session.spec_chat_history:
        opening = SpecificationAssistant.opening_message(spec)
        get_session_manager().append_spec_chat(session.session_id, "assistant", opening)
        session.current_specification = spec
        return {
            "request_id": req.request_id,
            "type": "spec_turn",
            "data": {
                "message": opening,
                "specification": spec.model_dump(),
                "still_missing": validation.missing_fields,
                "progress": "",
                "is_complete": False,
                "session_id": session.session_id,
            },
        }

    if validation.is_complete:
        spec.status = SpecStatus.IN_REVIEW
    session.current_specification = spec
    return {
        "request_id": req.request_id,
        "type": "spec_turn",
        "data": {
            "message": "Specification complete. Request spec_review to confirm.",
            "specification": spec.model_dump(),
            "still_missing": validation.missing_fields,
            "is_complete": validation.is_complete,
            "session_id": session.session_id,
        },
    }


async def spec_review(req: MCPRequest) -> Dict[str, Any]:
    session_id = req.payload.get("session_id")
    session = get_session_manager().get_or_create(session_id)
    spec = _load_spec(req, session)
    if spec is None:
        return _error(req.request_id, "MISSING_SPEC", "No specification to review.")

    validation = SpecValidator.validate(spec)
    if not validation.is_complete:
        return _error(req.request_id, "INCOMPLETE_SPEC", f"Missing: {validation.missing_fields}")

    spec.status = SpecStatus.IN_REVIEW
    review = render_specification(spec)
    modules, _ = ModulePlanner.select_modules(spec)
    from src.models import ExecutionPlan, PlanningReport
    from src.services.spec.architecture import ArchitectureBuilder
    from src.services.spec.phase2_adapter import resolve_effective_mode

    plan = ExecutionPlan(
        modules=modules,
        order=[m.name for m in modules],
        dependencies={m.name: list(m.depends_on) for m in modules},
        shared_parameters=dict(spec.parameters),
    )
    utxo = ArchitectureBuilder.build(plan, spec)
    report = PlanningReport(
        detected_capabilities=[c.name for c in spec.capabilities],
        selected_modules=[m.name for m in modules],
        effective_mode=resolve_effective_mode(utxo, plan),
    )
    composition_support = assess_composition_support(spec, report)
    session.current_specification = spec
    return {
        "request_id": req.request_id,
        "type": "spec_review",
        "data": {
            "review": review.model_dump(),
            "specification": spec.model_dump(),
            "composition_support": composition_support.model_dump(),
            "planning_report": report.model_dump(),
            "session_id": session.session_id,
        },
    }


async def spec_confirm(req: MCPRequest) -> Dict[str, Any]:
    session_id = req.payload.get("session_id")
    session = get_session_manager().get_or_create(session_id)
    spec = _load_spec(req, session)
    if spec is None:
        return _error(req.request_id, "MISSING_SPEC", "No specification to confirm.")

    spec = confirm_specification(spec)
    session.current_specification = spec
    return {
        "request_id": req.request_id,
        "type": "spec_confirm",
        "data": {
            "specification": spec.model_dump(),
            "session_id": session.session_id,
            "message": "Specification confirmed. Call generate with this session.",
        },
    }


async def spec_modify(req: MCPRequest) -> Dict[str, Any]:
    session_id = req.payload.get("session_id")
    session = get_session_manager().get_or_create(session_id)
    spec = _load_spec(req, session)
    if spec is None:
        return _error(req.request_id, "MISSING_SPEC", "No specification to modify.")

    spec = modify_specification(spec)
    session.current_specification = spec
    return {
        "request_id": req.request_id,
        "type": "spec_modify",
        "data": {
            "specification": spec.model_dump(),
            "session_id": session.session_id,
            "message": "Conversation reopened. Send spec_turn with your changes.",
        },
    }
