"""Stateful conversation turns for specification completion (no LLM required)."""

from __future__ import annotations

from typing import Any, Dict, Optional

from src.models import ContractSpecification, SpecStatus
from src.services.spec.parameter_extraction import (
    apply_parameter_updates,
    extract_parameters_from_message,
    extract_pending_from_assistant_message,
    is_affirmation,
)
from src.services.spec.validator import SpecValidator


def offer_default_for_uncertainty(
    spec: ContractSpecification,
    user_message: str,
) -> tuple[Optional[str], ContractSpecification, Optional[dict]]:
    """When the user is unsure or asks for standard, propose or apply a default."""
    from src.services.spec.field_guidance import (
        format_applied_default_message,
        format_suggestion_prompt,
        is_explicit_standard_request,
        is_uncertain_reply,
        next_field_to_ask,
        suggest_field_default,
    )

    if not is_uncertain_reply(user_message):
        return None, spec, None

    validation = SpecValidator.validate(spec)
    nxt = next_field_to_ask(spec, validation)
    if not nxt:
        return None, spec, None

    value, explanation = suggest_field_default(spec, nxt)
    if value is None or explanation == "":
        return None, spec, None

    if is_explicit_standard_request(user_message):
        updated = apply_parameter_updates(spec, {nxt: value})
        validation = SpecValidator.validate(updated)
        updated.status = SpecStatus.IN_REVIEW if validation.is_complete else SpecStatus.NEEDS_INPUT
        message = format_applied_default_message(updated, validation, nxt, value, explanation)
        return message, updated, {nxt: value}

    updated = spec.model_copy(deep=True)
    updated.pending_parameters = dict(updated.pending_parameters)
    updated.pending_parameters[nxt] = value
    message = format_suggestion_prompt(nxt, value, explanation)
    return message, updated, {nxt: value}


def build_opening_message(spec: ContractSpecification) -> str:
    """Friendly first message — one question, no form dump."""
    from src.services.spec.field_guidance import (
        build_progress_line,
        next_field_to_ask,
        question_for_field_human,
    )

    validation = SpecValidator.validate(spec)
    if validation.is_complete:
        return "Your specification looks complete — let's review it together."

    if not spec.capabilities:
        return (
            "Hey — I'm NexOps, your contract architect. Tell me what you're trying to build "
            "(multisig wallet, escrow, DAO treasury, auction, token, etc.) and we'll shape it together."
        )

    caps = ", ".join(c.name.replace("_", " ") for c in spec.capabilities)
    progress = build_progress_line(spec, validation)
    nxt = next_field_to_ask(spec, validation)
    if not nxt:
        return f"I've got the basics for your {caps} contract. {progress}"

    question = question_for_field_human(nxt)
    dao_note = ""
    cap_set = {c.name for c in spec.capabilities}
    if {"treasury", "vault", "weighted_multisig"}.issubset(cap_set) or (
        "weighted_multisig" in cap_set and ("treasury" in cap_set or "vault" in cap_set)
    ):
        dao_note = (
            " This sounds like a governance/funding DAO — we'll shape a treasury vault "
            "with weighted voting. Full Catalyst-style proposal voting isn't generated end-to-end yet, "
            "but we can capture the policy and point you to what we can generate today.\n\n"
        )

    return (
        f"I'll help you shape this {caps} contract step by step. {progress}\n\n"
        f"{dao_note}"
        f"First: {question} "
        f'(Answer in plain language, or say "use standard" for a sensible default.)'
    )


def apply_conversation_turn(
    spec: ContractSpecification,
    user_message: str,
    *,
    last_assistant_message: str = "",
) -> ContractSpecification:
    """
    Merge a user reply into the specification before optional LLM assistance.

    Handles incremental natural-language updates and affirmation of pending values.
    """
    updated = spec.model_copy(deep=True)

    if is_affirmation(user_message) and updated.pending_parameters:
        updated = apply_parameter_updates(updated, dict(updated.pending_parameters))

    extracted = extract_parameters_from_message(user_message, updated)
    if extracted:
        updated = apply_parameter_updates(updated, extracted)

    validation = SpecValidator.validate(updated)
    updated.status = SpecStatus.IN_REVIEW if validation.is_complete else SpecStatus.NEEDS_INPUT
    return updated


def merge_assistant_proposal(
    spec: ContractSpecification,
    assistant_message: str,
    llm_parameters: Dict[str, Any],
) -> ContractSpecification:
    """Apply LLM JSON parameters and stash unresolved proposals for affirmation."""
    updated = spec.model_copy(deep=True)
    pending = dict(updated.pending_parameters)

    if llm_parameters:
        updated = apply_parameter_updates(updated, llm_parameters)

    proposed = extract_pending_from_assistant_message(assistant_message, updated)
    for key, value in proposed.items():
        if key in updated.confirmed_fields:
            continue
        if key in updated.parameters and key in updated.confirmed_fields:
            continue
        if key not in updated.parameters or updated.parameters.get(key) in (None, ""):
            pending[key] = value

    updated.pending_parameters = pending
    validation = SpecValidator.validate(updated)
    updated.status = SpecStatus.IN_REVIEW if validation.is_complete else SpecStatus.NEEDS_INPUT
    return updated


def fields_to_ask(spec: ContractSpecification, validation) -> list[str]:
    """Fields still missing that are not already confirmed with values."""
    out = []
    for field in validation.missing_fields:
        if field in spec.confirmed_fields and not _value_missing(spec.parameters.get(field)):
            continue
        out.append(field)
    return out


def _value_missing(val: Any) -> bool:
    from src.services.spec.parameter_extraction import is_empty_value

    return is_empty_value(val)
