"""Conversational Specification Assistant — completes spec, never generates code."""

from __future__ import annotations

import json
import logging
import re
from typing import Any, Dict, List, Optional

from src.models import AssistantTurn, ContractSpecification, SpecChatTurn, SpecStatus, ValidationResult
from src.services.spec.capabilities import CAPABILITY_REGISTRY, all_known_field_names, get_capability
from src.services.spec.conversation import (
    apply_conversation_turn,
    build_opening_message,
    fields_to_ask,
    merge_assistant_proposal,
    offer_default_for_uncertainty,
)
from src.services.spec.discovery import is_in_discovery_phase, try_discover_specification
from src.services.spec.field_guidance import (
    attach_pending_default,
    build_progress_line,
    field_label,
    next_field_to_ask,
    question_for_field_human,
    suggest_field_default,
)
from src.services.spec.intent_pivot import (
    backdoor_refusal_message,
    is_backdoor_request,
    looks_like_cashscript_injection,
    try_pivot_specification,
)
from src.services.spec.parameter_extraction import is_affirmation, is_empty_value
from src.services.spec.validator import SpecValidator

logger = logging.getLogger("nexops.spec.assistant")


class SpecificationAssistant:
    @staticmethod
    def opening_message(spec: ContractSpecification) -> str:
        return build_opening_message(spec)

    @staticmethod
    async def respond(
        spec: ContractSpecification,
        validation: ValidationResult,
        user_message: str,
        api_key: Optional[str] = None,
        provider: Optional[str] = None,
        openrouter_key: Optional[str] = None,
        last_assistant_message: str = "",
        chat_history: Optional[List[SpecChatTurn]] = None,
    ) -> AssistantTurn:
        if is_backdoor_request(user_message):
            return AssistantTurn(
                updated_spec=spec,
                message=backdoor_refusal_message(),
                still_missing=fields_to_ask(spec, validation),
                progress=build_progress_line(spec, validation),
            )

        if looks_like_cashscript_injection(user_message):
            return AssistantTurn(
                updated_spec=spec,
                message=(
                    "Paste CashScript later if you want — for now let's keep this as a clean "
                    "specification. Once we confirm the design, NexOps will generate the contract "
                    "code for you."
                ),
                still_missing=list(validation.missing_fields),
                progress=build_progress_line(spec, validation),
            )

        if is_in_discovery_phase(spec):
            return await _discovery_turn(
                spec,
                validation,
                user_message,
                api_key=api_key,
                provider=provider,
                openrouter_key=openrouter_key,
                chat_history=chat_history,
            )

        pivot_spec, pivot_ack = try_pivot_specification(spec, user_message)
        if pivot_spec is not None:
            validation = SpecValidator.validate(pivot_spec)
            nxt = next_field_to_ask(pivot_spec, validation)
            follow = f"\n\nNext: {question_for_field_human(nxt)}" if nxt else ""
            return AssistantTurn(
                updated_spec=pivot_spec,
                message=f"{pivot_ack}{follow}",
                still_missing=fields_to_ask(pivot_spec, validation),
                progress=build_progress_line(pivot_spec, validation),
            )

        updated = apply_conversation_turn(
            spec,
            user_message,
            last_assistant_message=last_assistant_message,
        )
        validation = SpecValidator.validate(updated)

        # User unsure → offer a standard default (e.g. final threshold = initial 50)
        uncertain_msg, updated, suggested = offer_default_for_uncertainty(updated, user_message)
        if uncertain_msg:
            validation = SpecValidator.validate(updated)
            return AssistantTurn(
                updated_spec=updated,
                message=uncertain_msg,
                still_missing=fields_to_ask(updated, validation),
                progress=build_progress_line(updated, validation),
                suggested_default=suggested,
            )

        # Affirmation applied pending defaults — skip LLM, acknowledge warmly
        if is_affirmation(user_message) and validation.is_complete:
            return AssistantTurn(
                updated_spec=updated,
                message="Perfect — I've got everything I need. Ready for review when you are.",
                still_missing=[],
                progress=build_progress_line(updated, validation),
            )
        if is_affirmation(user_message) and updated.pending_parameters:
            validation = SpecValidator.validate(updated)
            nxt = next_field_to_ask(updated, validation)
            if nxt:
                question = question_for_field_human(nxt)
                return AssistantTurn(
                    updated_spec=updated,
                    message=f"Got it. Next up: {question}",
                    still_missing=fields_to_ask(updated, validation),
                    progress=build_progress_line(updated, validation),
                )
            return AssistantTurn(
                updated_spec=updated,
                message="Got it — that default is set.",
                still_missing=fields_to_ask(updated, validation),
                progress=build_progress_line(updated, validation),
            )

        registry_ctx = _registry_context_for_spec(updated, validation)
        prompt = _build_assistant_prompt(
            updated,
            validation,
            registry_ctx,
            user_message,
            chat_history=chat_history or [],
        )

        from src.services.llm.factory import LLMFactory

        llm = LLMFactory.get_provider(
            "spec_chat",
            api_key=api_key,
            provider_type=provider,
            openrouter_key=openrouter_key,
        )
        raw = await llm.complete(prompt)
        llm_params, message = _parse_assistant_response(raw, updated)

        updated = merge_assistant_proposal(updated, message or raw, llm_params)
        updated = _strip_unknown_capabilities(updated)
        updated = _merge_allowed_parameters(updated, spec)

        revalidation = SpecValidator.validate(updated)
        still_missing = fields_to_ask(updated, revalidation)

        if not message or _looks_like_form_dump(message):
            message = _craft_fallback_message(updated, revalidation, still_missing)

        # Soften overconfident external/IDE handoff language if the model slips
        message = _strip_external_handoff_language(message)

        suggested_default = None
        nxt = next_field_to_ask(updated, revalidation)
        if nxt and nxt in still_missing:
            updated, hint = attach_pending_default(updated, nxt)
            suggested_default = {nxt: updated.pending_parameters.get(nxt)}
            if hint and (
                not message
                or _looks_like_form_dump(message)
                or not _llm_addressed_field(message, nxt)
            ):
                if "reply yes" not in message.lower():
                    message = f"{message}\n\n{hint}" if message else hint

        if revalidation.is_complete:
            updated.status = SpecStatus.IN_REVIEW
        else:
            updated.status = SpecStatus.NEEDS_INPUT

        return AssistantTurn(
            updated_spec=updated,
            message=message,
            still_missing=still_missing,
            progress=build_progress_line(updated, revalidation),
            suggested_default=suggested_default,
        )


async def _discovery_turn(
    spec: ContractSpecification,
    validation: ValidationResult,
    user_message: str,
    *,
    api_key: Optional[str] = None,
    provider: Optional[str] = None,
    openrouter_key: Optional[str] = None,
    chat_history: Optional[List[SpecChatTurn]] = None,
) -> AssistantTurn:
    """Conversational discovery — no assumed contract type, no field rush."""
    discovered = try_discover_specification(spec, user_message)
    if discovered is not None:
        revalidation = SpecValidator.validate(discovered)
        caps = ", ".join(c.name.replace("_", " ") for c in discovered.capabilities)
        nxt = next_field_to_ask(discovered, revalidation)
        follow = question_for_field_human(nxt) if nxt else ""
        message = (
            f"Got it — let's shape a {caps} contract."
            + (f" {follow}" if follow else "")
        )
        return AssistantTurn(
            updated_spec=discovered,
            message=message,
            still_missing=fields_to_ask(discovered, revalidation),
            progress=build_progress_line(discovered, revalidation),
        )

    from src.services.llm.factory import LLMFactory

    prompt = _build_discovery_prompt(user_message, chat_history or [])
    llm = LLMFactory.get_provider(
        "spec_chat",
        api_key=api_key,
        provider_type=provider,
        openrouter_key=openrouter_key,
    )
    raw = await llm.complete(prompt)
    working = spec.model_copy(deep=True)
    _, message = _parse_assistant_response(raw, working)

    if not message:
        message = (
            "I'm here to help you design a Bitcoin Cash smart contract. "
            "What are you trying to build?"
        )

    discovered = try_discover_specification(working, user_message)
    if discovered is None and working.capabilities:
        discovered = working
        discovered.status = SpecStatus.NEEDS_INPUT

    if discovered is not None and discovered.capabilities:
        revalidation = SpecValidator.validate(discovered)
        nxt = next_field_to_ask(discovered, revalidation)
        if nxt:
            message = f"{message}\n\n{question_for_field_human(nxt)}"
        return AssistantTurn(
            updated_spec=discovered,
            message=message.strip(),
            still_missing=fields_to_ask(discovered, revalidation),
            progress=build_progress_line(discovered, revalidation),
        )

    return AssistantTurn(
        updated_spec=spec,
        message=message.strip(),
        still_missing=["contract_type"],
        progress="",
    )


def _build_discovery_prompt(user_message: str, chat_history: List[SpecChatTurn]) -> str:
    cap_names = ", ".join(sorted(CAPABILITY_REGISTRY.keys()))
    return f"""You are NexOps — the in-product Bitcoin Cash contract architect.
The user has not chosen a contract pattern yet. They may be greeting you, making small talk, or exploring ideas.

Tone:
- Respond naturally to what they actually said (answer greetings briefly and warmly)
- Do NOT assume multisig or any specific contract type
- Do NOT ask for signers, thresholds, weights, or other spec fields yet
- Gently invite them to describe what they want to build when it fits the conversation
- Stay concise (1-2 short paragraphs)

When they clearly describe a contract pattern, set "capabilities" using ONLY names from:
{cap_names}

Conversation so far:
{_format_chat_history(chat_history)}

User message: {user_message}

Respond with JSON only:
{{
  "message": "your conversational reply",
  "parameters": {{}},
  "capabilities": []
}}"""


def _strip_external_handoff_language(message: str) -> str:
    """NexOps owns generation — never tell users to leave for another IDE mid-spec."""
    banned = (
        "hand it to a developer",
        "cashscript ide",
        "outside what i do",
        "outside of what i do",
        "you'll need a developer",
        "someone else must implement",
    )
    lower = message.lower()
    if any(b in lower for b in banned):
        return (
            "I'm with you inside NexOps — we'll finish the specification here, then generate "
            "CashScript from it. I won't design hidden or undisclosed spend paths, but honest "
            "controls (owner recovery, timelock, burn, vault) are fair game.\n\n"
            "What direction should we take the design?"
        )
    return message


def _looks_like_form_dump(message: str) -> bool:
    lower = message.lower()
    return lower.count("**") >= 2 or "still need" in lower or "please provide" in lower


def _llm_addressed_field(message: str, field_name: str) -> bool:
    """True when the LLM reply already asks about this field naturally."""
    lower = message.lower()
    label = field_label(field_name).lower()
    keywords = {
        "final_threshold": ("final", "end up", "where should it end", "ramp", "ending"),
        "duration_days": ("how long", "days", "timeframe", "period", "over"),
        "asset_type": ("asset", "bch", "ft", "nft", "holding", "token"),
        "initial_threshold": ("starting", "initial", "baseline", "begin"),
    }
    if label in lower:
        return True
    return any(kw in lower for kw in keywords.get(field_name, ()))


def _format_chat_history(turns: List[SpecChatTurn], limit: int = 8) -> str:
    if not turns:
        return "(no prior messages)"
    lines = []
    for turn in turns[-limit:]:
        role = "User" if turn.role == "user" else "Assistant"
        lines.append(f"{role}: {turn.content}")
    return "\n".join(lines)


def _registry_context_for_spec(
    spec: ContractSpecification,
    validation: ValidationResult,
) -> str:
    lines = []
    for cap_inst in spec.capabilities:
        cap = get_capability(cap_inst.name)
        if not cap:
            continue
        lines.append(f"Capability: {cap.name}")
        for doc in cap.documentation:
            lines.append(f"  Doc: {doc}")
        for rec in cap.recommendations:
            lines.append(f"  Recommendation: {rec}")
    return "\n".join(lines)


def _build_assistant_prompt(
    spec: ContractSpecification,
    validation: ValidationResult,
    registry_ctx: str,
    user_message: str,
    *,
    chat_history: List[SpecChatTurn],
) -> str:
    confirmed = spec.confirmed_fields or []
    still_needed = fields_to_ask(spec, validation)
    focus_field = next_field_to_ask(spec, validation)
    focus_label = field_label(focus_field) if focus_field else ""
    focus_question = question_for_field_human(focus_field) if focus_field else ""

    pending_note = ""
    if spec.pending_parameters:
        pending_note = f"Pending user confirmation: {spec.pending_parameters}"

    return f"""You are NexOps — the in-product Bitcoin Cash contract architect.
You stay with the user for the whole flow: clarify → specify → review → generate.
You are NOT an external consultant and you must NEVER tell them to leave for another IDE,
hire a developer, or "hand the spec to someone else to implement".

Tone:
- Warm, concise, and human — like a teammate inside NexOps
- Acknowledge what the user provided, then move the design forward
- Ask at most ONE follow-up question per turn (focus field: {focus_label or 'none'})
- Use plain language; avoid raw field names like "final_threshold" in your message text

Pivots:
- If the user changes their mind (e.g. "do a fund lock instead", "burn forever"), acknowledge the new direction
- Stop asking about fields that no longer apply
- Prefer listing the new intent in plain terms over clinging to the old pattern

Safety (product policy):
- Refuse hidden backdoors / secret spend paths only the requester knows about
- Offer honest alternatives: documented owner recovery, timelock vault, or permanent burn

Rules:
- Do NOT generate CashScript source in chat
- Do NOT invent unsupported capabilities
- Do NOT re-ask confirmed fields: {confirmed}
- Do NOT list every missing field — only discuss the focus field unless the user asked something broader
- When the user supplies values, ALWAYS echo them in the parameters JSON object
- Optional deploy-time fields (token_category) must NOT block the conversation

Conversation so far:
{_format_chat_history(chat_history)}

Current specification:
{spec.model_dump_json()}

{pending_note}
Still needed (internal): {still_needed}
Focus this turn on: {focus_question}
Registry context:
{registry_ctx}

User message: {user_message}

Respond with JSON only:
{{
  "message": "your warm conversational reply (1-3 short paragraphs max)",
  "parameters": {{ "field_name": value }},
  "capabilities": ["capability names for THIS design — may change on pivot"]
}}"""


def _parse_assistant_response(
    raw: str,
    spec: ContractSpecification,
) -> tuple[Dict[str, Any], str]:
    text = raw.strip()
    if "```" in text:
        match = re.search(r"```(?:json)?\s*(.*?)\s*```", text, re.DOTALL)
        if match:
            text = match.group(1).strip()
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return {}, raw.strip()[:500]

    params: Dict[str, Any] = {}
    cap_names = [c.name for c in spec.capabilities]
    allowed = all_known_field_names(cap_names)
    raw_params = data.get("parameters") or {}
    if isinstance(raw_params, dict):
        for k, v in raw_params.items():
            if k in allowed and not is_empty_value(v):
                params[k] = v

    caps = data.get("capabilities")
    if isinstance(caps, list):
        known = {c.name for c in spec.capabilities}
        for c in caps:
            cn = str(c).lower().strip()
            if cn in CAPABILITY_REGISTRY and cn not in known:
                from src.models import CapabilityInstance
                spec.capabilities.append(CapabilityInstance(name=cn, parameters={}))

    return params, str(data.get("message") or "")


def _strip_unknown_capabilities(spec: ContractSpecification) -> ContractSpecification:
    spec.capabilities = [c for c in spec.capabilities if c.name in CAPABILITY_REGISTRY]
    return spec


def _merge_allowed_parameters(
    updated: ContractSpecification,
    original: ContractSpecification,
) -> ContractSpecification:
    if original.status == SpecStatus.CONFIRMED:
        updated.parameters = dict(original.parameters)
        updated.confirmed_fields = list(original.confirmed_fields)
        updated.pending_parameters = {}
        return updated

    merged_params = dict(original.parameters)
    merged_params.update(updated.parameters)
    updated.parameters = merged_params

    confirmed = set(original.confirmed_fields) | set(updated.confirmed_fields)
    updated.confirmed_fields = sorted(confirmed)

    pending = dict(original.pending_parameters)
    pending.update(updated.pending_parameters)
    for key in updated.confirmed_fields:
        pending.pop(key, None)
    updated.pending_parameters = pending
    return updated


def _craft_fallback_message(
    spec: ContractSpecification,
    validation: ValidationResult,
    still_missing: List[str],
) -> str:
    if validation.is_complete:
        return "Looks good — your specification is ready for review."

    nxt = next_field_to_ask(spec, validation)
    if not nxt:
        return "Almost there — just a couple more details."

    captured = []
    for key in spec.confirmed_fields:
        if key in spec.parameters:
            captured.append(f"{field_label(key)}: {spec.parameters[key]}")
    ack = ""
    if captured:
        ack = f"I've noted {'; '.join(captured[-3:])}. "

    value, explanation = suggest_field_default(spec, nxt)
    question = question_for_field_human(nxt)
    if value is not None:
        return (
            f"{ack}{question} "
            f"If you're not sure, we can {explanation.lower()} — just say yes."
        )
    return f"{ack}{question}"
