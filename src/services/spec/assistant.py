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
from src.services.spec.field_guidance import (
    attach_pending_default,
    build_progress_line,
    field_label,
    format_suggestion_prompt,
    next_field_to_ask,
    question_for_field_human,
    suggest_field_default,
)
from src.services.spec.parameter_extraction import is_affirmation, is_empty_value
from src.services.spec.validator import SpecValidator

logger = logging.getLogger("nexops.spec.assistant")

_CASHSCRIPT_MARKERS = re.compile(r"\b(pragma|require\(|contract\s+\w+|function\s+\w+)", re.I)


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
        if _CASHSCRIPT_MARKERS.search(user_message):
            return AssistantTurn(
                updated_spec=spec,
                message="I help complete the specification only — I cannot generate CashScript here.",
                still_missing=list(validation.missing_fields),
                progress=build_progress_line(spec, validation),
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

        suggested_default = None
        nxt = next_field_to_ask(updated, revalidation)
        if nxt and nxt in still_missing:
            updated, hint = attach_pending_default(updated, nxt)
            suggested_default = {nxt: updated.pending_parameters.get(nxt)}
            # Keep pending for "use standard"/yes, but don't duplicate when the LLM already asked.
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

    return f"""You are NexOps, a friendly Bitcoin Cash contract architect helping a user complete their specification.

Tone:
- Warm, concise, and human — like a helpful colleague, not a form or API
- Acknowledge what the user already provided before asking anything new
- Ask at most ONE follow-up question per turn (focus field: {focus_label or 'none'})
- Use plain language; avoid raw field names like "final_threshold" in your message text
- If suggesting a default, phrase it as an offer: "We can keep the final threshold at 50 — same as the start. Sound good?"

Rules:
- Do NOT generate CashScript
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
  "capabilities": ["existing capability names only"]
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
