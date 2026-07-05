"""Conversational Specification Assistant — completes spec, never generates code."""

from __future__ import annotations

import json
import logging
import re
from typing import Any, Dict, Optional, Set

from src.models import AssistantTurn, ContractSpecification, SpecStatus, ValidationResult
from src.services.spec.capabilities import CAPABILITY_REGISTRY, get_capability
from src.services.spec.validator import SpecValidator

logger = logging.getLogger("nexops.spec.assistant")

_CASHSCRIPT_MARKERS = re.compile(r"\b(pragma|require\(|contract\s+\w+|function\s+\w+)", re.I)


class SpecificationAssistant:
    @staticmethod
    async def respond(
        spec: ContractSpecification,
        validation: ValidationResult,
        user_message: str,
        api_key: Optional[str] = None,
        provider: Optional[str] = None,
        openrouter_key: Optional[str] = None,
    ) -> AssistantTurn:
        if _CASHSCRIPT_MARKERS.search(user_message):
            return AssistantTurn(
                updated_spec=spec,
                message="I help complete the specification only — I cannot generate CashScript here.",
                still_missing=list(validation.missing_fields),
            )

        registry_ctx = _registry_context_for_spec(spec, validation)
        prompt = _build_assistant_prompt(spec, validation, registry_ctx, user_message)

        from src.services.llm.factory import LLMFactory

        llm = LLMFactory.get_provider(
            "phase1",
            api_key=api_key,
            provider_type=provider,
            openrouter_key=openrouter_key,
        )
        raw = await llm.complete(prompt)
        updated, message = _parse_assistant_response(raw, spec, validation)

        # Code-enforced constraints
        updated = _strip_unknown_capabilities(updated)
        updated = _merge_allowed_parameters(updated, spec)
        revalidation = SpecValidator.validate(updated)
        if not message:
            message = _fallback_message(revalidation)

        return AssistantTurn(
            updated_spec=updated,
            message=message,
            still_missing=list(revalidation.missing_fields),
        )


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
) -> str:
    return f"""You are the NexOps Specification Assistant. Help the user complete their contract specification.

You may:
- Ask conversational follow-up questions
- Explain concepts
- Recommend configurations from the registry
- Propose parameter updates

You must NOT:
- Invent unsupported capabilities
- Generate CashScript
- Bypass required fields

Current specification:
{spec.model_dump_json()}

Missing fields: {validation.missing_fields}
Registry context:
{registry_ctx}

User message: {user_message}

Respond with JSON only:
{{
  "message": "your conversational reply",
  "parameters": {{ "field_name": value }},
  "capabilities": ["existing capability names only"]
}}"""


def _parse_assistant_response(
    raw: str,
    spec: ContractSpecification,
    validation: ValidationResult,
) -> tuple[ContractSpecification, str]:
    text = raw.strip()
    if "```" in text:
        match = re.search(r"```(?:json)?\s*(.*?)\s*```", text, re.DOTALL)
        if match:
            text = match.group(1).strip()
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return spec, raw.strip()[:500]

    updated = spec.model_copy(deep=True)
    params = data.get("parameters") or {}
    if isinstance(params, dict):
        for k, v in params.items():
            if k in validation.missing_fields or k in updated.parameters:
                updated.parameters[k] = v

    caps = data.get("capabilities")
    if isinstance(caps, list):
        known = {c.name for c in updated.capabilities}
        for c in caps:
            cn = str(c).lower().strip()
            if cn in CAPABILITY_REGISTRY and cn not in known:
                from src.models import CapabilityInstance
                updated.capabilities.append(CapabilityInstance(name=cn, parameters={}))

    if validation.is_complete:
        updated.status = SpecStatus.IN_REVIEW
    else:
        updated.status = SpecStatus.NEEDS_INPUT

    return updated, str(data.get("message") or "")


def _strip_unknown_capabilities(spec: ContractSpecification) -> ContractSpecification:
    spec.capabilities = [c for c in spec.capabilities if c.name in CAPABILITY_REGISTRY]
    return spec


def _merge_allowed_parameters(
    updated: ContractSpecification,
    original: ContractSpecification,
) -> ContractSpecification:
    if original.status == SpecStatus.CONFIRMED:
        updated.parameters = dict(original.parameters)
    return updated


def _fallback_message(validation: ValidationResult) -> str:
    if validation.is_complete:
        return "Your specification looks complete. Ready for review."
    missing = ", ".join(validation.missing_fields)
    return f"I still need: {missing}."
