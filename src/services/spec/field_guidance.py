"""Human-friendly field labels, progress, defaults, and one-question flow."""

from __future__ import annotations

from typing import Any, List, Optional, Tuple

from src.models import ContractSpecification, ValidationResult
from src.services.spec.capabilities import CAPABILITY_REGISTRY, get_capability
from src.services.spec.parameter_extraction import is_empty_value
from src.services.spec.orchestrator import _default_for_field

FIELD_LABELS = {
    "initial_threshold": "starting approval threshold",
    "final_threshold": "final approval threshold",
    "duration_days": "decay period (days)",
    "asset_type": "asset type (BCH, FT, or NFT)",
    "holders": "number of key holders",
    "weights": "voting weights",
    "signers": "signers",
    "threshold": "signature threshold",
    "timeout_days": "timeout (days)",
    "recipients": "recipients",
    "shares": "payment shares",
    "start_price": "starting price",
    "min_price": "minimum price",
    "token_category": "token category (optional at deploy time)",
    "max_supply": "maximum supply",
}

_UNCERTAIN_PHRASES = (
    "not sure",
    "don't know",
    "dont know",
    "no idea",
    "you pick",
    "you choose",
    "whatever",
    "standard",
    "default",
    "recommend",
    "suggest",
    "up to you",
    "anything",
    "idk",
    "dunno",
)


def field_label(field_name: str) -> str:
    return FIELD_LABELS.get(field_name, field_name.replace("_", " "))


def is_uncertain_reply(message: str) -> bool:
    lower = message.strip().lower()
    return any(p in lower for p in _UNCERTAIN_PHRASES)


def is_explicit_standard_request(message: str) -> bool:
    """User explicitly wants the suggested standard — apply immediately, no extra yes."""
    lower = message.strip().lower()
    if lower in {"standard", "default", "use standard", "use default"}:
        return True
    explicit = (
        "use standard",
        "use default",
        "use the standard",
        "go with standard",
        "standard is fine",
        "default is fine",
    )
    return any(p in lower for p in explicit)


def next_field_to_ask(spec: ContractSpecification, validation: ValidationResult) -> Optional[str]:
    """Return the single highest-priority missing field, or None if complete."""
    for field in validation.missing_fields:
        if field in spec.confirmed_fields and not is_empty_value(spec.parameters.get(field)):
            continue
        return field
    return None


def suggest_field_default(
    spec: ContractSpecification,
    field_name: str,
) -> Tuple[Any, str]:
    """
    Context-aware default for a missing field.

    Returns (value, human explanation for the user).
    """
    params = spec.parameters
    intent = spec.intent or ""
    cap_names = {c.name for c in spec.capabilities}

    if field_name == "initial_threshold":
        if "linear_decay" in cap_names or "treasury" in cap_names or "vault" in cap_names:
            return (
                50,
                "a 50% starting approval level — common for treasury decay setups",
            )
        if params.get("final_threshold") is not None:
            final = params["final_threshold"]
            return final, f"match the starting level to your final threshold ({final})"

    if field_name == "final_threshold":
        initial = params.get("initial_threshold")
        if initial is not None and not is_empty_value(initial):
            return (
                initial,
                f"keep the final threshold at {initial} — the same as your starting level (no ramp over time)",
            )
        default = _default_for_field(field_name, intent)
        return default, f"use a standard final threshold of {default}"

    if field_name == "asset_type":
        if "ft" in intent.lower() or "token" in intent.lower():
            return "ft", "hold fungible tokens (FT) — you can set the exact category when you deploy"
        if "nft" in intent.lower():
            return "nft", "hold NFTs — you can set the exact category when you deploy"
        return "BCH", "hold native BCH (most common for treasuries)"

    if field_name == "duration_days":
        return 30, "use a 30-day decay period (common default)"

    if field_name == "threshold" and params.get("signers"):
        signers = params["signers"]
        if isinstance(signers, list) and len(signers) >= 2:
            return max(1, len(signers) - 1), f"use {max(1, len(signers) - 1)}-of-{len(signers)} multisig"

    default = _default_for_field(field_name, intent)
    if default is not None:
        return default, f"use the standard value: {default}"
    return None, ""


def build_progress_line(spec: ContractSpecification, validation: ValidationResult) -> str:
    """Short progress summary for CLI / API."""
    if validation.is_complete:
        return "All required details captured — ready for review."
    cap_names = {c.name for c in spec.capabilities}
    required_names: List[str] = []
    for cap_name in cap_names:
        cap = get_capability(cap_name)
        if not cap:
            continue
        for fs in cap.required_fields:
            if fs.name not in required_names:
                required_names.append(fs.name)
    total = len(required_names)
    filled = sum(
        1
        for name in required_names
        if not is_empty_value(spec.parameters.get(name))
    )
    nxt = next_field_to_ask(spec, validation)
    if nxt:
        return f"Progress: {filled}/{total} details — next: {field_label(nxt)}"
    return f"Progress: {filled}/{total} details"


def question_for_field_human(field_name: str) -> str:
    for cap in CAPABILITY_REGISTRY.values():
        for fs in cap.required_fields:
            if fs.name == field_name:
                if fs.question:
                    return fs.question
    return f"What should the {field_label(field_name)} be?"


def format_suggestion_prompt(field_name: str, value: Any, explanation: str) -> str:
    label = field_label(field_name)
    expl = explanation.rstrip(".")
    if str(value) in expl:
        return (
            f"No problem — {expl.capitalize()}. "
            f"Reply yes to confirm, or tell me what you'd prefer."
        )
    return (
        f"No problem — I'll use {value} for {label}: {expl}. "
        f"Reply yes to confirm, or tell me what you'd prefer."
    )


def format_applied_default_message(
    spec: ContractSpecification,
    validation: ValidationResult,
    field_name: str,
    value: Any,
    explanation: str,
) -> str:
    """Message after auto-applying a standard the user requested."""
    label = field_label(field_name)
    expl = explanation.rstrip(".")
    msg = f"Done — {label} is set to {value} ({expl})."
    nxt = next_field_to_ask(spec, validation)
    if validation.is_complete:
        return f"{msg}\n\nThat's everything I need — ready for review."
    if nxt:
        q = question_for_field_human(nxt)
        return f"{msg}\n\nNext: {q} (say \"use standard\" anytime you want a sensible default.)"
    return msg


def attach_pending_default(
    spec: ContractSpecification,
    field_name: str,
) -> tuple[ContractSpecification, str]:
    """Set pending default for a field and return the user-facing offer text."""
    value, explanation = suggest_field_default(spec, field_name)
    if value is None or not explanation:
        return spec, ""
    updated = spec.model_copy(deep=True)
    updated.pending_parameters = dict(updated.pending_parameters)
    updated.pending_parameters[field_name] = value
    return updated, format_suggestion_prompt(field_name, value, explanation)
