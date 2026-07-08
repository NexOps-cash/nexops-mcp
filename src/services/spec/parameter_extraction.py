"""Deterministic parameter extraction from natural-language spec replies."""

from __future__ import annotations

import re
from typing import Any, Dict, List, Set

from src.models import ContractSpecification
from src.services.spec.capabilities import all_known_field_names

_AFFIRMATIONS = frozenset({
    "yes",
    "y",
    "yeah",
    "yep",
    "correct",
    "confirm",
    "confirmed",
    "that's right",
    "thats right",
    "ok",
    "okay",
    "sure",
    "right",
})


def is_affirmation(message: str) -> bool:
    text = message.strip().lower().rstrip(".!")
    return text in _AFFIRMATIONS


def is_empty_value(val: Any) -> bool:
    if val is None:
        return True
    if val == "":
        return True
    if isinstance(val, (list, dict)) and len(val) == 0:
        return True
    return False


def normalize_asset_type(raw: str) -> str:
    text = raw.strip().lower()
    if text in {"ft", "token", "fungible", "fungible token"}:
        return "ft"
    if text == "nft":
        return "nft"
    if text in {"bch", "bitcoin", "cash"}:
        return "bch"
    return text


def extract_parameters_from_message(
    message: str,
    spec: ContractSpecification,
) -> Dict[str, Any]:
    """Best-effort parse of user text into specification parameters."""
    text = message.strip()
    lower = text.lower()
    out: Dict[str, Any] = {}
    cap_names = [c.name for c in spec.capabilities]
    allowed = all_known_field_names(cap_names)

    if "asset_type" in allowed:
        asset_match = re.search(
            r"(?:asset(?:\s*type)?|hold(?:s|ing)?)\s*(?:is\s*)?(ft|nft|bch|token)\b",
            lower,
        )
        if not asset_match:
            asset_match = re.search(r"\basset\s+(ft|nft|bch|token)\b", lower)
        if asset_match:
            out["asset_type"] = normalize_asset_type(asset_match.group(1))
        elif re.search(r"\b(ft|nft)\b", lower) and re.search(r"\basset\b", lower):
            token = re.search(r"\b(ft|nft)\b", lower)
            if token:
                out["asset_type"] = normalize_asset_type(token.group(1))

    if "duration_days" in allowed:
        duration_match = re.search(r"(\d+)\s*days?\b", lower)
        if duration_match:
            out["duration_days"] = int(duration_match.group(1))

    if "initial_threshold" in allowed or "final_threshold" in allowed:
        threshold_days = re.match(r"^\s*(\d+)\s+(\d+)\s*days?\b", lower)
        if threshold_days:
            if "initial_threshold" in allowed:
                out["initial_threshold"] = int(threshold_days.group(1))
            if "duration_days" in allowed:
                out["duration_days"] = int(threshold_days.group(2))
        else:
            pair_match = re.match(r"^\s*(\d+)\s+(\d+)\b", text)
            if pair_match:
                if "initial_threshold" in allowed:
                    out.setdefault("initial_threshold", int(pair_match.group(1)))
                if "final_threshold" in allowed:
                    out.setdefault("final_threshold", int(pair_match.group(2)))

    if "final_threshold" in allowed:
        final_match = re.search(
            r"(?:final(?:\s*threshold)?|fina(?:l)?)\s*(?:is|=|:)?\s*(\d+)",
            lower,
        )
        if final_match:
            out["final_threshold"] = int(final_match.group(1))

    if "initial_threshold" in allowed:
        initial_match = re.search(
            r"initial(?:\s*threshold)?\s*(?:is|=|:)?\s*(\d+)",
            lower,
        )
        if initial_match:
            out["initial_threshold"] = int(initial_match.group(1))

    if "timeout_days" in allowed:
        timeout_match = re.search(r"(\d+)\s*days?\b", lower)
        if timeout_match and "duration_days" not in out:
            out["timeout_days"] = int(timeout_match.group(1))

    return {k: v for k, v in out.items() if k in allowed and not is_empty_value(v)}


def extract_pending_from_assistant_message(message: str, spec: ContractSpecification) -> Dict[str, Any]:
    """Parse proposed values from assistant clarification text (for yes confirmations)."""
    lower = message.lower()
    cap_names = [c.name for c in spec.capabilities]
    allowed = all_known_field_names(cap_names)
    out: Dict[str, Any] = {}

    patterns = [
        (r"final_threshold should be (\d+)", "final_threshold", int),
        (r"initial_threshold should be (\d+)", "initial_threshold", int),
        (r"duration_days should be (\d+)", "duration_days", int),
        (r"asset_type should be ['\"]?(ft|nft|bch|token)['\"]?", "asset_type", normalize_asset_type),
        (r"final_threshold of (\d+)", "final_threshold", int),
        (r"final_threshold is (\d+)", "final_threshold", int),
        (r"asset_type (?:is|to) ['\"]?(ft|nft|bch)['\"]?", "asset_type", normalize_asset_type),
        (r"mean(?:ing)?[:\s]+final_threshold=(\d+)", "final_threshold", int),
        (r"final_threshold=(\d+)", "final_threshold", int),
        (r"asset_type=['\"]?(ft|nft|bch)['\"]?", "asset_type", normalize_asset_type),
    ]
    for pattern, field, conv in patterns:
        if field not in allowed:
            continue
        match = re.search(pattern, lower)
        if match:
            out[field] = conv(match.group(1))

    return out


def confirm_fields(spec: ContractSpecification, field_names: Set[str]) -> None:
    confirmed = set(spec.confirmed_fields)
    confirmed.update(field_names)
    spec.confirmed_fields = sorted(confirmed)


def apply_parameter_updates(
    spec: ContractSpecification,
    updates: Dict[str, Any],
    *,
    confirm: bool = True,
) -> ContractSpecification:
    updated = spec.model_copy(deep=True)
    applied: Set[str] = set()
    for key, value in updates.items():
        if is_empty_value(value):
            continue
        updated.parameters[key] = value
        applied.add(key)
        updated.pending_parameters.pop(key, None)
    if confirm and applied:
        confirm_fields(updated, applied)
    return updated
