"""Deterministic parameter extraction from natural-language spec replies."""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Set

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
    if not text:
        return {}
    cap_names = [c.name for c in spec.capabilities]
    allowed = all_known_field_names(cap_names)

    if "\n" in text or text.strip().startswith("-") or "requirements" in text.lower():
        merged: Dict[str, Any] = {}
        for line in re.split(r"\n+", text):
            cleaned = re.sub(r"^[\s\-•*]+", "", line).strip()
            if not cleaned or cleaned.lower().rstrip(":") == "requirements":
                continue
            _merge_extracted(merged, _extract_single_line(cleaned, allowed, cap_names))
        if merged:
            return {k: v for k, v in merged.items() if k in allowed and not is_empty_value(v)}

    return {
        k: v
        for k, v in _extract_single_line(text, allowed, cap_names).items()
        if k in allowed and not is_empty_value(v)
    }


def _merge_extracted(merged: Dict[str, Any], part: Dict[str, Any]) -> None:
    """Merge line extractions; append split recipients/shares from multiple bullets."""
    for key, value in part.items():
        if key in ("recipients", "shares") and key in merged and isinstance(merged[key], list):
            if isinstance(value, list):
                merged[key] = merged[key] + value
            else:
                merged[key] = value
        else:
            merged[key] = value


def _extract_single_line(
    text: str,
    allowed: Set[str],
    cap_names: List[str],
) -> Dict[str, Any]:
    lower = text.lower()
    out: Dict[str, Any] = {}

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
        elif re.search(r"\bpreserve\s+bch\b|\bbch\s+value\b", lower):
            out["asset_type"] = "bch"

    if "recipients" in allowed or "shares" in allowed:
        pct_matches = re.findall(r"(\d+)\s*%\s*to\s+([^,\n%.]+)", text, flags=re.I)
        if pct_matches:
            recipients: List[str] = []
            shares: List[int] = []
            for pct, name in pct_matches:
                shares.append(int(pct))
                recipients.append(_normalize_recipient_name(name))
            if "recipients" in allowed:
                out["recipients"] = recipients
            if "shares" in allowed:
                out["shares"] = shares

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
            vesting_lock = any(
                k in lower
                for k in (
                    "locked",
                    "lock",
                    "vesting",
                    "cliff",
                    "reclaim",
                    "refund",
                    "timeout",
                    "expire",
                    "delivery",
                    "deadline",
                    "within",
                    "after",
                )
            )
            if vesting_lock:
                out["timeout_days"] = int(timeout_match.group(1))

    if "signers" in allowed:
        party_signers = _extract_escrow_party_signers(lower)
        if party_signers:
            out["signers"] = party_signers
        else:
            named = _extract_comma_separated_names(text)
            if named and len(named) >= 2:
                out["signers"] = named

    if "threshold" in allowed:
        m_of_n = re.search(r"\b(\d+)\s*[- ]?of\s*[- ]?(\d+)\b", lower)
        if m_of_n:
            out["threshold"] = int(m_of_n.group(1))
            if "signers" in allowed and "signers" not in out:
                count = int(m_of_n.group(2))
                if count >= 2:
                    out["signers"] = [f"Signer{i + 1}" for i in range(count)]
        elif "both" in lower and "buyer" in lower and "seller" in lower:
            out["threshold"] = 2
            if "signers" in allowed and "signers" not in out:
                out["signers"] = _extract_escrow_party_signers(lower) or [
                    "Buyer",
                    "Seller",
                    "Arbiter",
                ]

    people_count = _extract_people_count(lower)
    if people_count:
        if "holders" in allowed:
            out["holders"] = people_count
        if "signers" in allowed and "signers" not in out:
            out["signers"] = [f"Signer{i + 1}" for i in range(people_count)]
        if "weights" in allowed and ("equal" in lower or "same" in lower):
            base = 100 // people_count
            rem = 100 - (base * people_count)
            weights = [base] * people_count
            weights[0] += rem
            out["weights"] = weights

    if "threshold" in allowed and "threshold" not in out:
        threshold_match = re.search(
            r"(?:threshold|approve|need|require|of)\s*(?:is|=|:)?\s*(\d+)\b",
            lower,
        )
        if not threshold_match:
            threshold_match = re.search(r"\b(\d+)\s*(?:of\s*\d+|enough|sufficient|signers?\b)", lower)
        if threshold_match:
            out["threshold"] = int(threshold_match.group(1))
        elif re.match(r"^\s*(\d+)\s*$", lower):
            out["threshold"] = int(lower.strip())

    return out


def _normalize_recipient_name(raw: str) -> str:
    name = raw.strip().rstrip(".- ")
    if re.match(r"^founder\s+[a-z]$", name, re.I):
        parts = name.split()
        return f"Founder {parts[-1].upper()}"
    if name.lower().startswith("founder "):
        rest = name[8:].strip()
        return f"Founder {rest.upper() if len(rest) == 1 else rest.title()}"
    return name.title() if name.islower() else name


def _extract_escrow_party_signers(lower: str) -> Optional[List[str]]:
    parties: List[str] = []
    for key, label in (
        ("buyer", "Buyer"),
        ("seller", "Seller"),
        ("arbiter", "Arbiter"),
        ("arbitrator", "Arbiter"),
    ):
        if re.search(rf"\b{key}\b", lower) and label not in parties:
            parties.append(label)
    return parties if len(parties) >= 2 else None


def _extract_comma_separated_names(text: str) -> List[str]:
    if "," not in text:
        return []
    parts = [p.strip() for p in text.replace(";", ",").split(",") if p.strip()]
    if len(parts) < 2:
        return []
    if all(re.match(r"^[A-Za-z][A-Za-z0-9_\- ]*$", p) for p in parts):
        return [p.title() if p.islower() else p for p in parts]
    return []


def _extract_people_count(lower: str) -> Optional[int]:
    match = re.search(
        r"\b(\d+)\s*(?:ppl|people|persons?|signers?|holders?|members?|keys?)\b",
        lower,
    )
    if match:
        return int(match.group(1))
    return None


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
        updated.parameters[key] = _normalize_param_value(key, value, updated.parameters)
        applied.add(key)
        updated.pending_parameters.pop(key, None)

    # If holders was set but signers is still a bare count / missing, expand names.
    if "holders" in applied or "signers" in applied:
        updated.parameters["signers"] = _expand_signers_param(
            updated.parameters.get("signers"),
            updated.parameters.get("holders"),
        )
        if not is_empty_value(updated.parameters.get("signers")):
            applied.add("signers")

    if confirm and applied:
        confirm_fields(updated, applied)
    return updated


def _normalize_param_value(key: str, value: Any, current: Dict[str, Any]) -> Any:
    if key == "signers":
        return _expand_signers_param(value, current.get("holders"))
    if key in {"threshold", "holders", "timeout_days", "duration_days", "initial_threshold", "final_threshold"}:
        if isinstance(value, bool):
            return value
        if isinstance(value, (int, float)):
            return int(value)
        if isinstance(value, str) and value.strip().isdigit():
            return int(value.strip())
    return value


def _expand_signers_param(signers: Any, holders: Any = None) -> Any:
    if isinstance(signers, list):
        if len(signers) == 1 and isinstance(signers[0], (int, float)):
            count = int(signers[0])
            return [f"Signer{i + 1}" for i in range(max(0, count))]
        if signers and all(isinstance(x, str) for x in signers):
            return signers
        if signers:
            return [str(x) for x in signers]
    if isinstance(signers, int):
        return [f"Signer{i + 1}" for i in range(max(0, signers))]
    if isinstance(signers, str) and signers.strip().isdigit():
        return [f"Signer{i + 1}" for i in range(int(signers.strip()))]
    if isinstance(signers, str) and signers.strip():
        parts = [p.strip() for p in signers.replace(";", ",").split(",") if p.strip()]
        if parts:
            return parts
    if isinstance(holders, int) and holders > 0:
        return [f"Signer{i + 1}" for i in range(holders)]
    if isinstance(holders, str) and holders.strip().isdigit():
        return [f"Signer{i + 1}" for i in range(int(holders.strip()))]
    return signers
