"""Mid-conversation intent pivots and unsafe-request handling."""

from __future__ import annotations

import re
from typing import List, Optional, Set, Tuple

from src.models import CapabilityInstance, ContractSpecification, SpecStatus, RawIntent
from src.services.spec.detection import detect_capabilities
from src.services.spec.validator import SpecValidator

_PIVOT_PHRASES = (
    "instead",
    "rather",
    "forget that",
    "scratch that",
    "change of plan",
    "different idea",
    "lets do",
    "let's do",
    "i want a",
    "i need a",
    "actually",
    "switch to",
    "pivot",
)

_BURN_KEYS = (
    "never release",
    "forever stuck",
    "gone forever",
    "burn",
    "irreversible",
    "no withdrawal",
    "cannot withdraw",
    "proof of burn",
    "permanent lock",
)

_FUND_LOCK_KEYS = (
    "fund lock",
    "time lock",
    "timelock",
    "time-locked",
    "locked funds",
    "hash lock",
    "hashlock",
    "puzzle",
)

_BACKDOOR_KEYS = (
    "backdoor",
    "back door",
    "hidden key",
    "secret key only i",
    "only i know",
    "undocumented",
    "hidden admin",
    "trapdoor",
)


def is_backdoor_request(message: str) -> bool:
    lower = message.lower()
    return any(k in lower for k in _BACKDOOR_KEYS)


def backdoor_refusal_message() -> str:
    return (
        "I can't help design a hidden backdoor or secret spend path only you know about. "
        "NexOps specs are meant to be honest and auditable — anything that spends funds "
        "must be visible in the contract design.\n\n"
        "What I *can* help with are explicit, documented controls, for example:\n"
        "  • an owner recovery key that everyone on the team knows about\n"
        "  • a time-locked vault with a clear unlock condition\n"
        "  • a permanent burn / proof-of-burn (no spend path by design)\n\n"
        "Which of those directions fits what you actually want?"
    )


def looks_like_intent_pivot(message: str, current_caps: Set[str]) -> bool:
    lower = message.lower().strip()
    if len(lower) < 8:
        return False
    if any(k in lower for k in _BURN_KEYS) or any(k in lower for k in _FUND_LOCK_KEYS):
        return True
    if any(p in lower for p in _PIVOT_PHRASES):
        # Pivot phrases alone are weak; require a pattern keyword too.
        pattern_hit = any(
            k in lower
            for k in (
                "vault",
                "escrow",
                "treasury",
                "auction",
                "multisig",
                "lock",
                "burn",
                "timelock",
                "dao",
                "fund",
                "vest",
                "decay",
            )
        )
        return pattern_hit
    return False


def suggested_caps_from_pivot(message: str) -> List[str]:
    lower = message.lower()
    if any(k in lower for k in _BURN_KEYS):
        # Permanent lock / burn — model as vault with no release path in review;
        # generation will later flag / narrow to supported vault.
        return ["vault", "timelock"]
    if any(k in lower for k in _FUND_LOCK_KEYS):
        return ["vault", "timelock"]
    if "escrow" in lower:
        return ["escrow", "multisig"]
    if "auction" in lower:
        return ["auction"]
    if "treasury" in lower or "dao" in lower:
        return ["treasury", "vault", "weighted_multisig"]
    if "vault" in lower:
        return ["vault"]
    # Re-run full detector on the pivot text.
    detected = detect_capabilities(RawIntent(intent=message, capabilities=[], constraints={}), message)
    return [c.name for c in detected.capabilities]


def try_pivot_specification(
    spec: ContractSpecification,
    user_message: str,
) -> Tuple[Optional[ContractSpecification], Optional[str]]:
    """
    If the user clearly changed ideas, rebuild capabilities and clear stale params.

    Returns (new_spec, acknowledgment) or (None, None) when no pivot.
    """
    current = {c.name for c in spec.capabilities}
    if not looks_like_intent_pivot(user_message, current):
        return None, None

    new_caps = suggested_caps_from_pivot(user_message)
    if not new_caps:
        return None, None

    new_set = set(new_caps)
    if new_set == current:
        return None, None

    # Soft pivot: different primary pattern / clearly incompatible with sit-and-ask-signers.
    if current and new_set.issubset(current) and len(new_set) < len(current):
        # Narrowing is also a pivot (e.g.DAO → vault only).
        pass
    elif current & new_set and len(new_set - current) == 0 and len(current - new_set) == 0:
        return None, None

    pivoted = ContractSpecification(
        intent=user_message.strip() or spec.intent,
        capabilities=[CapabilityInstance(name=n) for n in sorted(new_set)],
        parameters={},
        status=SpecStatus.NEEDS_INPUT,
        confirmed_fields=[],
        pending_parameters={},
    )
    validation = SpecValidator.validate(pivoted)
    pivoted.status = SpecStatus.IN_REVIEW if validation.is_complete else SpecStatus.NEEDS_INPUT

    labels = ", ".join(n.replace("_", " ") for n in sorted(new_set))
    ack = (
        f"Got it — pivoting away from the previous shape. "
        f"I'll treat this as: {labels}. "
        f"I've cleared the old fields so we don't keep asking about irrelevant details."
    )
    if any(k in user_message.lower() for k in _BURN_KEYS):
        ack += (
            " Permanent / irreversible lock is a strong commitment design — "
            "we can couple this to a vault with no withdrawal path, or mark it "
            "as burn-style if that's the goal."
        )
    return pivoted, ack


# CashScript injection: real code shapes only — not the English word "contract".
_CASHSCRIPT_CODE = re.compile(
    r"(pragma\s+cashscript|require\s*\(|^\s*contract\s+\w+\s*\(|^\s*function\s+\w+\s*\()",
    re.I | re.M,
)


def looks_like_cashscript_injection(message: str) -> bool:
    return bool(_CASHSCRIPT_CODE.search(message))
