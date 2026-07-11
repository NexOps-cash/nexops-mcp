"""Human-facing spec conversation copy — discovery, pivots, summaries."""

from __future__ import annotations

from typing import Optional

from src.models import ContractSpecification, SpecStatus, ValidationResult
from src.services.spec.detection import is_founder_vesting_spec, is_simple_token_timelock_vesting
from src.services.spec.validator import SpecValidator

PARAMETER = "PARAMETER"


def opening_message() -> str:
    return (
        "Hello! I'm NexOps — your Bitcoin Cash contract architect. "
        "I help you design CashScript smart contracts step by step, then generate production-ready code.\n\n"
        "What would you like your smart contract to do?"
    )


def ambiguous_pattern_message() -> str:
    return (
        "Great ideas — both are absolutely possible on Bitcoin Cash. Here's the difference:\n\n"
        "**Founder vesting** — locks tokens or funds for founders and unlocks gradually over time "
        "(for example 25% per year over 4 years). Stops founders from dumping everything on day one.\n\n"
        "**Treasury governance** — a shared fund controlled by voting. Members vote on how to spend "
        "the treasury (funding projects, paying contributors, etc.).\n\n"
        "Which interests you more? Or we can combine ideas — say a treasury with different vesting "
        "schedules per role."
    )


def founder_vesting_ack_message(spec: ContractSpecification) -> str:
    params = spec.parameters
    vest_years = params.get("vesting_years")
    cliff_days = params.get("timeout_days")
    cliff_years = (cliff_days // 365) if isinstance(cliff_days, int) and cliff_days >= 365 else None

    if vest_years and cliff_years:
        remaining = max(vest_years - cliff_years, 1)
        return (
            f"Perfect! A **{vest_years}-year** vesting schedule with a **{cliff_years}-year** cliff "
            f"is a classic setup. Nothing unlocks during the cliff; after year {cliff_years}, "
            f"the remainder releases over the next **{remaining}** year(s).\n\n"
            "Should vesting be **linear** (a little unlocks each day after the cliff), "
            "or in **chunks** (equal tranches each year)?"
        )

    return (
        "Got it — **founder vesting** with a cliff lock, then gradual release to founders. "
        "Tell me the cliff length, total vesting period, founder split, and asset type (BCH or token)."
    )


def token_vesting_pivot_message(spec: ContractSpecification) -> str:
    lock_days = spec.parameters.get("timeout_days") or 365
    amount = spec.parameters.get("token_amount") or spec.parameters.get("max_supply")
    amount_line = f"**{int(amount):,}** fungible tokens" if amount else "fungible tokens"

    return (
        "Excellent — this is a **simpler time-locked vesting** contract than gradual founder vesting. "
        f"I'll lock {amount_line} for **{lock_days} days** with no movement until expiry; "
        "then the beneficiary claims everything (plus BCH dust preserved).\n\n"
        "A few details to nail down:\n"
        "• **Beneficiary** — specific pubkey/address, or **parameterize** at deploy time?\n"
        "• **Start time** — clock starts at **contract deployment**, or a fixed timestamp?\n"
        "• **Token category** — fixed category ID, or a deploy-time **parameter**?\n\n"
        'Say something like *"use parameters and start at deploy"* if you want a reusable template.'
    )


def is_parameterization_request(message: str) -> bool:
    lower = message.lower()
    return any(
        p in lower
        for p in (
            "use parameter",
            "use parameters",
            "parameterize",
            "as parameter",
            "as parameters",
            "when contract deployed",
            "at deploy",
            "start at deploy",
            "from deployment",
            "when deployed",
        )
    )


def apply_parameterization_preferences(
    spec: ContractSpecification,
    message: str,
) -> ContractSpecification:
    """Apply deploy-time parameter defaults from natural language."""
    if spec.parameters.get("lifecycle_mode") != "token_vesting":
        return spec

    updated = spec.model_copy(deep=True)
    lower = message.lower()
    params = dict(updated.parameters)

    if any(p in lower for p in ("use parameter", "parameter", "parameterize", "as parameter")):
        params["beneficiary_pubkey"] = PARAMETER
        params["token_category"] = PARAMETER
        if not params.get("recipients"):
            params["recipients"] = [PARAMETER]

    if any(p in lower for p in ("deploy", "deployment", "when contract deployed", "when deployed")):
        params["lock_start"] = "deployment"

    updated.parameters = params
    updated.parameters.pop("awaiting_token_vesting_details", None)

    for key, val in params.items():
        if val not in (None, "", []) and key not in updated.confirmed_fields:
            updated.confirmed_fields = list(updated.confirmed_fields) + [key]

    validation = SpecValidator.validate(updated)
    updated.status = SpecStatus.IN_REVIEW if validation.is_complete else SpecStatus.NEEDS_INPUT
    return updated


def token_vesting_ready_summary(spec: ContractSpecification) -> str:
    lock_days = spec.parameters.get("timeout_days") or 365
    amount = spec.parameters.get("token_amount") or spec.parameters.get("max_supply")
    beneficiary = spec.parameters.get("beneficiary_pubkey") or spec.parameters.get("recipients")
    token_cat = spec.parameters.get("token_category")
    lock_start = spec.parameters.get("lock_start", "deployment")

    ben_line = (
        "beneficiary pubkey as a **deploy-time parameter**"
        if beneficiary == PARAMETER or beneficiary == [PARAMETER]
        else f"beneficiary: {beneficiary}"
    )
    cat_line = (
        "token category as a **deploy-time parameter**"
        if token_cat == PARAMETER
        else f"token category: {token_cat}"
    )
    start_line = (
        "lock starts at **contract deployment**"
        if lock_start == "deployment"
        else f"lock starts: {lock_start}"
    )
    amt = f"{int(amount):,} " if amount else ""

    return (
        "Perfect! I have everything I need to design your token vesting contract:\n\n"
        f"• **{lock_days}-day lock** starting from {start_line}\n"
        f"• **{amt}fungible tokens** locked with exact amount + category preserved\n"
        f"• **{ben_line}**\n"
        f"• **{cat_line}**\n"
        "• After expiry, beneficiary claims all tokens + any BCH dust\n\n"
        "This gives you a production-ready, reusable contract. "
        "We'll confirm the spec summary next, then generate CashScript."
    )


def maybe_completion_message(
    spec: ContractSpecification,
    validation: Optional[ValidationResult] = None,
) -> Optional[str]:
    validation = validation or SpecValidator.validate(spec)
    if spec.parameters.get("lifecycle_mode") != "token_vesting":
        return None
    if spec.parameters.get("awaiting_token_vesting_details"):
        return None
    if not validation.is_complete:
        return None
    if spec.parameters.get("lock_start") or spec.parameters.get("beneficiary_pubkey"):
        return token_vesting_ready_summary(spec)
    return None


def mark_token_vesting_awaiting_details(spec: ContractSpecification) -> ContractSpecification:
    updated = spec.model_copy(deep=True)
    updated.parameters["awaiting_token_vesting_details"] = True
    updated.status = SpecStatus.NEEDS_INPUT
    return updated
