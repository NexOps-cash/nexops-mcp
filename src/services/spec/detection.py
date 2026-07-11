"""Deterministic capability detection from extracted intent + keywords."""

from __future__ import annotations

from typing import List, Set

from src.models import CapabilityInstance, ContractSpecification, RawIntent
from src.services.spec.capabilities import CAPABILITY_REGISTRY, get_capability


_ESCROW_KEYWORDS = {"refund", "reclaim", "timeout", "after", "expire", "expiry", "deadline", "arbiter", "escrow"}
_SPLIT_KEYS = ("split", "distribute", "distribution", "recipients", "payroll", "treasury", "partners", "revenue")
_VAULT_KEYS = ("vault", "cold storage", "withdrawal limit", "controlled release", "treasury")
_WEIGHTED_KEYS = ("weighted", "weight", "weights", "voting weight", "vote weight")
_GOVERNANCE_KEYS = (
    "dao",
    "governance",
    "catalyst",
    "catlyst",  # common misspelling
    "cardano catalyst",
    "proposal fund",
    "funding dao",
    "community fund",
    "treasury dao",
)
_DECAY_KEYS = ("linear decay", "threshold increase", "linear threshold")
_AUCTION_KEYS = ("auction", "bid", "dutch", "price decay", "declining price", "marketplace")
_VESTING_VAULT_KEYS = ("vesting", "founder vesting", "cliff vest", "vesting vault")
_FOUNDER_VESTING_CHOICE_PHRASES = (
    "vesting first",
    "lets do vesting",
    "let's do vesting",
    "let us do vesting",
    "do vesting",
    "founder vesting",
    "founders vesting",
    "founders' vesting",
    "lets do founder vesting",
    "let's do founder vesting",
)
_FOUNDER_VESTING_CAPS = frozenset({"vault", "timelock", "split"})
_TREASURY_DECAY_FIELDS = frozenset({"initial_threshold", "final_threshold", "duration_days"})


def explicit_founder_vesting_choice(text: str) -> bool:
    t = text.strip().lower()
    if is_simple_token_timelock_vesting(t):
        return False
    return any(p in t for p in _FOUNDER_VESTING_CHOICE_PHRASES)


def is_simple_token_timelock_vesting(text: str) -> bool:
    """Single-beneficiary CashTokens lock — not founder cliff + split."""
    lower = text.lower()
    token_signal = any(
        k in lower
        for k in ("cashtoken", "cashtokens", "fungible token", "fungible tokens", "cash token")
    )
    lock_signal = any(
        k in lower
        for k in ("lock", "locked", "365 days", "cannot move", "before expiry", "timelock", "expiry")
    )
    founder_signal = any(
        k in lower
        for k in ("founder", "cliff", "50/50", "payroll", "split", "linear decay", "governance")
    )
    return token_signal and lock_signal and not founder_signal


def simple_token_vesting_capability_instances() -> List[CapabilityInstance]:
    return [CapabilityInstance(name="vault"), CapabilityInstance(name="timelock")]


def spec_intent_text(spec: ContractSpecification) -> str:
    return (spec.intent or "").strip().lower()


def is_founder_vesting_spec(spec: ContractSpecification) -> bool:
    if spec.parameters.get("lifecycle_mode") == "token_vesting":
        return False
    text = spec_intent_text(spec)
    if is_simple_token_timelock_vesting(text):
        return False
    if spec.parameters.get("lifecycle_mode") == "vesting":
        return True
    if explicit_founder_vesting_choice(text):
        return True
    if is_cliff_vesting_vault(text):
        return True
    cap_names = {c.name for c in spec.capabilities}
    if _FOUNDER_VESTING_CAPS.issubset(cap_names):
        if "vest" in text or "founder" in text or "cliff" in text:
            return True
    return False


def founder_vesting_capability_instances() -> List[CapabilityInstance]:
    return [CapabilityInstance(name=n) for n in sorted(_FOUNDER_VESTING_CAPS)]


def normalize_founder_vesting_spec(spec: ContractSpecification) -> ContractSpecification:
    """Keep founder vesting on vault/timelock/split — never treasury linear_decay."""
    if not is_founder_vesting_spec(spec):
        return spec
    updated = spec.model_copy(deep=True)
    updated.capabilities = [
        c for c in updated.capabilities
        if c.name not in ("linear_decay", "treasury", "weighted_multisig")
    ]
    names = {c.name for c in updated.capabilities}
    for cap_name in sorted(_FOUNDER_VESTING_CAPS):
        if cap_name not in names:
            updated.capabilities.append(CapabilityInstance(name=cap_name))
    updated.parameters["lifecycle_mode"] = "vesting"
    for key in _TREASURY_DECAY_FIELDS:
        if key in updated.parameters and key not in updated.confirmed_fields:
            updated.parameters.pop(key, None)
    return updated


def _is_treasury_linear_decay_signal(intent_lower: str) -> bool:
    if is_cliff_vesting_vault(intent_lower) or explicit_founder_vesting_choice(intent_lower):
        return False
    if "founder" in intent_lower and ("vest" in intent_lower or "cliff" in intent_lower):
        return False
    if any(k in intent_lower for k in _DECAY_KEYS):
        return True
    if "decay" not in intent_lower:
        return False
    if any(k in intent_lower for k in ("treasury", "governance", "dao", "approval threshold", "voting threshold")):
        return True
    if "%" in intent_lower and "vest" not in intent_lower and "cliff" not in intent_lower:
        return "threshold" in intent_lower or "approval" in intent_lower
    return False


def is_cliff_vesting_vault(intent_lower: str) -> bool:
    """
    Founder/cliff vesting: lock funds for N days, then release/split — not treasury voting decay.
    """
    if not intent_lower:
        return False
    has_vesting = any(k in intent_lower for k in _VESTING_VAULT_KEYS) or (
        "vest" in intent_lower and ("vault" in intent_lower or "founder" in intent_lower)
    ) or explicit_founder_vesting_choice(intent_lower)
    has_lock_or_release = any(
        k in intent_lower
        for k in (
            "locked",
            "lock",
            "cliff",
            "days",
            "release",
            "distribute",
            "distributed",
            "split",
            "%",
            "founder",
            "year",
        )
    )
    return has_vesting and has_lock_or_release


def _is_governance_dao(intent_lower: str) -> bool:
    if any(k in intent_lower for k in _GOVERNANCE_KEYS):
        return True
    # "voting" alone is ambiguous; only couple it with org/gov language.
    if "voting" in intent_lower and any(
        k in intent_lower for k in ("dao", "governance", "council", "committee", "catalyst")
    ):
        return True
    return False


def detect_capabilities(
    raw: RawIntent,
    original_intent: str = "",
    *,
    allow_generic_multisig_default: bool = False,
) -> ContractSpecification:
    intent_lower = (original_intent or raw.intent or "").lower()
    names: Set[str] = {c.lower().strip() for c in raw.capabilities if c}

    if is_cliff_vesting_vault(intent_lower) or explicit_founder_vesting_choice(intent_lower):
        caps = founder_vesting_capability_instances()
        params = dict(raw.constraints)
        params.setdefault("lifecycle_mode", "vesting")
        return ContractSpecification(
            intent=raw.intent or original_intent,
            capabilities=caps,
            parameters=params,
        )

    if any(k in intent_lower for k in _VAULT_KEYS) or raw.intent.lower() in ("treasury", "vault"):
        names.add("treasury")
        names.add("vault")
    if _is_governance_dao(intent_lower):
        # Catalyst-style funding DAOs need a treasury vault plus weighted voting —
        # not a plain equal-key multisig shell.
        names.update({"treasury", "vault", "weighted_multisig"})
    if any(k in intent_lower for k in _WEIGHTED_KEYS) or "weighted_multisig" in names:
        names.add("weighted_multisig")
    if _is_treasury_linear_decay_signal(intent_lower) or "linear_decay" in names:
        names.add("linear_decay")
    if any(k in intent_lower for k in _AUCTION_KEYS) or "auction" in names:
        names.add("auction")
    if "timelock" in names or any(w in intent_lower for w in _ESCROW_KEYWORDS):
        if "multisig" in names or "escrow" in intent_lower:
            names.add("escrow")
            names.add("multisig")
    if any(k in intent_lower for k in _SPLIT_KEYS) and ("multisig" in names or "split" in names):
        names.add("split")
    if "nft" in intent_lower or "token" in intent_lower:
        if "mint" in intent_lower:
            names.add("nft_minting")
        elif "mutable" in intent_lower:
            names.add("nft_mutable")
        elif "immutable" in intent_lower or "collectible" in intent_lower:
            names.add("nft_immutable")
        elif "fungible" in intent_lower or "ft" in intent_lower:
            names.add("token_ft")

    # Filter to registry-known capabilities
    valid = [n for n in names if n in CAPABILITY_REGISTRY]
    if not valid:
        if "escrow" in intent_lower or "arbiter" in intent_lower:
            valid = ["escrow", "multisig"]
        elif "split" in intent_lower or "distribute" in intent_lower:
            valid = ["split", "multisig"]
        elif is_cliff_vesting_vault(intent_lower) or explicit_founder_vesting_choice(intent_lower):
            valid = ["vault", "timelock", "split"]
        elif _is_governance_dao(intent_lower):
            valid = ["treasury", "vault", "weighted_multisig"]
        elif "vault" in intent_lower or "treasury" in intent_lower:
            valid = ["treasury", "vault"]
        elif "auction" in intent_lower or "bid" in intent_lower or "dutch" in intent_lower:
            valid = ["auction"]
        elif "nft" in intent_lower or "token" in intent_lower:
            valid = ["token_ft"]
        elif allow_generic_multisig_default:
            valid = ["multisig"]

    caps = [CapabilityInstance(name=n, parameters={}) for n in sorted(set(valid))]
    return ContractSpecification(
        intent=raw.intent or original_intent,
        capabilities=caps,
        parameters=dict(raw.constraints),
    )
