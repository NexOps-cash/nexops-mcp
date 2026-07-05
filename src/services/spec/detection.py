"""Deterministic capability detection from extracted intent + keywords."""

from __future__ import annotations

from typing import List, Set

from src.models import CapabilityInstance, ContractSpecification, RawIntent
from src.services.spec.capabilities import CAPABILITY_REGISTRY, get_capability


_ESCROW_KEYWORDS = {"refund", "reclaim", "timeout", "after", "expire", "expiry", "deadline", "arbiter", "escrow"}
_SPLIT_KEYS = ("split", "distribute", "distribution", "recipients", "payroll", "treasury", "partners", "revenue")
_VAULT_KEYS = ("vault", "cold storage", "withdrawal limit", "controlled release", "treasury")
_WEIGHTED_KEYS = ("weighted", "weight", "weights", "voting weight")
_DECAY_KEYS = ("linear decay", "decay", "threshold increase", "linear threshold")


def detect_capabilities(raw: RawIntent, original_intent: str = "") -> ContractSpecification:
    intent_lower = (original_intent or raw.intent or "").lower()
    names: Set[str] = {c.lower().strip() for c in raw.capabilities if c}

    if any(k in intent_lower for k in _VAULT_KEYS) or raw.intent.lower() in ("treasury", "vault"):
        names.add("treasury")
        names.add("vault")
    if any(k in intent_lower for k in _WEIGHTED_KEYS) or "weighted_multisig" in names:
        names.add("weighted_multisig")
    if any(k in intent_lower for k in _DECAY_KEYS) or "linear_decay" in names:
        names.add("linear_decay")
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
        elif "vault" in intent_lower or "treasury" in intent_lower:
            valid = ["treasury", "vault"]
        elif "nft" in intent_lower or "token" in intent_lower:
            valid = ["token_ft"]
        else:
            valid = ["multisig"]

    caps = [CapabilityInstance(name=n, parameters={}) for n in sorted(set(valid))]
    return ContractSpecification(
        intent=raw.intent or original_intent,
        capabilities=caps,
        parameters=dict(raw.constraints),
    )
