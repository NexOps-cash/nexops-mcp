"""Deterministic semantic layer normalization (Phase 1 post-routing)."""

from __future__ import annotations

from src.models import IntentModel

_NFT_SIGNALS = {
    "nft", "token", "custody", "tokencategory", "nft custody", "cashtoken",
    "immutable nft", "mutable nft", "soulbound",
}

_FT_CAP_MINT_SIGNALS = (
    "loyalty", "fungible", "points token", "reward token", "game currency",
    "treasury may mint", "maximum supply", "max supply", "supply cap",
    "capped fungible", "mint amount", "currentsupply", "maxsupply",
)


def apply_ownership_semantics(intent_model: IntentModel, intent_lower: str) -> None:
    if any(w in intent_lower for w in ("soulbound", "non-transferable", "identity nft", "cannot transfer ownership")):
        intent_model.ownership_mode = "soulbound"
    elif any(
        w in intent_lower
        for w in ("minting authority", "mint authority", "retained by covenant", "authority permanently")
    ):
        intent_model.ownership_mode = "covenant_retained"
    elif any(
        w in intent_lower
        for w in ("multisig", "governance", "treasury", "mediator", "delegated", "quorum")
    ):
        intent_model.ownership_mode = "delegated"
    elif any(w in intent_lower for w in ("marketplace", "buyer pays", "transfer to buyer", "transfer to recipient")):
        intent_model.ownership_mode = "transferable"


def apply_lifecycle_semantics(intent_model: IntentModel, intent_lower: str) -> None:
    if any(w in intent_lower for w in ("soulbound", "update metadata", "update commitment", "renewal", "renew")):
        if "subscription" in intent_lower or "streaming" in intent_lower or "expiry" in intent_lower:
            intent_model.lifecycle_mode = "state_transition"
        elif intent_model.ownership_mode == "soulbound":
            intent_model.lifecycle_mode = "state_transition"
    if any(
        w in intent_lower
        for w in ("escrow", "marketplace", "auction", "redeem", "voucher", "payout", "claim", "release to buyer")
    ):
        if "mint authority" in intent_lower or "minting authority" in intent_lower:
            intent_model.lifecycle_mode = "persistent"
        elif "transfer nft" in intent_lower or "receive nft" in intent_lower or "highest bidder" in intent_lower:
            intent_model.lifecycle_mode = "migratory"
        else:
            intent_model.lifecycle_mode = "terminating"
    if any(w in intent_lower for w in ("subscription", "streaming", "update state", "treasury state")):
        intent_model.lifecycle_mode = "state_transition"
    if any(w in intent_lower for w in ("transfer to", "send to recipient", "buyer receives", "recipient receives")):
        if intent_model.lifecycle_mode not in ("terminating", "state_transition"):
            intent_model.lifecycle_mode = "migratory"
    if any(w in intent_lower for w in ("vault", "covenant retains", "stays in covenant", "self-anchor")):
        if intent_model.lifecycle_mode == "persistent" or intent_model.ownership_mode == "covenant_retained":
            intent_model.lifecycle_mode = "persistent"
    # Marketplace immutable NFT purchase → migratory (NFT to buyer after payment)
    if (
        "marketplace" in intent_lower
        and "immutable" in intent_lower
        and ("buyer pays" in intent_lower or "until buyer pays" in intent_lower)
    ):
        intent_model.lifecycle_mode = "migratory"


def apply_supply_semantics(intent_model: IntentModel, intent_lower: str) -> None:
    if any(w in intent_lower for w in ("redeemable", "voucher", "redeem", "exchanged for bch")):
        intent_model.supply_mode = "redeemable"
    elif any(w in intent_lower for w in ("burnable", "destroy token", "burn itself", "never mint")):
        intent_model.supply_mode = "burnable"
        if "never mint" in intent_lower or "but never mint" in intent_lower:
            intent_model.supply_mode = "burnable"
    elif any(
        w in intent_lower
        for w in (
            "capped", "max supply", "maximum supply", "open edition", "mint cap",
            "capped max", "supply cap", "never exceed", "must never exceed",
        )
    ):
        intent_model.supply_mode = "capped_mint"
    if "burn" in intent_lower and "mint" not in intent_lower and intent_model.supply_mode == "fixed":
        intent_model.supply_mode = "burnable"


def apply_commitment_semantics(intent_model: IntentModel, intent_lower: str) -> None:
    if any(
        w in intent_lower
        for w in ("subscription", "expiry timestamp", "expiry", "renewal", "streaming payment")
    ):
        intent_model.commitment_schema = "expiry"
    if any(
        w in intent_lower
        for w in ("governance", "treasury state", "treasury nft", "multisig approval")
    ):
        intent_model.commitment_schema = "governance"
    if intent_model.ownership_mode == "soulbound" or intent_model.lifecycle_mode == "state_transition":
        intent_model.requires_commitment = True


def _semantic_cashtoken_adjust(intent_model: IntentModel, intent_lower: str) -> None:
    """Re-route CashToken class from semantic supply/ownership signals."""
    if intent_model.ownership_mode == "soulbound" or "soulbound" in intent_lower:
        intent_model.contract_type = "nft_mutable_state_update"
        intent_model.token_class = "nft_mutable"
        intent_model.nft_capability = "mutable"
        intent_model.requires_commitment = True
        if "nft" not in intent_model.features:
            intent_model.features = list(intent_model.features) + ["nft"]
        return

    if intent_model.supply_mode in ("burnable", "redeemable") and any(
        w in intent_lower for w in ("fungible", "token covenant", "voucher token", "burnable")
    ):
        intent_model.contract_type = "ft_transfer"
        intent_model.token_class = "ft"
        if "tokens" not in intent_model.features:
            intent_model.features = list(intent_model.features) + ["tokens"]
        if intent_model.supply_mode == "burnable" and "burn" not in intent_model.features:
            intent_model.features = list(intent_model.features) + ["burn"]
        return

    if "marketplace" in intent_lower:
        if "marketplace" not in intent_model.features:
            intent_model.features = list(intent_model.features) + ["marketplace"]
    if any(w in intent_lower for w in ("marketplace", "nft escrow", "escrow")) and any(
        s in intent_lower for s in _NFT_SIGNALS
    ):
        if "immutable" in intent_lower or intent_model.token_class == "nft_immutable":
            intent_model.contract_type = "nft_transfer_immutable"
            intent_model.token_class = "nft_immutable"
            intent_model.nft_capability = "none"
        if "escrow" in intent_lower and "escrow" not in intent_model.features:
            intent_model.features = list(intent_model.features) + ["escrow"]
        return

    if "auction" in intent_lower and "nft" in intent_lower:
        intent_model.contract_type = "nft_transfer_immutable"
        intent_model.token_class = "nft_immutable"
        intent_model.nft_capability = "none"
        intent_model.requires_commitment = True
        return

    if intent_model.supply_mode == "capped_mint" or "open edition" in intent_lower:
        is_ft_cap = any(s in intent_lower for s in _FT_CAP_MINT_SIGNALS) or (
            "mint" in intent_lower
            and "nft" not in intent_lower
            and any(w in intent_lower for w in ("fungible", "token", "points", "loyalty", "reward"))
        )
        if is_ft_cap and "open edition" not in intent_lower and "nft drop" not in intent_lower:
            intent_model.contract_type = "ft_mint_authority"
            intent_model.token_class = "ft"
            intent_model.nft_capability = "none"
            if "minting" not in intent_model.features:
                intent_model.features = list(intent_model.features) + ["minting"]
            if "tokens" not in intent_model.features:
                intent_model.features = list(intent_model.features) + ["tokens"]
        else:
            intent_model.contract_type = "nft_minting_authority"
            intent_model.token_class = "nft_minting"
            intent_model.nft_capability = "minting"
            if "minting" not in intent_model.features:
                intent_model.features = list(intent_model.features) + ["minting"]


def check_pure_bch_escrow_mismatch(intent_model: IntentModel, intent_lower: str) -> bool:
    """Token class set but prompt is pure BCH escrow without token/NFT context."""
    tc = (intent_model.token_class or "").strip()
    if not tc:
        return False
    has_escrow = "escrow" in intent_lower or intent_model.contract_type in ("escrow", "escrow_2of3_nft")
    if not has_escrow:
        return False
    return not any(s in intent_lower for s in _NFT_SIGNALS)


def apply_semantic_normalization(intent_model: IntentModel, intent_lower: str) -> None:
    apply_ownership_semantics(intent_model, intent_lower)
    apply_lifecycle_semantics(intent_model, intent_lower)
    apply_supply_semantics(intent_model, intent_lower)
    apply_commitment_semantics(intent_model, intent_lower)
    _semantic_cashtoken_adjust(intent_model, intent_lower)
