"""Semantic profile resolution: constraint precedence and Phase 2 / lint hints."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional

from src.models import IntentModel


@dataclass
class SemanticProfile:
    ownership_mode: str = "transferable"
    lifecycle_mode: str = "persistent"
    supply_mode: str = "fixed"
    commitment_schema: str = "opaque"
    extra_rails: List[str] = field(default_factory=list)
    lint_rule_overrides: List[str] = field(default_factory=list)
    benchmark_features: List[str] = field(default_factory=list)


def resolve_semantic_constraints(intent_model: IntentModel) -> None:
    """Small precedence table for known ownership/lifecycle conflicts."""
    om = intent_model.ownership_mode
    lm = intent_model.lifecycle_mode

    if om == "soulbound" and lm == "migratory":
        intent_model.lifecycle_mode = "state_transition"

    if om == "soulbound" and lm == "terminating":
        intent_model.lifecycle_mode = "state_transition"

    if om == "covenant_retained" and lm in ("migratory", "terminating"):
        intent_model.lifecycle_mode = "persistent"

    if intent_model.supply_mode == "capped_mint" and om == "transferable":
        intent_model.ownership_mode = "covenant_retained"

    if intent_model.supply_mode in ("burnable", "redeemable") and lm == "persistent":
        intent_model.lifecycle_mode = "terminating"


def resolve_semantic_profile(intent_model: Optional[IntentModel]) -> SemanticProfile:
    if not intent_model:
        return SemanticProfile()

    resolve_semantic_constraints(intent_model)

    profile = SemanticProfile(
        ownership_mode=intent_model.ownership_mode,
        lifecycle_mode=intent_model.lifecycle_mode,
        supply_mode=intent_model.supply_mode,
        commitment_schema=intent_model.commitment_schema,
    )

    if intent_model.ownership_mode == "soulbound":
        profile.benchmark_features.extend(
            ["soulbound_no_external_transfer", "covenant_self_reference"]
        )
    if intent_model.lifecycle_mode == "terminating":
        profile.benchmark_features.append("terminating_payout_path")
    if intent_model.lifecycle_mode == "migratory":
        profile.benchmark_features.append("migratory_locking_bytecode")
    if intent_model.lifecycle_mode == "state_transition":
        profile.benchmark_features.append("state_transition_commitment")
    if intent_model.supply_mode == "redeemable":
        profile.benchmark_features.append("redeem_burn_termination")
    if intent_model.commitment_schema == "expiry":
        profile.benchmark_features.append("expiry_time_check")
    if intent_model.commitment_schema == "governance":
        profile.benchmark_features.append("governance_commitment_mutate")

    return profile


def semantic_rail_blocks(intent_model: Optional[IntentModel]) -> str:
    """Injected into build_pattern_rails from semantic fields."""
    if not intent_model:
        return ""
    blocks: List[str] = []
    om = intent_model.ownership_mode
    lm = intent_model.lifecycle_mode
    sm = intent_model.supply_mode
    cs = intent_model.commitment_schema

    if om == "soulbound":
        blocks.append(
            "[RAIL: SOULBOUND]\n"
            "- NFT MUST stay in covenant: require(tx.outputs[0].lockingBytecode == this.activeBytecode);\n"
            "- FORBID sending NFT to external recipient lockingBytecode;\n"
            "- Metadata updates: require(tx.outputs[0].nftCommitment == newCommitment);\n"
        )
    if lm == "terminating":
        blocks.append(
            "[RAIL: TERMINATING LIFECYCLE]\n"
            "- Payout/claim functions: DO NOT use this.activeBytecode on payout output;\n"
            "- Require BCH value checks to seller/recipient;\n"
            "- LockingBytecodeP2PKH: use hash160(pubkey) OR bytes20 param (buyerPkh/sellerPkh);\n"
        )
    if lm == "migratory":
        blocks.append(
            "[RAIL: MIGRATORY LIFECYCLE]\n"
            "- Transfer path: require(tx.outputs[0].lockingBytecode == recipientLockingBytecode);\n"
            "- DO NOT self-anchor on sole migratory output;\n"
        )
    if lm == "state_transition":
        blocks.append(
            "[RAIL: STATE TRANSITION]\n"
            "- Continuation: require(tx.outputs[0].lockingBytecode == this.activeBytecode);\n"
            "- Commitment mutation or equality as required by schema;\n"
        )
    if sm == "burnable":
        blocks.append(
            "[RAIL: BURNABLE SUPPLY]\n"
            "- Burn path: token output absent or tokenCategory == 0x;\n"
            "- FORBID mint functions that increase total supply;\n"
        )
    if sm == "redeemable":
        blocks.append(
            "[RAIL: REDEEMABLE]\n"
            "- Redeem: burn token + BCH payout; terminating lifecycle;\n"
            "- require(tx.inputs[...].tokenCategory == expectedCategory);\n"
            "- Burn: require(tx.outputs[0].tokenCategory == 0x); prefer tokenAmount == 0;\n"
        )
    if intent_model.features and "marketplace" in intent_model.features:
        blocks.append(
            "[RAIL: MARKETPLACE 2-PARTY]\n"
            "- Simple purchase: buyer pays seller exact BCH; NFT migrates to buyer locking bytecode;\n"
            "- FORBID arbiter, dispute, or 2-of-3 escrow branches unless intent explicitly requests them;\n"
            "- Use bytes20 buyerPkh and sellerPkh constructor params;\n"
            "- Prefer require(tx.outputs[N].lockingBytecode == new LockingBytecodeP2PKH(buyerPkh));\n"
        )
    if sm == "capped_mint":
        blocks.append(
            "[RAIL: CAPPED MINT]\n"
            "- require(totalMinted + mintAmount <= maxSupply);\n"
            "- Authority output: lockingBytecode == this.activeBytecode;\n"
        )
    if cs == "expiry":
        blocks.append(
            "[RAIL: EXPIRY COMMITMENT]\n"
            "- Compare tx.time or prior nftCommitment for subscription expiry;\n"
        )
    if cs == "governance":
        blocks.append(
            "[RAIL: GOVERNANCE COMMITMENT]\n"
            "- require(checkMultiSig(...) or checkSig) before commitment update;\n"
            "- require(tx.outputs[0].nftCommitment == newTreasuryState);\n"
        )
    return "\n".join(blocks)
