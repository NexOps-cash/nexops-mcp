"""Capability registry — single source of truth for specification fields."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Set


@dataclass(frozen=True)
class FieldSpec:
    name: str
    type: str = "string"
    question: str = ""
    validator: Optional[Callable[[object], bool]] = None


@dataclass(frozen=True)
class Capability:
    name: str
    required_fields: List[FieldSpec] = field(default_factory=list)
    optional_fields: List[FieldSpec] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    documentation: List[str] = field(default_factory=list)
    examples: List[str] = field(default_factory=list)
    best_practices: List[str] = field(default_factory=list)
    implies: List[str] = field(default_factory=list)
    conflicts: List[str] = field(default_factory=list)


def _f(name: str, question: str, type_: str = "string") -> FieldSpec:
    return FieldSpec(name=name, type=type_, question=question)


CAPABILITY_REGISTRY: Dict[str, Capability] = {
    "treasury": Capability(
        name="treasury",
        required_fields=[_f("asset_type", "Which asset does the treasury hold? (BCH, FT, NFT)")],
        recommendations=["Use vault covenant for long-term storage", "Separate hot and cold paths"],
        documentation=["A treasury holds funds under policy-controlled spend paths."],
        examples=["Founder treasury", "DAO treasury", "Recovery wallet"],
        best_practices=["Always bind withdrawals to authorization capability", "Preserve value on re-anchor"],
        implies=["withdrawal_policy"],
    ),
    "weighted_multisig": Capability(
        name="weighted_multisig",
        required_fields=[
            _f("holders", "How many key holders?", "integer"),
            _f("weights", "What voting weight does each holder have?", "list"),
        ],
        recommendations=["2-of-3 for startup teams", "3-of-5 for DAO governance"],
        documentation=["Controls withdrawals using weighted signatures instead of equal multisig."],
        examples=["Founder + advisor + ops", "DAO council"],
        best_practices=["Weights should sum to 100%", "Document emergency recovery path"],
    ),
    "linear_decay": Capability(
        name="linear_decay",
        required_fields=[
            _f("initial_threshold", "What should the initial voting threshold be?", "number"),
            _f("final_threshold", "What should the final threshold be?", "number"),
            _f("duration_days", "Over how many days should the threshold change?", "integer"),
        ],
        documentation=["Linearly increases authorization threshold over time."],
        examples=["30-day ramp from 2-of-3 to 3-of-3"],
        best_practices=["Set final threshold >= initial threshold for treasury safety"],
    ),
    "withdrawal_policy": Capability(
        name="withdrawal_policy",
        required_fields=[_f("asset_type", "Which asset type is withdrawn?", "string")],
        optional_fields=[_f("max_withdrawal", "Maximum single withdrawal amount?", "number")],
        documentation=["Defines how funds leave the treasury covenant."],
        examples=["BCH payout", "FT transfer"],
    ),
    "multisig": Capability(
        name="multisig",
        required_fields=[
            _f("signers", "Who are the signers?", "list"),
            _f("threshold", "What is the signature threshold?", "integer"),
        ],
        recommendations=["2-of-3 for small teams"],
        documentation=["Multiple parties must co-sign spends."],
        examples=["2-of-3 escrow", "3-of-5 DAO"],
    ),
    "timelock": Capability(
        name="timelock",
        required_fields=[_f("timeout_days", "After how many days does the timelock expire?", "integer")],
        documentation=["Time-gated release or refund path."],
        examples=["7-day refund window", "30-day vesting cliff"],
    ),
    "escrow": Capability(
        name="escrow",
        required_fields=[
            _f("signers", "Who are the escrow parties?", "list"),
            _f("threshold", "What is the payout threshold?", "integer"),
        ],
        optional_fields=[_f("timeout_days", "Refund timeout in days?", "integer")],
        implies=["multisig"],
        documentation=["Conditional release with optional timeout refund."],
        examples=["Buyer/seller/arbiter escrow"],
    ),
    "split": Capability(
        name="split",
        required_fields=[
            _f("recipients", "Who receives the split?", "list"),
            _f("shares", "What share does each recipient get?", "list"),
        ],
        documentation=["Distributes value across multiple outputs with conservation."],
        examples=["Payroll split", "Revenue share"],
        conflicts=["escrow"],
    ),
    "vault": Capability(
        name="vault",
        required_fields=[_f("asset_type", "What asset is stored in the vault?", "string")],
        documentation=["Self-continuing covenant with controlled withdrawal."],
        examples=["Cold storage vault", "Treasury vault"],
    ),
    "auction": Capability(
        name="auction",
        required_fields=[
            _f("start_price", "What is the starting (high) price?", "number"),
            _f("min_price", "What is the minimum (floor) price?", "number"),
            _f("duration_days", "How many days does the auction run?", "integer"),
            _f("asset_type", "What is being auctioned? (BCH, NFT, FT)", "string"),
        ],
        recommendations=["Dutch auction: price decays linearly until a bid is accepted"],
        documentation=["Time-decaying price auction; first acceptable bid wins."],
        examples=["NFT dutch auction", "BCH declining-price sale"],
        best_practices=["Bind bid authorization to multisig or single buyer pubkey"],
    ),
    "token_ft": Capability(
        name="token_ft",
        required_fields=[],
        optional_fields=[_f("token_category", "What is the fungible token category?", "string")],
        documentation=["CashTokens fungible transfer/mint patterns."],
        examples=["Reward points", "Stablecoin sidecar"],
    ),
    "nft_immutable": Capability(
        name="nft_immutable",
        required_fields=[],
        optional_fields=[_f("token_category", "What is the NFT category?", "string")],
        documentation=["Immutable NFT transfer with commitment preservation."],
        examples=["Collectible", "Membership badge"],
    ),
    "nft_mutable": Capability(
        name="nft_mutable",
        required_fields=[],
        optional_fields=[_f("token_category", "What is the NFT category?", "string")],
        documentation=["Mutable NFT with state updates in commitment."],
        examples=["Game item", "Governance badge"],
    ),
    "nft_minting": Capability(
        name="nft_minting",
        required_fields=[_f("max_supply", "What is the maximum supply?", "integer")],
        documentation=["NFT minting authority covenant."],
        examples=["Open edition drop", "Collection mint"],
    ),
    "hybrid_token": Capability(
        name="hybrid_token",
        required_fields=[
            _f("token_category", "Primary token category?", "string"),
            _f("sidecar_category", "Sidecar token category?", "string"),
        ],
        documentation=["Multi-property covenant (stablecoin / sidecar style)."],
        examples=["Stablecoin minter sidecar"],
    ),
}


def get_capability(name: str) -> Optional[Capability]:
    return CAPABILITY_REGISTRY.get(name.lower().strip())


def all_required_field_names(capability_names: List[str]) -> Dict[str, str]:
    """Map field name -> owning capability for generation-required fields."""
    out: Dict[str, str] = {}
    for cap_name in capability_names:
        cap = get_capability(cap_name)
        if not cap:
            continue
        for fs in cap.required_fields:
            out[fs.name] = cap_name
    return out


def all_known_field_names(capability_names: List[str]) -> Set[str]:
    """Required + optional field names for active capabilities."""
    names: Set[str] = set()
    for cap_name in capability_names:
        cap = get_capability(cap_name)
        if not cap:
            continue
        for fs in cap.required_fields:
            names.add(fs.name)
        for fs in cap.optional_fields:
            names.add(fs.name)
    return names
