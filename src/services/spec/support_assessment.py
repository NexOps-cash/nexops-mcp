"""Composition support assessment — backend source of truth for frontend Mode C."""

from __future__ import annotations

from typing import Dict, FrozenSet, List, Set, Tuple

from src.models import (
    CompositionSupportAssessment,
    ContractSpecification,
    PlanningReport,
    SuggestedAlternative,
)
from src.services.spec.capabilities import CAPABILITY_REGISTRY, get_capability
from src.services.spec.detection import is_cliff_vesting_vault

# Module pairs known to work today (benchmark/scorecard evidence).
_ALLOWED_TWO_MODULE_SETS: Tuple[FrozenSet[str], ...] = (
    frozenset({"EscrowModule", "MultisigModule"}),
)

# Single-pattern capabilities with strong generation evidence.
_SUPPORTED_SINGLE_CAPABILITIES: FrozenSet[str] = frozenset({
    "multisig",
    "escrow",
    "timelock",
    "vault",
    "treasury",
    "auction",
    "token_ft",
    "nft_immutable",
    "nft_mutable",
    "nft_minting",
    "hybrid_token",
})

# Patterns with partial coverage — generation may proceed with warning.
_EXPERIMENTAL_CAPABILITIES: FrozenSet[str] = frozenset({
    "split",
    "linear_decay",
    "withdrawal_policy",
})

# Composed stacks that are not production-supported (generation collapses to one mode).
_BLOCKED_CAPABILITY_SETS: Tuple[FrozenSet[str], ...] = (
    frozenset({"treasury", "vault", "weighted_multisig", "linear_decay"}),
    frozenset({"treasury", "weighted_multisig", "linear_decay"}),
    frozenset({"vault", "weighted_multisig", "linear_decay"}),
    frozenset({"weighted_multisig", "linear_decay"}),
    frozenset({"treasury", "linear_decay"}),
    frozenset({"vault", "linear_decay"}),
)

_MODULE_LABELS: Dict[str, str] = {
    "VaultModule": "A secure Vault",
    "EscrowModule": "A secure Escrow",
    "LinearThresholdModule": "A standalone Linear Threshold policy",
    "VestingScheduleModule": "A linear vesting schedule",
    "WeightedMultisigModule": "A weighted multisig authorization policy",
    "MultisigModule": "A multisig wallet",
    "SplitPaymentModule": "A split payment contract",
    "DutchAuctionModule": "A Dutch auction",
}

_SUPPORTED_SUBSET_CATALOG: List[SuggestedAlternative] = [
    SuggestedAlternative(
        id="escrow_2of3",
        label="2-of-3 escrow",
        description="Buyer, seller, and arbiter with multisig release and optional timeout refund.",
        prompt_example="Create a 2-of-3 escrow with buyer, seller, and arbiter",
        capabilities=["escrow", "multisig"],
    ),
    SuggestedAlternative(
        id="multisig",
        label="Multisig wallet",
        description="Standard BCH multisig with configurable threshold.",
        prompt_example="Create a 2-of-3 multisig wallet for Alice, Bob, and Carol",
        capabilities=["multisig"],
    ),
    SuggestedAlternative(
        id="vault",
        label="Vault",
        description="Staged withdrawal or delayed-release vault covenant.",
        prompt_example="Create a vault with delayed withdrawal after 7 days",
        capabilities=["vault", "treasury"],
    ),
    SuggestedAlternative(
        id="dutch_auction",
        label="Dutch auction",
        description="Time-decaying price auction for BCH or NFT sale.",
        prompt_example="Create a Dutch auction for an NFT with declining price",
        capabilities=["auction"],
    ),
    SuggestedAlternative(
        id="linear_vesting",
        label="Linear vesting / decay",
        description="Time-based unlock or threshold decay as a single pattern.",
        prompt_example="Create a linear decay threshold policy from 2 to 3 over 30 days",
        capabilities=["linear_decay"],
    ),
]


def _unique_modules(modules: List[str]) -> List[str]:
    seen: set[str] = set()
    out: List[str] = []
    for name in modules:
        if name in seen:
            continue
        seen.add(name)
        out.append(name)
    return out


def _module_label(module_name: str) -> str:
    return _MODULE_LABELS.get(module_name, module_name.replace("Module", "").replace("_", " "))


def _build_guidance(
    *,
    unique_modules: List[str],
    suggestions: List[SuggestedAlternative],
    include_future_note: bool = True,
) -> str:
    lines = [
        "This request requires multi-module composition, which isn't supported yet.",
        "",
        "I can currently generate:",
        "",
    ]
    for mod in unique_modules:
        lines.append(f"  • {_module_label(mod)}.")
    if suggestions:
        lines.append("")
        lines.append("Related patterns you can generate now:")
        for alt in suggestions[:4]:
            example = f' — e.g. "{alt.prompt_example}"' if alt.prompt_example else ""
            lines.append(f"  • {alt.label}{example}")
    if include_future_note:
        lines.append("")
        lines.append(
            "When multi-module composition is available, these will be combined automatically."
        )
    return "\n".join(lines)


def _attach_guidance(assessment: CompositionSupportAssessment) -> CompositionSupportAssessment:
    unique = _unique_modules(assessment.selected_modules)
    if assessment.status == "unsupported" and len(unique) >= 2 and not assessment.guidance:
        assessment.guidance = _build_guidance(
            unique_modules=unique,
            suggestions=assessment.suggestions,
        )
    return assessment


def _capability_conflicts(cap_names: Set[str]) -> List[str]:
    conflicts: List[str] = []
    for cap_name in cap_names:
        cap = get_capability(cap_name)
        if not cap:
            continue
        for other in cap.conflicts:
            if other in cap_names:
                pair = tuple(sorted((cap_name, other)))
                msg = f"{pair[0]} conflicts with {pair[1]}"
                if msg not in conflicts:
                    conflicts.append(msg)
    return conflicts


def _vesting_vault_suggestions(spec: ContractSpecification) -> List[SuggestedAlternative]:
    params = spec.parameters or {}
    days = params.get("timeout_days") or params.get("duration_days", 180)
    recipients = params.get("recipients") or ["Founder A", "Founder B"]
    shares = params.get("shares") or [60, 40]
    if isinstance(recipients, list) and isinstance(shares, list) and recipients and shares:
        split_desc = ", ".join(f"{s}% to {r}" for s, r in zip(shares, recipients))
    else:
        split_desc = "60% to Founder A, 40% to Founder B"
    return [
        SuggestedAlternative(
            id="vault_timelock",
            label="Timed vault (lock then release)",
            description="Lock BCH for N days, then allow release.",
            prompt_example=f"Create a BCH vault with funds locked for {days} days then releasable",
            capabilities=["vault", "timelock"],
        ),
        SuggestedAlternative(
            id="split_only",
            label="Split payment (post-unlock)",
            description="Standalone split distribution after unlock.",
            prompt_example=f"Split payment: {split_desc}",
            capabilities=["split"],
        ),
    ]


def _subset_suggestions(cap_names: Set[str], limit: int = 4) -> List[SuggestedAlternative]:
    out: List[SuggestedAlternative] = []
    for alt in _SUPPORTED_SUBSET_CATALOG:
        if alt.capabilities and all(c in cap_names or c in _SUPPORTED_SINGLE_CAPABILITIES for c in alt.capabilities):
            if any(c in cap_names for c in alt.capabilities):
                out.append(alt)
        elif not alt.capabilities:
            out.append(alt)
    if not out:
        out = list(_SUPPORTED_SUBSET_CATALOG[:limit])
    return out[:limit]


def _is_subset(blocked: FrozenSet[str], cap_names: Set[str]) -> bool:
    return blocked.issubset(cap_names)


def assess_composition_support(
    spec: ContractSpecification,
    report: PlanningReport,
) -> CompositionSupportAssessment:
    """
    Determine whether the planned specification is supported for generation.

    Single-pattern prompts (e.g. 2-of-3 escrow) must return status=supported.
  """
    cap_names = {c.name for c in spec.capabilities}
    modules = _unique_modules(list(report.selected_modules or []))
    module_set = frozenset(modules)
    effective_mode = report.effective_mode or ""
    conflicts = _capability_conflicts(cap_names)

    supported_subset = [alt.label for alt in _SUPPORTED_SUBSET_CATALOG]

    if conflicts:
        suggestions = _subset_suggestions(cap_names)
        return _attach_guidance(CompositionSupportAssessment(
            status="unsupported",
            reason="Capability conflict detected in the specification.",
            detail="; ".join(conflicts),
            detected_capabilities=sorted(cap_names),
            selected_modules=modules,
            effective_mode=effective_mode,
            suppressed_modules=modules[1:] if len(modules) > 1 else [],
            supported_subset=supported_subset,
            suggestions=suggestions,
            can_save_spec=True,
            can_proceed=False,
            capability_conflicts=conflicts,
        ))

    for blocked in _BLOCKED_CAPABILITY_SETS:
        if _is_subset(blocked, cap_names):
            suppressed = modules[1:] if len(modules) > 1 else []
            suggestions = _subset_suggestions(cap_names)
            return _attach_guidance(CompositionSupportAssessment(
                status="unsupported",
                reason="This request requires multi-module composition, which isn't supported yet.",
                detail=(
                    f"Detected capabilities: {', '.join(sorted(cap_names))}. "
                    f"Planned modules: {', '.join(modules)}. "
                    f"Only the first module drives generation today."
                ),
                detected_capabilities=sorted(cap_names),
                selected_modules=modules,
                effective_mode=effective_mode,
                suppressed_modules=suppressed,
                supported_subset=supported_subset,
                suggestions=suggestions,
                can_save_spec=True,
                can_proceed=False,
                capability_conflicts=[],
            ))

    if "split" in cap_names and len(cap_names) > 1:
        suggestions = [
            SuggestedAlternative(
                id="split_only",
                label="Split payment only",
                description="Generate a standalone split contract without other patterns.",
                prompt_example="Split payment to two recipients 50/50",
                capabilities=["split"],
            ),
            *_SUPPORTED_SUBSET_CATALOG[:2],
        ]
        if is_cliff_vesting_vault((spec.intent or "").lower()):
            suggestions = _vesting_vault_suggestions(spec)
        return _attach_guidance(CompositionSupportAssessment(
            status="unsupported",
            reason="Split payment cannot be composed with other patterns yet.",
            detail="Split distribution requires N-output conservation work that is not composition-ready.",
            detected_capabilities=sorted(cap_names),
            selected_modules=modules,
            effective_mode=effective_mode,
            suppressed_modules=modules[1:] if len(modules) > 1 else [],
            supported_subset=supported_subset,
            suggestions=suggestions,
            can_save_spec=True,
            can_proceed=False,
        ))

    if len(modules) >= 3:
        return _attach_guidance(CompositionSupportAssessment(
            status="unsupported",
            reason="This request requires multi-module composition, which isn't supported yet.",
            detail=f"Planned modules: {', '.join(modules)}.",
            detected_capabilities=sorted(cap_names),
            selected_modules=modules,
            effective_mode=effective_mode,
            suppressed_modules=modules[1:],
            supported_subset=supported_subset,
            suggestions=_subset_suggestions(cap_names),
            can_save_spec=True,
            can_proceed=False,
        ))

    if len(modules) == 2:
        if module_set not in _ALLOWED_TWO_MODULE_SETS:
            if module_set == frozenset({"VaultModule", "LinearThresholdModule"}) or module_set == frozenset(
                {"VaultModule", "VestingScheduleModule"}
            ):
                return _attach_guidance(CompositionSupportAssessment(
                    status="unsupported",
                    reason="This request requires multi-module composition, which isn't supported yet.",
                    detail=(
                        f"Planned modules: {', '.join(modules)}. "
                        "Treasury/vault and threshold decay must be generated separately for now."
                    ),
                    detected_capabilities=sorted(cap_names),
                    selected_modules=modules,
                    effective_mode=effective_mode,
                    suppressed_modules=[m for m in modules if m != modules[0]],
                    supported_subset=supported_subset,
                    suggestions=_subset_suggestions(cap_names),
                    can_save_spec=True,
                    can_proceed=False,
                ))
            if "WeightedMultisigModule" in modules and "LinearThresholdModule" in modules:
                return _attach_guidance(CompositionSupportAssessment(
                    status="unsupported",
                    reason="Weighted multisig and threshold decay cannot be generated together yet.",
                    detail=(
                        f"Modules {', '.join(modules)} are planned but only "
                        f"{effective_mode or modules[0]} is used at generation time."
                    ),
                    detected_capabilities=sorted(cap_names),
                    selected_modules=modules,
                    effective_mode=effective_mode,
                    suppressed_modules=[m for m in modules if m != modules[0]],
                    supported_subset=supported_subset,
                    suggestions=_subset_suggestions(cap_names),
                    can_save_spec=True,
                    can_proceed=False,
                ))
            return CompositionSupportAssessment(
                status="experimental",
                reason="This two-module composition is experimental and may not reflect all planned behavior.",
                detail=f"Modules: {', '.join(modules)}. Effective mode: {effective_mode or 'unknown'}.",
                detected_capabilities=sorted(cap_names),
                selected_modules=modules,
                effective_mode=effective_mode,
                suppressed_modules=[m for m in modules if m != modules[0]],
                supported_subset=supported_subset,
                suggestions=_subset_suggestions(cap_names),
                can_save_spec=True,
                can_proceed=True,
            )

    if cap_names == {"split"} or (len(cap_names) == 1 and "split" in cap_names):
        return CompositionSupportAssessment(
            status="experimental",
            reason="Split payment generation is experimental (~50% benchmark convergence).",
            detail="Proceed only if you accept lower first-pass quality.",
            detected_capabilities=sorted(cap_names),
            selected_modules=modules,
            effective_mode=effective_mode,
            supported_subset=supported_subset,
            suggestions=[_SUPPORTED_SUBSET_CATALOG[0]],
            can_save_spec=True,
            can_proceed=True,
        )

    if len(cap_names) == 1 and next(iter(cap_names)) in _EXPERIMENTAL_CAPABILITIES:
        cap = next(iter(cap_names))
        return CompositionSupportAssessment(
            status="experimental",
            reason=f"{cap.replace('_', ' ').title()} is supported as a single pattern with reduced robustness.",
            detail="Generation proceeds but may not meet full benchmark quality.",
            detected_capabilities=sorted(cap_names),
            selected_modules=modules,
            effective_mode=effective_mode,
            supported_subset=supported_subset,
            suggestions=_subset_suggestions(cap_names),
            can_save_spec=True,
            can_proceed=True,
        )

    # Escrow + multisig (2 modules) or single supported capability
    return CompositionSupportAssessment(
        status="supported",
        reason="This specification maps to a supported generation pattern.",
        detail=f"Effective mode: {effective_mode or 'generic'}.",
        detected_capabilities=sorted(cap_names),
        selected_modules=modules,
        effective_mode=effective_mode,
        supported_subset=supported_subset,
        suggestions=[],
        can_save_spec=True,
        can_proceed=True,
    )


def personalize_suggestion_prompt(
    alt: SuggestedAlternative,
    spec: ContractSpecification,
) -> str:
    """Build a generation prompt from the user's spec so alternatives stay relevant."""
    params = spec.parameters or {}
    if alt.id == "linear_vesting" or alt.capabilities == ["linear_decay"]:
        initial = params.get("initial_threshold", 50)
        final = params.get("final_threshold", initial)
        days = params.get("duration_days", 30)
        return (
            f"Create a linear decay threshold policy from {initial} to {final} "
            f"over {days} days"
        )
    if alt.id == "vault":
        asset = str(params.get("asset_type", "BCH"))
        days = params.get("timeout_days") or params.get("duration_days", 7)
        return (
            f"Create a {asset} treasury vault with delayed withdrawal after {days} days"
        )
    if alt.id == "vault_timelock":
        asset = str(params.get("asset_type", "BCH"))
        days = params.get("timeout_days") or params.get("duration_days", 180)
        return f"Create a {asset} vault with funds locked for {days} days then releasable"
    if alt.id == "split_only" or alt.capabilities == ["split"]:
        recipients = params.get("recipients") or ["Founder A", "Founder B"]
        shares = params.get("shares") or [60, 40]
        if isinstance(recipients, list) and isinstance(shares, list):
            split_desc = ", ".join(f"{s}% to {r}" for s, r in zip(shares, recipients))
            return f"Split payment: {split_desc}"
    if alt.id == "escrow_2of3":
        return alt.prompt_example
    return alt.prompt_example or alt.label


def assess_from_capabilities(capability_names: List[str], modules: List[str], effective_mode: str) -> CompositionSupportAssessment:
    """Convenience wrapper when only report fields are available."""
    from src.models import CapabilityInstance, ContractSpecification

    spec = ContractSpecification(
        intent="",
        capabilities=[CapabilityInstance(name=n) for n in capability_names],
    )
    report = PlanningReport(
        detected_capabilities=capability_names,
        selected_modules=modules,
        effective_mode=effective_mode,
    )
    return assess_composition_support(spec, report)
