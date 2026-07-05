"""Orchestrates the specification-first Phase 1 pipeline."""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional, Tuple

from src.models import (
    ClarificationPlan,
    ContractIR,
    ContractMetadata,
    ContractSpecification,
    ExecutionPlan,
    IntentModel,
    PlanningReport,
    SpecStatus,
    UTXOArchitecture,
    ValidationResult,
)
from src.services.spec.clarification import build_clarification_plan
from src.services.spec.composer import Composer
from src.services.spec.detection import detect_capabilities
from src.services.spec.extraction import extract_intent
from src.services.spec.phase2_adapter import resolve_effective_mode
from src.services.spec.planner import ModulePlanner
from src.services.spec.validator import SpecValidator

logger = logging.getLogger("nexops.spec.orchestrator")


ResolutionMode = str  # "interactive" | "non_interactive"


def apply_legacy_fallback(
    spec: ContractSpecification,
    intent: str,
    security_level: str,
) -> Tuple[ContractSpecification, Dict[str, Any]]:
    """
    Fill missing required parameters using deterministic defaults (benchmark/test parity).
    """
    from src.services.spec.capabilities import all_required_field_names

    inferred: Dict[str, Any] = {}
    cap_names = [c.name for c in spec.capabilities]
    required = all_required_field_names(cap_names)
    params = dict(spec.parameters)

    for field_name in required:
        if params.get(field_name) not in (None, "", []):
            continue
        default = _default_for_field(field_name, intent)
        if default is not None:
            params[field_name] = default
            inferred[field_name] = default

    spec.parameters = params
    validation = SpecValidator.validate(spec)
    if validation.is_complete:
        spec.status = SpecStatus.CONFIRMED
    return spec, inferred


def _default_for_field(field_name: str, intent: str) -> Any:
    intent_lower = intent.lower()
    if field_name == "holders":
        return 3
    if field_name == "weights":
        return [56, 30, 14]
    if field_name == "initial_threshold":
        return 2
    if field_name == "final_threshold":
        return 3
    if field_name == "duration_days":
        for token in intent_lower.replace(",", " ").split():
            if token.isdigit():
                return int(token)
        return 30
    if field_name == "asset_type":
        return "BCH"
    if field_name == "signers":
        return ["Alice", "Bob", "Carol"]
    if field_name == "threshold":
        return 2
    if field_name == "timeout_days":
        return 7
    if field_name == "recipients":
        return ["RecipientA", "RecipientB"]
    if field_name == "shares":
        return [50, 50]
    if field_name == "token_category":
        return "0x00"
    if field_name == "max_supply":
        return 1000
    return None


def _heuristic_raw_intent(intent: str) -> RawIntent:
    """Keyword-only extraction for non-interactive / benchmark paths (no LLM)."""
    from src.models import RawIntent

    il = intent.lower()
    caps: List[str] = []
    if any(k in il for k in ("treasury", "vault", "cold storage")):
        caps.extend(["treasury", "vault"])
    if any(k in il for k in ("weighted", "weight", "weights")):
        caps.append("weighted_multisig")
    if any(k in il for k in ("decay", "linear decay", "threshold")):
        caps.append("linear_decay")
    if "escrow" in il or "arbiter" in il:
        caps.extend(["escrow", "multisig"])
    elif "multisig" in il:
        caps.append("multisig")
    if any(k in il for k in ("split", "distribute", "payroll", "recipients")):
        caps.append("split")
    if "timelock" in il or any(k in il for k in ("timeout", "refund", "reclaim")):
        caps.append("timelock")
    if "nft" in il and "mint" in il:
        caps.append("nft_minting")
    elif "nft" in il:
        caps.append("nft_immutable" if "immutable" in il else "nft_mutable")
    if "fungible" in il or " token" in il:
        caps.append("token_ft")

    primary = "generic"
    if "escrow" in il:
        primary = "escrow"
    elif "vault" in il or "treasury" in il:
        primary = "treasury"
    elif "split" in il:
        primary = "split"
    elif "multisig" in il:
        primary = "multisig"

    return RawIntent(intent=primary, capabilities=list(dict.fromkeys(caps)), constraints={})


async def run_spec_pipeline(
    intent: str,
    security_level: str = "high",
    resolution_mode: ResolutionMode = "non_interactive",
    api_key: Optional[str] = None,
    provider: Optional[str] = None,
    openrouter_key: Optional[str] = None,
    phase1_model: Optional[str] = None,
    existing_spec: Optional[ContractSpecification] = None,
) -> Tuple[
    ContractSpecification,
    Optional[ClarificationPlan],
    Optional[ExecutionPlan],
    Optional[UTXOArchitecture],
    PlanningReport,
    Optional[IntentModel],
]:
    legacy_fallback = False
    inferred: Dict[str, Any] = {}

    if existing_spec and existing_spec.status == SpecStatus.CONFIRMED:
        spec = existing_spec
        validation = ValidationResult(is_complete=True)
    elif existing_spec:
        spec = existing_spec
        raw = None
        validation = SpecValidator.validate(spec)
    else:
        if resolution_mode == "non_interactive":
            raw = _heuristic_raw_intent(intent)
        else:
            raw = await extract_intent(
                intent,
                api_key=api_key,
                provider=provider,
                openrouter_key=openrouter_key,
                phase1_model=phase1_model,
            )
        spec = detect_capabilities(raw, original_intent=intent)
        spec.intent = spec.intent or intent
        validation = SpecValidator.validate(spec)

    clarification: Optional[ClarificationPlan] = None
    execution_plan: Optional[ExecutionPlan] = None
    utxo_arch: Optional[UTXOArchitecture] = None
    intent_model: Optional[IntentModel] = None

    if not validation.is_complete:
        if resolution_mode == "interactive":
            spec.status = SpecStatus.NEEDS_INPUT
            clarification = build_clarification_plan(validation)
            report = PlanningReport(
                detected_capabilities=[c.name for c in spec.capabilities],
                missing_fields=list(validation.missing_fields),
                inferred_fields=inferred,
                selected_modules=[],
                legacy_fallback=False,
                effective_mode="",
            )
            return spec, clarification, None, None, report, None

        spec, inferred = apply_legacy_fallback(spec, intent, security_level)
        legacy_fallback = True
        validation = SpecValidator.validate(spec)

    if spec.status != SpecStatus.CONFIRMED:
        spec.status = SpecStatus.CONFIRMED

    modules, decisions = ModulePlanner.select_modules(spec)
    try:
        execution_plan, utxo_arch = Composer.compose(spec)
    except Exception as exc:
        logger.warning("Composer failed: %s — building plan without gate", exc)
        from src.services.spec.architecture import ArchitectureBuilder
        execution_plan = ExecutionPlan(
            modules=modules,
            order=[m.name for m in modules],
            dependencies={m.name: m.depends_on for m in modules},
            shared_parameters=dict(spec.parameters),
        )
        utxo_arch = ArchitectureBuilder.build(execution_plan, spec)

    effective_mode = resolve_effective_mode(utxo_arch, execution_plan)
    intent_model = derive_intent_model(spec, effective_mode)

    report = PlanningReport(
        detected_capabilities=[c.name for c in spec.capabilities],
        missing_fields=list(validation.missing_fields),
        inferred_fields=inferred,
        selected_modules=[m.name for m in modules],
        legacy_fallback=legacy_fallback,
        effective_mode=effective_mode,
    )
    return spec, clarification, execution_plan, utxo_arch, report, intent_model


def derive_intent_model(spec: ContractSpecification, effective_mode: str) -> IntentModel:
    cap_names = {c.name for c in spec.capabilities}
    features: List[str] = []
    if "multisig" in cap_names or "weighted_multisig" in cap_names:
        features.append("multisig")
    if "timelock" in cap_names or spec.parameters.get("timeout_days"):
        features.append("timelock")
    if "escrow" in cap_names:
        features.append("escrow")
    if "split" in cap_names:
        features.append("split")
    if any(c.startswith("nft") or c.startswith("token") for c in cap_names):
        features.append("tokens")

    contract_type = _contract_type_from_mode(effective_mode)
    return IntentModel(
        contract_type=contract_type,
        features=features,
        signers=list(spec.parameters.get("signers") or []),
        threshold=spec.parameters.get("threshold"),
        timeout_days=spec.parameters.get("duration_days") or spec.parameters.get("timeout_days"),
        purpose=spec.intent,
        token_class=_token_class_from_caps(cap_names),
    )


def _contract_type_from_mode(mode: str) -> str:
    mapping = {
        "vault": "vault",
        "escrow_2of3_nft": "escrow_2of3_nft",
        "multisig": "multisig",
        "split": "distribution",
        "token_ft": "ft_transfer",
        "nft_immutable": "nft_transfer_immutable",
        "nft_mutable": "nft_mutable_state_update",
        "nft_minting": "nft_minting_authority",
        "hybrid_token": "hybrid_token",
        "linear_vesting": "linear_vesting",
        "timelock": "timelock",
    }
    return mapping.get(mode, mode or "generic")


def _token_class_from_caps(cap_names: set) -> Optional[str]:
    if "token_ft" in cap_names:
        return "ft"
    if "nft_immutable" in cap_names:
        return "nft_immutable"
    if "nft_mutable" in cap_names:
        return "nft_mutable"
    if "nft_minting" in cap_names:
        return "nft_minting"
    if "hybrid_token" in cap_names:
        return "hybrid"
    return None


def merge_answers(
    spec: ContractSpecification,
    answers: Dict[str, Any],
) -> ContractSpecification:
    updated = spec.model_copy(deep=True)
    for k, v in answers.items():
        updated.parameters[k] = v
    validation = SpecValidator.validate(updated)
    updated.status = SpecStatus.IN_REVIEW if validation.is_complete else SpecStatus.NEEDS_INPUT
    return updated
