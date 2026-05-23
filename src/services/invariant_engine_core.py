"""
Unified invariant engine core with generation/audit policy profiles (Wave 1.5).

Single validation loop; profiles control detector sets, invariant gating, and metadata routing.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence

from src.services.anti_pattern_detectors import AntiPatternDetector, Violation
from src.services.capability_detectors import (
    AUDIT_CAPABILITY_DETECTOR_REGISTRY,
    CAPABILITY_DETECTOR_REGISTRY,
)
from src.services.pattern_profiles import get_pattern_profile
from src.services.semantic_capabilities import extract_semantic_capabilities, save_capability_trace
from src.utils.cashscript_ast import CashScriptAST

logger = logging.getLogger("nexops.invariant_engine_core")


@dataclass(frozen=True)
class EnforcerPolicyProfile:
    """Declarative enforcer policy — no nested conditionals in extraction."""

    name: str
    base_detectors: Sequence[AntiPatternDetector]
    capability_detectors: Sequence[AntiPatternDetector]
    use_transaction_invariants: bool = False
    auth_classifier_metadata_only: bool = False
    include_stage_in_result: bool = False
    emit_capability_trace: bool = False


def _run_detectors(
    detectors: Sequence[AntiPatternDetector],
    ast: CashScriptAST,
    disabled: set,
    invariants: Optional[Dict[str, Any]] = None,
) -> List[Violation]:
    violations: List[Violation] = []
    for detector in detectors:
        if detector.id in disabled:
            continue
        try:
            if invariants is not None and hasattr(detector, "detect"):
                import inspect

                sig = inspect.signature(detector.detect)
                if len(sig.parameters) >= 2:
                    violation = detector.detect(ast, invariants)  # type: ignore[misc]
                else:
                    violation = detector.detect(ast)
            else:
                violation = detector.detect(ast)
            if violation:
                violations.append(violation)
        except Exception as exc:
            logger.error("Detector %s failed: %s", detector.id, exc)
    return violations


def validate_with_profile(
    code: str,
    profile: EnforcerPolicyProfile,
    *,
    contract_mode: str = "",
    stage: str = "generation",
    trace_case_id: str = "",
) -> Dict[str, Any]:
    """
    Run anti-pattern + capability detectors under a policy profile.
    """
    try:
        ast = CashScriptAST(code, contract_mode=contract_mode)
    except Exception as exc:
        logger.error("Failed to parse code: %s", exc)
        err = {
            "valid": False,
            "violated_rules": ["parse_error"],
            "violations": [
                {
                    "rule": "parse_error",
                    "reason": f"Failed to parse code: {exc}",
                    "exploit": "Cannot validate unparseable code",
                    "location": {},
                    "severity": "critical",
                }
            ],
        }
        if profile.include_stage_in_result:
            err["stage"] = stage
        return err

    pattern_profile = get_pattern_profile(contract_mode)
    disabled = set(pattern_profile.get("disable_detectors", []))

    invariants: Dict[str, Any] = {}
    if profile.use_transaction_invariants:
        try:
            from src.services.audit_engine.invariant_engine import InvariantEngine

            invariants = InvariantEngine(ast).analyze()
        except Exception as exc:
            logger.warning("InvariantEngine analysis failed: %s", exc)
            invariants = {}

    all_detectors: List[AntiPatternDetector] = list(profile.base_detectors) + list(
        profile.capability_detectors
    )
    raw_violations = _run_detectors(all_detectors, ast, disabled, invariants or None)
    violation_dicts = [v.to_dict() for v in raw_violations]

    if profile.auth_classifier_metadata_only:
        auth_metadata = [v for v in violation_dicts if v.get("rule") == "authorization_model_classifier"]
        findings = [v for v in violation_dicts if v.get("rule") != "authorization_model_classifier"]
    else:
        auth_metadata = []
        findings = violation_dicts

    caps = extract_semantic_capabilities(code, contract_mode=contract_mode)
    if profile.emit_capability_trace and trace_case_id:
        try:
            save_capability_trace(
                case_id=f"audit_{trace_case_id}",
                caps=caps,
                requirement_results={"profile": profile.name},
            )
        except OSError:
            pass

    result: Dict[str, Any] = {
        "valid": len(findings) == 0,
        "violated_rules": [v["rule"] for v in findings],
        "violations": findings,
        "capabilities": caps.to_trace_dict(),
    }
    if invariants:
        result["invariants"] = invariants
    if auth_metadata:
        result["auth_classifier_metadata"] = auth_metadata
    if profile.include_stage_in_result:
        result["stage"] = stage
    return result


def build_generation_profile(base_detectors: Sequence[AntiPatternDetector]) -> EnforcerPolicyProfile:
    return EnforcerPolicyProfile(
        name="generation",
        base_detectors=base_detectors,
        capability_detectors=CAPABILITY_DETECTOR_REGISTRY,
        use_transaction_invariants=False,
        auth_classifier_metadata_only=False,
        include_stage_in_result=True,
        emit_capability_trace=False,
    )


def build_audit_profile(base_detectors: Sequence[AntiPatternDetector]) -> EnforcerPolicyProfile:
    return EnforcerPolicyProfile(
        name="audit",
        base_detectors=base_detectors,
        capability_detectors=AUDIT_CAPABILITY_DETECTOR_REGISTRY,
        use_transaction_invariants=True,
        auth_classifier_metadata_only=True,
        include_stage_in_result=False,
        emit_capability_trace=True,
    )
