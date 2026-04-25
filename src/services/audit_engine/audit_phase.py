"""Audit-only deterministic validation phase.

This replaces `Phase3.validate` for AuditAgent only. It does not import Phase1,
Phase2, or the generator pipeline.
"""

from src.models import TollGateResult, ViolationDetail
from src.services.audit_engine.audit_detectors import AUDIT_DETECTOR_REGISTRY
from src.services.audit_engine.audit_enforcer import get_audit_enforcer
from src.services.audit_engine.audit_lint import get_audit_linter
from src.utils.cashscript_ast import CashScriptAST


def validate_audit(code: str, contract_mode: str = "") -> TollGateResult:
    """Run deterministic audit lint and audit detectors."""
    # Explicit parse keeps mode-aware AST behavior visible at this boundary.
    CashScriptAST(code, contract_mode=contract_mode)

    linter = get_audit_linter()
    enforcer = get_audit_enforcer()

    violations: list[ViolationDetail] = []

    lint_result = linter.lint(code, contract_mode=contract_mode)
    for violation in lint_result.get("violations", []):
        violations.append(
            ViolationDetail(
                rule=violation.get("rule_id", "unknown_lint"),
                reason=violation.get("message", "Lint rule violated."),
                exploit=violation.get("exploit", ""),
                fix_hint=violation.get("fix_hint", ""),
                location={"line": violation.get("line_hint", 0)},
                severity=violation.get("severity", "medium"),
            )
        )

    enforcer_result = enforcer.validate_code(code, contract_mode=contract_mode)
    enforcer_violations = enforcer_result.get("violations", [])
    for violation in enforcer_violations:
        violations.append(
            ViolationDetail(
                rule=violation.get("rule", "unknown_detector"),
                reason=violation.get("reason", ""),
                exploit=violation.get("exploit", ""),
                fix_hint=violation.get("fix_hint", ""),
                location=violation.get("location", {}),
                severity=violation.get("severity", "medium"),
            )
        )

    detector_ids = {detector.id for detector in AUDIT_DETECTOR_REGISTRY}
    failed_detectors = {
        violation.get("rule")
        for violation in enforcer_violations
        if violation.get("rule") in detector_ids
    }
    total_detectors = len(AUDIT_DETECTOR_REGISTRY)
    structural_score = (
        (total_detectors - len(failed_detectors)) / total_detectors
        if total_detectors
        else 1.0
    )

    critical_violations = [violation for violation in violations if violation.severity == "critical"]
    return TollGateResult(
        passed=len(critical_violations) == 0,
        violations=violations,
        hallucination_flags=[],
        structural_score=structural_score,
    )
