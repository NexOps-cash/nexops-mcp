import logging
from typing import List, Dict, Any

from src.models import AuditIssue, AuditReport, Severity
from src.services.compiler import get_compiler_service
from src.services.dsl_lint import get_dsl_linter
from src.services.pipeline import Phase3
from src.services.scoring import calculate_audit_report

logger = logging.getLogger("nexops.audit_agent")

COMPILE_ERROR_MAP = {
    "ParseError": "compile_parse_error",
    "TypeMismatchError": "compile_type_mismatch",
    "UnusedVariableError": "compile_unused_variable",
    "ExtraneousInputError": "compile_extraneous_input",
    "TimeoutError": "compile_timeout",
    "CompilerNotFoundError": "compile_environment_error",
    "InternalError": "compile_internal_error",
    "UnknownError": "compile_unknown_error"
}

class AuditAgent:
    """
    Audits any CashScript contract by running it through the full NexOps synthesis validation stack:
    Compile -> DSL Lint -> Phase 3 (TollGate / AntiPatterns) -> Scoring
    """
    
    @staticmethod
    def audit(code: str, effective_mode: str = "") -> AuditReport:
        issues: List[AuditIssue] = []
        
        # ── 1. Compile Check (Syntactic validity) ──
        compiler = get_compiler_service()
        compile_result = compiler.compile(code)
        compile_success = compile_result.get("success", False)
        
        if not compile_success:
            err = compile_result.get("error", {})
            err_type = err.get("type", "UnknownError")
            rule_id = COMPILE_ERROR_MAP.get(err_type, "compile_unknown_error")
            
            issues.append(
                AuditIssue(
                    title=f"Compilation Failed: {err_type}",
                    severity=Severity.CRITICAL,
                    line=err.get("line") or 0,
                    description=f"The contract failed to compile: {err.get('raw', 'Unknown compiler error')}",
                    recommendation=err.get("hint", "Review syntax and compiler output."),
                    rule_id=rule_id,
                    can_fix=True
                )
            )
            
        # ── 2. DSL Lint (Structural conventions) ──
        linter = get_dsl_linter()
        lint_result = linter.lint(code, contract_mode=effective_mode)
        dsl_passed = lint_result.get("passed", False)
        
        for violation in lint_result.get("violations", []):
            rule_id = violation.get("rule_id", "unknown_lint")
            issues.append(
                AuditIssue(
                    title=f"DSL Structure Warning ({rule_id})",
                    severity=Severity.HIGH,  # DSL violations are usually fatal for compiler/logic
                    line=violation.get("line_hint", 0),
                    description=violation.get("message", "Lint rule violated."),
                    recommendation="Adhere to NexOps CashScript DSL conventions.",
                    rule_id=rule_id,
                    can_fix=True
                )
            )

        # ── 3. TollGate / AntiPatterns (Semantic security) ──
        toll_gate_result = Phase3.validate(code)
        structural_score = toll_gate_result.structural_score
        
        for violation in toll_gate_result.violations:
            rule_id = violation.rule
            
            # Anti-pattern severity is defined in the detector, default to CRITICAL/HIGH
            # We map string back to the Severity Enum
            sev_str = violation.severity.upper() if hasattr(violation, "severity") and violation.severity else "HIGH"
            try:
                severity = Severity(sev_str)
            except ValueError:
                severity = Severity.HIGH
                
            issues.append(
                AuditIssue(
                    title=f"Security Violation: {rule_id}",
                    severity=severity,
                    line=violation.location.get("line", 0) if violation.location else 0,
                    description=violation.exploit or violation.reason,
                    recommendation=violation.fix_hint or "Review contract architecture and apply secure patterns.",
                    rule_id=rule_id,
                    can_fix=True
                )
            )
            
        # ── 4. Aggregate, Deduplicate, Score, and Format ──
        report = calculate_audit_report(
            issues=issues,
            compile_success=compile_success,
            dsl_passed=dsl_passed,
            structural_score=structural_score,
            original_code=code
        )
        
        return report

def get_audit_agent() -> AuditAgent:
    return AuditAgent()
