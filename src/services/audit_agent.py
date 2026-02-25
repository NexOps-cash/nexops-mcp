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
    async def audit(code: str, intent: str = "", effective_mode: str = "") -> AuditReport:
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
            # Respect the severity hint from the linter:
            # 'info' → LOW (non-blocking, informational)
            # absent → HIGH (DSL violations are usually fatal for compiler/logic)
            lint_sev_str = (violation.get("severity") or "HIGH").upper()
            if lint_sev_str == "INFO":
                lint_sev_str = "LOW"  # Severity enum has no INFO; map to LOW
            try:
                lint_severity = Severity(lint_sev_str)
            except ValueError:
                lint_severity = Severity.HIGH
            is_info = violation.get("severity", "").lower() == "info"
            issues.append(
                AuditIssue(
                    title=f"DSL Structure Warning ({rule_id})",
                    severity=lint_severity,
                    line=violation.get("line_hint", 0),
                    description=violation.get("message", "Lint rule violated."),
                    recommendation="Adhere to NexOps CashScript DSL conventions.",
                    rule_id=rule_id,
                    can_fix=not is_info  # Info notes don't need AI repair
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
            
        # ── 4. Phase 4: Semantic Logic Review (LLM) ──
        # Evaluates the actual meaning of the contract vs the intent.
        semantic_score = None
        
        try:
            from src.services.llm.factory import LLMFactory
            import json
            
            audit_provider = LLMFactory.get_provider("audit")
            
            system_prompt = """You are a CashScript Security Auditor.
Your job is to analyze the logic of the contract and find semantic/game-theoretic bugs (e.g., deadlocks, unspendable branches, missing timeouts, broken invariants).
Do NOT complain about syntax, formatting, or missing PRAGMA statements.
Focus ONLY on the logic flow and constraints.

Return ONLY a JSON object exactly matching this schema:
{
  "semantic_score": <int 0-100, 100 means perfect logic match>,
  "semantic_issues": [
    {
      "title": "<Short title of logical flaw>",
      "description": "<Detailed explanation of why it is broken>",
      "severity": "<CRITICAL or HIGH or MEDIUM>"
    }
  ]
}"""

            if intent:
                user_prompt = f"""DECLARED INTENT:
{intent}

CONTRACT TO AUDIT:
{code}

Tasks:
1. Summarize internally what this contract actually does.
2. Does it perfectly match the declared intent?
3. Point out logical mismatches, deadlocks, or security flaws where the code fails the intent.
Output JSON."""
            else:
                user_prompt = f"""CONTRACT TO AUDIT:
{code}

Tasks:
1. Analyze this CashScript contract. Identify its likely intended pattern (e.g., Escrow, Swap, Multisig, Vault).
2. Identify any internal logical contradictions, deadlocks, or conditions where funds might become permanently stuck or stolen based on standard conventions for that pattern.
Output JSON."""

            raw_response = await audit_provider.complete(user_prompt, system=system_prompt)
            
            # Use raw_decode to find and parse the first valid JSON object.
            # This correctly handles nested {} braces inside string fields,
            # which the greedy regex approach cannot.
            decoder = json.JSONDecoder()
            start = raw_response.find('{')
            if start == -1:
                raise ValueError("No JSON object found in LLM audit response.")
            semantic_data, _ = decoder.raw_decode(raw_response, start)
                
            semantic_data = semantic_data
            semantic_score = semantic_data.get("semantic_score", None)
            
            for s_issue in semantic_data.get("semantic_issues", []):
                sev_str = s_issue.get("severity", "HIGH").upper()
                try:
                    severity = Severity(sev_str)
                except ValueError:
                    severity = Severity.HIGH
                    
                issues.append(
                    AuditIssue(
                        title=f"Semantic Flaw: {s_issue.get('title', 'Logic Error')}",
                        severity=severity,
                        line=0, # Semantic issues apply to the whole contract
                        description=s_issue.get("description", "A logical flaw was detected."),
                        recommendation="Review the contract's business logic against the intended pattern.",
                        rule_id="semantic_logic_flaw",
                        can_fix=True
                    )
                )
                
            logger.info(f"[Semantic Audit] Completed. Score: {semantic_score}")
            
        except Exception as e:
            logger.error(f"[Semantic Audit] Failed to execute LLM logic review: {e}")

        # ── 5. Aggregate, Deduplicate, Score, and Format ──
        report = calculate_audit_report(
            issues=issues,
            compile_success=compile_success,
            dsl_passed=dsl_passed,
            structural_score=structural_score,
            semantic_score=semantic_score,
            original_code=code
        )
        
        return report

def get_audit_agent() -> AuditAgent:
    return AuditAgent()
