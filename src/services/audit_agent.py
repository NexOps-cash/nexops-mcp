import logging
from typing import List, Optional

from src.models import AuditIssue, AuditReport, Severity, IssueClass, ExploitSeverity
from src.services.compiler import get_compiler_service
from src.services.dsl_lint import get_dsl_linter
from src.services.pipeline import Phase3
from src.services.scoring import calculate_audit_report, ALLOWED_CATEGORIES

logger = logging.getLogger("nexops.audit_agent")

COMPILE_ERROR_MAP = {
    "ParseError": "compile_parse_error",
    "TypeMismatchError": "compile_type_mismatch",
    "UnusedVariableError": "compile_unused_variable",
    "ExtraneousInputError": "compile_extraneous_input",
    "TimeoutError": "compile_timeout",
    "CompilerNotFoundError": "compile_environment_error",
    "InternalError": "compile_internal_error",
    "UnknownError": "compile_unknown_error",
}

# ── Semantic Audit ──────────────────────────────────────────────────────────

SEMANTIC_SYSTEM_PROMPT = """\
You are a BCH CashScript smart-contract auditor.
Classify semantic risk with UTXO-aware reasoning only.

Use exactly one category:
- EXPLOIT
- DESIGN_TRADEOFF
- ASSUMPTION
- SAFE

For EXPLOIT also set exploit_severity:
- direct_fund_loss
- partial_violation
- griefing

For non-EXPLOIT set exploit_severity = "n/a".

Definitions:
- EXPLOIT: attacker can violate value/authorization invariants on-chain.
- DESIGN_TRADEOFF: intentional but risky architecture with no direct exploit proof.
- ASSUMPTION: safety relies on an external contract/system (deferred validation).
- SAFE: no meaningful semantic issue found.

Do NOT:
- mention reentrancy
- mention race conditions or front-running
- assume EVM account/call-stack behavior
- treat single-party control as a vulnerability by default

Focus only on:
- value conservation (BCH and tokenAmount flows)
- authorization bypass
- invariant breaks under attacker-controlled transaction structure

Return strict JSON only:
{
  "category": "EXPLOIT | DESIGN_TRADEOFF | ASSUMPTION | SAFE",
  "exploit_severity": "direct_fund_loss | partial_violation | griefing | n/a",
  "explanation": "short rationale",
  "confidence": 0.0,
  "business_logic_score": 0,
  "business_logic_notes": "short rationale"
}"""

SEMANTIC_CLASS_TO_INTERNAL = {
    "safe": "none",
    "assumption": "minor_design_risk",
    "design_tradeoff": "moderate_logic_risk",
    "exploit": "major_protocol_flaw",
    # Backward-compatible semantic labels from existing tests/providers.
    "none": "none",
    "minor_design_risk": "minor_design_risk",
    "moderate_logic_risk": "moderate_logic_risk",
    "major_protocol_flaw": "major_protocol_flaw",
    "funds_unspendable": "funds_unspendable",
}


def _downgrade_issue_class(issue_class: IssueClass) -> IssueClass:
    if issue_class == IssueClass.REAL_ISSUE:
        return IssueClass.CONTEXTUAL
    if issue_class == IssueClass.CONTEXTUAL:
        return IssueClass.NOISE
    return IssueClass.NOISE


def _severity_from_string(raw_severity: str) -> Severity:
    sev_str = (raw_severity or "HIGH").upper()
    if sev_str == "WARNING":
        sev_str = "MEDIUM"
    if sev_str == "INFO":
        return Severity.INFO
    try:
        return Severity(sev_str)
    except ValueError:
        return Severity.HIGH


def _build_semantic_user_prompt(code: str, intent: str) -> str:
    if intent:
        return (
            f"DECLARED INTENT:\n{intent}\n\n"
            f"CONTRACT TO AUDIT:\n{code}\n\n"
            "Classify the semantic risk category. Output strict JSON only."
        )
    return (
        f"CONTRACT TO AUDIT:\n{code}\n\n"
        "Identify the intended pattern (Escrow, Swap, Multisig, Vault, etc.) "
        "and classify the semantic risk category. Output strict JSON only."
    )


class AuditAgent:
    """
    Audits any CashScript contract through the full NexOps validation stack:
    Compile → DSL Lint → Phase 3 (TollGate / AntiPatterns) → Semantic Classification → Scoring
    """

    @staticmethod
    async def audit(
        code: str, 
        intent: str = "", 
        effective_mode: str = "", 
        api_key: Optional[str] = None, 
        provider: Optional[str] = None,
        groq_key: Optional[str] = None,
        openrouter_key: Optional[str] = None
    ) -> AuditReport:
        issues: List[AuditIssue] = []
        semantic_confidence: Optional[float] = None

        # ── 1. Compile Check ──────────────────────────────────────────────
        compiler = get_compiler_service()
        compile_result = compiler.compile(code)
        compile_success = compile_result.get("success", False)

        if not compile_success:
            err = compile_result.get("error", {})
            err_type = err.get("type", "UnknownError")
            rule_id = COMPILE_ERROR_MAP.get(err_type, "compile_unknown_error")

            # Internal/unknown compiler errors (e.g. Node.js runtime failures like
            # "sourceTags is not iterable") are environment issues, not security
            # defects — demote so they don't falsely block otherwise valid contracts.
            INTERNAL_ERR_TYPES = {"UnknownError", "InternalError", "CompilerNotFoundError", "TimeoutError"}
            compile_severity = Severity.HIGH if err_type in INTERNAL_ERR_TYPES else Severity.CRITICAL
            compile_issue_class = IssueClass.CONTEXTUAL if err_type in INTERNAL_ERR_TYPES else IssueClass.REAL_ISSUE
            compile_exploit = ExploitSeverity.GRIEFING if err_type in INTERNAL_ERR_TYPES else ExploitSeverity.DIRECT_FUND_LOSS
            compile_source = "toolchain" if err_type in INTERNAL_ERR_TYPES else "contract"

            issues.append(
                AuditIssue(
                    title=f"Compilation Failed: {err_type}",
                    severity=compile_severity,
                    line=err.get("line") or 0,
                    description=f"The contract failed to compile: {err.get('raw', 'Unknown compiler error')}",
                    recommendation=err.get("hint", "Review syntax and compiler output."),
                    rule_id=rule_id,
                    can_fix=True,
                    source=compile_source,
                    issue_class=compile_issue_class,
                    exploit_severity=compile_exploit,
                )
            )

        # ── 2. DSL Lint ───────────────────────────────────────────────────
        linter = get_dsl_linter()
        lint_result = linter.lint(code, contract_mode=effective_mode)
        dsl_passed = lint_result.get("passed", False)

        for violation in lint_result.get("violations", []):
            rule_id = violation.get("rule_id", "unknown_lint")
            lint_severity = _severity_from_string(violation.get("severity") or "HIGH")
            issue_class = IssueClass.NOISE if rule_id == "LNC-002" else IssueClass.CONTEXTUAL
            is_info = violation.get("severity", "").lower() == "info"
            issues.append(
                AuditIssue(
                    title=f"DSL Structure Warning ({rule_id})",
                    severity=lint_severity,
                    line=violation.get("line_hint", 0),
                    description=violation.get("message", "Lint rule violated."),
                    recommendation="Adhere to NexOps CashScript DSL conventions.",
                    rule_id=rule_id,
                    can_fix=not is_info,
                    issue_class=issue_class,
                    exploit_severity=ExploitSeverity.NOT_APPLICABLE,
                )
            )

        # ── 3. TollGate / AntiPatterns ────────────────────────────────────
        try:
            toll_gate_result = Phase3.validate(code, effective_mode)
        except TypeError:
            # Backward compatibility for mocked/legacy single-arg validators in tests.
            toll_gate_result = Phase3.validate(code)
        structural_score = toll_gate_result.structural_score

        for violation in toll_gate_result.violations:
            rule_id = violation.rule
            severity = _severity_from_string(
                violation.severity if hasattr(violation, "severity") else "HIGH"
            )
            issue_class = (
                IssueClass.REAL_ISSUE
                if severity in (Severity.CRITICAL, Severity.HIGH)
                else IssueClass.CONTEXTUAL
            )
            exploit_severity = ExploitSeverity.PARTIAL_VIOLATION
            deferred_validation = False

            if rule_id == "index_underflow":
                exploit_severity = ExploitSeverity.GRIEFING
                issue_class = IssueClass.REAL_ISSUE
            elif rule_id in {"commitment_length_missing", "vulnerable_covenant.cash"}:
                exploit_severity = ExploitSeverity.DIRECT_FUND_LOSS
            elif rule_id in {"unbounded_numeric_field", "authorization_model_classifier"}:
                exploit_severity = ExploitSeverity.GRIEFING
            elif severity == Severity.CRITICAL:
                exploit_severity = ExploitSeverity.DIRECT_FUND_LOSS

            if rule_id == "authorization_model_classifier" and severity == Severity.INFO:
                issue_class = IssueClass.NOISE
                exploit_severity = ExploitSeverity.NOT_APPLICABLE

            if (effective_mode or "").lower() == "parser" and "missing" in rule_id:
                deferred_validation = True
                issue_class = IssueClass.CONTEXTUAL

            issues.append(
                AuditIssue(
                    title=f"Security Violation: {rule_id}",
                    severity=severity,
                    line=violation.location.get("line", 0) if violation.location else 0,
                    description=violation.exploit or violation.reason,
                    recommendation=violation.fix_hint
                    or "Review contract architecture and apply secure patterns.",
                    rule_id=rule_id,
                    can_fix=True,
                    issue_class=issue_class,
                    exploit_severity=exploit_severity,
                    deferred_validation=deferred_validation,
                )
            )

        # ── 4. Semantic Classification (LLM) ─────────────────────────────
        # Skip entirely if compile failed — no point classifying broken code.
        semantic_category = "none"
        business_logic_score = 5   # conservative default if LLM skipped/fails

        if compile_success:
            try:
                from src.services.llm.factory import LLMFactory
                import json

                audit_provider = LLMFactory.get_provider(
                    "audit", 
                    api_key=api_key, 
                    provider_type=provider,
                    groq_key=groq_key,
                    openrouter_key=openrouter_key
                )
                user_prompt = _build_semantic_user_prompt(code, intent)

                raw_response = await audit_provider.complete(
                    user_prompt, system=SEMANTIC_SYSTEM_PROMPT
                )

                # Extract first valid JSON object from the response.
                decoder = json.JSONDecoder()
                start = raw_response.find("{")
                if start == -1:
                    raise ValueError("No JSON object found in LLM audit response.")
                semantic_data, _ = decoder.raw_decode(raw_response, start)

                semantic_label = str(semantic_data.get("category", "SAFE")).strip().lower()
                mapped_category = SEMANTIC_CLASS_TO_INTERNAL.get(semantic_label, "none")
                if mapped_category not in ALLOWED_CATEGORIES:
                    logger.warning(
                        f"[Semantic Audit] Unknown category '{semantic_label}' — defaulting to 'none'."
                    )
                    mapped_category = "none"

                semantic_category = mapped_category
                confidence = semantic_data.get("confidence", 0.0)
                try:
                    semantic_confidence = max(0.0, min(1.0, float(confidence)))
                except (TypeError, ValueError):
                    semantic_confidence = 0.0
                explanation = semantic_data.get("explanation", "")
                semantic_exploit = str(semantic_data.get("exploit_severity", "n/a")).strip().lower()
                exploit_map = {
                    "direct_fund_loss": ExploitSeverity.DIRECT_FUND_LOSS,
                    "partial_violation": ExploitSeverity.PARTIAL_VIOLATION,
                    "griefing": ExploitSeverity.GRIEFING,
                    "n/a": ExploitSeverity.NOT_APPLICABLE,
                }
                semantic_exploit_severity = exploit_map.get(semantic_exploit, ExploitSeverity.NOT_APPLICABLE)

                # Free-form business logic score (0-10)
                raw_biz = semantic_data.get("business_logic_score", 5)
                try:
                    business_logic_score = max(0, min(10, int(raw_biz)))
                except (TypeError, ValueError):
                    business_logic_score = 5
                biz_notes = semantic_data.get("business_logic_notes", "")

                logger.info(
                    f"[Semantic Audit] category={semantic_category!r} "
                    f"confidence={semantic_confidence:.2f} biz_score={business_logic_score}/10 | "
                    f"{explanation[:80]} | {biz_notes[:80]}"
                )

                # ── 4.5 Inject Semantic Issue into Report ──────────────────
                if semantic_category != "none":
                    title_map = {
                        "funds_unspendable": "Critical Risk: Funds Permanently Locked",
                        "major_protocol_flaw": "Critical Risk: Major Protocol Flaw",
                        "moderate_logic_risk": "Security Risk: Moderate Logic Flaw",
                        "minor_design_risk": "Design Risk: Suboptimal Architecture",
                    }
                    severity_map = {
                        "funds_unspendable": Severity.CRITICAL,
                        "major_protocol_flaw": Severity.CRITICAL,
                        "moderate_logic_risk": Severity.HIGH,
                        "minor_design_risk": Severity.MEDIUM,
                    }
                    semantic_issue_class = IssueClass.REAL_ISSUE
                    deferred_validation = False
                    if semantic_label == "design_tradeoff":
                        semantic_issue_class = IssueClass.CONTEXTUAL
                        if semantic_exploit_severity == ExploitSeverity.NOT_APPLICABLE:
                            semantic_exploit_severity = ExploitSeverity.GRIEFING
                    elif semantic_label == "assumption":
                        semantic_issue_class = IssueClass.CONTEXTUAL
                        semantic_exploit_severity = ExploitSeverity.NOT_APPLICABLE
                        deferred_validation = True
                    elif semantic_label == "safe":
                        semantic_issue_class = IssueClass.NOISE
                        semantic_exploit_severity = ExploitSeverity.NOT_APPLICABLE
                    elif semantic_label == "exploit" and semantic_exploit_severity == ExploitSeverity.NOT_APPLICABLE:
                        semantic_exploit_severity = ExploitSeverity.DIRECT_FUND_LOSS

                    if semantic_confidence is not None and semantic_confidence < 0.5:
                        semantic_issue_class = _downgrade_issue_class(semantic_issue_class)
                    
                    issues.append(
                        AuditIssue(
                            title=title_map.get(semantic_category, f"Semantic Risk: {semantic_category}"),
                            severity=severity_map.get(semantic_category, Severity.HIGH),
                            line=0,
                            description=explanation or f"Semantic risk category '{semantic_category}' detected.",
                            recommendation=biz_notes or "Review the contract logic and ensure all spending paths are reachable.",
                            rule_id=f"semantic_{semantic_category}",
                            can_fix=False, # Semantic logic deadlocks usually require human redesign
                            issue_class=semantic_issue_class,
                            exploit_severity=semantic_exploit_severity,
                            deferred_validation=deferred_validation,
                        )
                    )

            except Exception as e:
                logger.error(f"[Semantic Audit] LLM classification failed: {e} — defaulting to 'none'.")
                semantic_category = "none"
                business_logic_score = 5   # conservative default on failure
                semantic_confidence = None
        else:
            logger.info("[Semantic Audit] Skipped — compile failed.")

        # ── 5. Aggregate, Score, Return ───────────────────────────────────
        report = calculate_audit_report(
            issues=issues,
            compile_success=compile_success,
            dsl_passed=dsl_passed,
            structural_score=structural_score,
            semantic_category=semantic_category,
            business_logic_score=business_logic_score,
            semantic_confidence=semantic_confidence,
            original_code=code,
        )

        return report


def get_audit_agent() -> AuditAgent:
    return AuditAgent()
