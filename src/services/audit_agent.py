import logging
from typing import List, Optional

from src.models import AuditIssue, AuditReport, Severity
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
You are a CashScript Security Auditor. You must perform TWO assessments:

─────────────────────────────────────────────
PART 1 — Structural Risk Category (choose EXACTLY ONE):
─────────────────────────────────────────────
  none                – No semantic issues. Logic is sound and complete.
  minor_design_risk   – Suboptimal design but not exploitable under normal conditions.
  moderate_logic_risk – Logical flaw that could be exploited under adversarial conditions.
  major_protocol_flaw – Serious protocol-level flaw that breaks core contract guarantees.
  funds_unspendable   – Funds are PERMANENTLY locked with NO exit path whatsoever.

Rules for "funds_unspendable" (use ONLY when ALL apply):
  • Funds are locked back into the same contract or a void with no exit.
  • No branch exists that pays out to any external address.
  • Both the release branch AND the refund branch are missing or permanently unreachable.
  • Logic structurally leads to a deadlock with no time-based escape.
  DO NOT use "funds_unspendable" for: power imbalance, arbiter fairness debates,
  timeout disagreements, or game-theory critique.

─────────────────────────────────────────────
PART 2 — Business Logic Quality Score (integer 0-10):
─────────────────────────────────────────────
Assess the SUBJECTIVE quality of the business logic. This is your FREE-FORM judgment.
Consider:
  • Race conditions or timing-based attack windows (e.g., front-running, UTXO races)
  • Multi-party fairness: does any single party hold disproportionate power to grief others?
  • Edge-case handling: what happens when values are 0, min, or max?
  • Economic incentive alignment: are all parties incentivised to behave honestly?
  • Completeness: are there common scenarios the contract fails to handle?

Scoring guide:
  10 = Excellent business logic, no conceivable subjective concern
   8 = Minor subjective gaps but unlikely to matter in practice
   5 = Noticeable business logic weakness that a sophisticated user should know about
   3 = Significant subjective concern (e.g., clear race window or power imbalance)
   0 = Business logic is fundamentally unsound

Note: Even well-written contracts rarely deserve 10/10. Be honest and strict.

Do NOT re-examine syntax, formatting, or PRAGMA.

You MUST return ONLY a strict JSON object — no prose, no markdown, no explanation outside JSON:
{
  "category": "<one of the 5 categories above>",
  "explanation": "<brief explanation of the category classification>",
  "confidence": <float 0.0-1.0>,
  "business_logic_score": <integer 0-10>,
  "business_logic_notes": "<brief explanation of the business logic score>"
}"""


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
        provider: Optional[str] = None
    ) -> AuditReport:
        issues: List[AuditIssue] = []

        # ── 1. Compile Check ──────────────────────────────────────────────
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
                    can_fix=True,
                )
            )

        # ── 2. DSL Lint ───────────────────────────────────────────────────
        linter = get_dsl_linter()
        lint_result = linter.lint(code, contract_mode=effective_mode)
        dsl_passed = lint_result.get("passed", False)

        for violation in lint_result.get("violations", []):
            rule_id = violation.get("rule_id", "unknown_lint")
            lint_sev_str = (violation.get("severity") or "HIGH").upper()
            if lint_sev_str == "INFO":
                lint_sev_str = "LOW"
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
                    can_fix=not is_info,
                )
            )

        # ── 3. TollGate / AntiPatterns ────────────────────────────────────
        toll_gate_result = Phase3.validate(code)
        structural_score = toll_gate_result.structural_score

        for violation in toll_gate_result.violations:
            rule_id = violation.rule
            sev_str = (
                violation.severity.upper()
                if hasattr(violation, "severity") and violation.severity
                else "HIGH"
            )
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
                    recommendation=violation.fix_hint
                    or "Review contract architecture and apply secure patterns.",
                    rule_id=rule_id,
                    can_fix=True,
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

                audit_provider = LLMFactory.get_provider("audit", api_key=api_key, provider_type=provider)
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

                raw_category = str(semantic_data.get("category", "none")).strip().lower()
                if raw_category not in ALLOWED_CATEGORIES:
                    logger.warning(
                        f"[Semantic Audit] Unknown category '{raw_category}' — defaulting to 'none'."
                    )
                    raw_category = "none"

                semantic_category = raw_category
                confidence = semantic_data.get("confidence", 0.0)
                explanation = semantic_data.get("explanation", "")

                # Free-form business logic score (0-10)
                raw_biz = semantic_data.get("business_logic_score", 5)
                try:
                    business_logic_score = max(0, min(10, int(raw_biz)))
                except (TypeError, ValueError):
                    business_logic_score = 5
                biz_notes = semantic_data.get("business_logic_notes", "")

                logger.info(
                    f"[Semantic Audit] category={semantic_category!r} "
                    f"confidence={confidence:.2f} biz_score={business_logic_score}/10 | "
                    f"{explanation[:80]} | {biz_notes[:80]}"
                )

            except Exception as e:
                logger.error(f"[Semantic Audit] LLM classification failed: {e} — defaulting to 'none'.")
                semantic_category = "none"
                business_logic_score = 5   # conservative default on failure
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
            original_code=code,
        )

        return report


def get_audit_agent() -> AuditAgent:
    return AuditAgent()
