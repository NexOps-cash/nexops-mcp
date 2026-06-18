import logging
from typing import List, Optional

from src.models import (
    AuditIssue,
    AuditReport,
    ConfidenceLevel,
    ExploitSeverity,
    FindingKind,
    IntentModel,
    IssueClass,
    Provenance,
    SemanticVerdict,
    Severity,
    Triggerability,
)
from src.services.audit_engine.audit_lint import get_audit_linter as get_dsl_linter
from src.services.audit_engine.audit_phase import validate_audit
from src.services.audit_engine.invariant_engine import InvariantEngine
from src.services.audit_fact_bundle import build_audit_fact_bundle
from src.services.compiler import get_compiler_service
from src.services.finding_policy import (
    finalize_from_judgment,
    kind_to_semantic_category,
    finalize,
    is_exploitable,
    log_judgment_contradictions,
)
from src.services.intent_invariants import (
    build_invariant_matrix,
    verify_intent_invariants,
)
from src.services.scoring import calculate_audit_report
from src.services.semantic_capabilities import extract_semantic_capabilities
from src.services.semantic_judge import (
    parse_legacy_semantic_response,
    run_semantic_judge,
    semantic_judge_v2_enabled,
)
from src.utils.cashscript_ast import CashScriptAST

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
    "ToolchainError": "compile_toolchain_error",
}

# ── Semantic Audit ──────────────────────────────────────────────────────────

SEMANTIC_SYSTEM_PROMPT = """\
You are a BCH CashScript smart-contract auditor.
Classify semantic risk with UTXO-aware reasoning only.

UTXO / BCH guardrails (must respect):
- Every input to a valid transaction is consumed when the spend succeeds; the spending path authorizes that input.
- If a required authorization or policy token appears on an input, that input is a controlled, signed spend of that UTXO — it is not automatically an "attacker-injected bypass" of the authorizer merely because a token with the right category also appears on a different input in the same transaction.
- Distinguish (a) a concrete on-chain value-loss or authorization-bypass from (b) design tradeoffs, operational failures, or off-chain/issuer assumptions. Do not label (b) as EXPLOIT.

Operational vs security (critical):
- Treasury underfunding, insufficient input balance, liquidity shortages, fee/dust handling, and missing change outputs are NOT exploits — they are operational or deployment concerns unless an attacker can extract more value than entitled.
- Script failure for honest users due to rigid equality is a design tradeoff, not a security vulnerability.

You will receive an INVARIANT MATRIX listing ENFORCED and MISSING intent checks. Do NOT re-report invariants already listed as ENFORCED or MISSING in that matrix.

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
- infer "bypass" from multi-input layouts alone when a category-based auth check is the intended design

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
    "none": "none",
    "minor_design_risk": "minor_design_risk",
    "moderate_logic_risk": "moderate_logic_risk",
    "major_protocol_flaw": "major_protocol_flaw",
    "funds_unspendable": "funds_unspendable",
}


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


# Compile-time critical finding — never severity-cap via grief-only heuristic
_NO_GRIEF_CAP_TOLL_RULES = frozenset(
    {
        "cashscript_unsupported_top_level_while",
    }
)


def _build_semantic_user_prompt(
    code: str,
    intent: str,
    invariant_matrix_text: str = "",
) -> str:
    parts: List[str] = []
    if intent:
        parts.append(f"DECLARED INTENT:\n{intent}\n")
    if invariant_matrix_text:
        parts.append(f"INVARIANT MATRIX:\n{invariant_matrix_text}\n")
    parts.append(f"CONTRACT TO AUDIT:\n{code}\n")
    parts.append(
        "Classify semantic risk for issues NOT already covered by the invariant matrix. "
        "Output strict JSON only."
    )
    return "\n".join(parts)


def _emit_issue(
    *,
    summary: str,
    description: str,
    recommendation: str,
    rule_id: str,
    line: int = 0,
    can_fix: bool = True,
    source: str = "deterministic",
    proposed_severity: Optional[Severity] = None,
    semantic_label: str = "",
    exploit_severity: ExploitSeverity = ExploitSeverity.NOT_APPLICABLE,
    provenance: Provenance = Provenance.DETERMINISTIC,
    confidence_score: Optional[float] = None,
    kind: Optional[FindingKind] = None,
    triggerability: Optional[Triggerability] = None,
    deferred_validation: bool = False,
) -> AuditIssue:
    text = f"{summary} {description}"
    finalized = finalize(
        kind=kind,
        proposed_severity=proposed_severity,
        summary=summary,
        rule_id=rule_id,
        semantic_label=semantic_label,
        text=text,
        exploit_severity=exploit_severity,
        provenance=provenance,
        confidence_score=confidence_score,
        deferred_validation=deferred_validation,
        triggerability=triggerability,
    )
    return AuditIssue(
        title=finalized.title,
        severity=finalized.severity,
        line=line,
        description=description,
        recommendation=recommendation,
        rule_id=rule_id,
        can_fix=can_fix,
        source=source,
        issue_class=finalized.issue_class,
        exploit_severity=finalized.exploit_severity,
        deferred_validation=deferred_validation,
        kind=finalized.kind,
        confidence=finalized.confidence,
        confidence_score=confidence_score,
        provenance=provenance,
        triggerability=finalized.triggerability,
    )


class AuditAgent:
    """
    Audits any CashScript contract through the full NexOps validation stack:
    Compile → DSL Lint → Phase 3 (TollGate / AntiPatterns) → Intent Invariants
    → Semantic Classification → Scoring
    """

    @staticmethod
    async def audit(
        code: str,
        intent: str = "",
        effective_mode: str = "",
        intent_model: Optional[IntentModel] = None,
        api_key: Optional[str] = None,
        provider: Optional[str] = None,
        openrouter_key: Optional[str] = None,
    ) -> AuditReport:
        issues: List[AuditIssue] = []
        semantic_confidence: Optional[float] = None

        invariant_matrix = build_invariant_matrix(code, intent, intent_model)
        invariant_matrix_text = invariant_matrix.format_for_prompt()

        # ── 1. Compile Check ──────────────────────────────────────────────
        compiler = get_compiler_service()
        compile_result = compiler.compile(code)
        compile_success = compile_result.get("success", False)
        compile_toolchain_error = bool(compile_result.get("toolchain_error", False))

        if not compile_success:
            err = compile_result.get("error", {})
            err_type = err.get("type", "UnknownError")
            rule_id = COMPILE_ERROR_MAP.get(err_type, "compile_unknown_error")

            INTERNAL_ERR_TYPES = {
                "UnknownError",
                "InternalError",
                "CompilerNotFoundError",
                "TimeoutError",
                "ToolchainError",
            }
            is_internal = err_type in INTERNAL_ERR_TYPES
            if err_type == "ToolchainError":
                compile_title = "Compiler toolchain error (cashc/Node)"
                compile_desc = (
                    "The cashc compiler crashed with an internal error — this is not a CashScript syntax "
                    f"diagnosis. Raw output: {err.get('raw', '')}"
                )
            else:
                compile_title = f"Compilation Failed: {err_type}"
                compile_desc = f"The contract failed to compile: {err.get('raw', 'Unknown compiler error')}"

            issues.append(
                _emit_issue(
                    summary=compile_title,
                    description=compile_desc.strip(),
                    recommendation=err.get("hint", "Review syntax and compiler output."),
                    rule_id=rule_id,
                    line=err.get("line") or 0,
                    proposed_severity=Severity.HIGH if is_internal else Severity.HIGH,
                    kind=FindingKind.OPERATIONAL_RISK,
                    triggerability=Triggerability.NON_ATTACKER,
                    exploit_severity=ExploitSeverity.NOT_APPLICABLE,
                    provenance=Provenance.DETERMINISTIC,
                )
            )

        # ── 2. DSL Lint ───────────────────────────────────────────────────
        linter = get_dsl_linter()
        lint_result = linter.lint(code, contract_mode=effective_mode)
        dsl_passed = lint_result.get("passed", False)

        for violation in lint_result.get("violations", []):
            rule_id = violation.get("rule_id", "unknown_lint")
            lint_severity = _severity_from_string(violation.get("severity") or "HIGH")
            is_info = violation.get("severity", "").lower() == "info"
            message = violation.get("message", "")
            if (
                lint_severity == Severity.HIGH
                and not is_exploitable(message=message)
            ):
                lint_severity = Severity.MEDIUM

            issues.append(
                _emit_issue(
                    summary=f"DSL Structure Warning ({rule_id})",
                    description=message or "Lint rule violated.",
                    recommendation="Adhere to NexOps CashScript DSL conventions.",
                    rule_id=rule_id,
                    line=violation.get("line_hint", 0),
                    can_fix=not is_info,
                    proposed_severity=lint_severity,
                    kind=FindingKind.OBSERVATION if rule_id == "LNC-002" else None,
                    provenance=Provenance.DETERMINISTIC,
                )
            )

        # ── 3. TollGate / AntiPatterns ────────────────────────────────────
        toll_gate_result = validate_audit(code, effective_mode)
        structural_score = toll_gate_result.structural_score

        for violation in toll_gate_result.violations:
            rule_id = violation.rule
            severity = _severity_from_string(
                violation.severity if hasattr(violation, "severity") else "HIGH"
            )
            exploit_severity = ExploitSeverity.PARTIAL_VIOLATION
            deferred_validation = False

            if rule_id == "index_underflow":
                exploit_severity = ExploitSeverity.GRIEFING
            elif rule_id in {"commitment_length_missing", "vulnerable_covenant.cash"}:
                exploit_severity = ExploitSeverity.DIRECT_FUND_LOSS
            elif rule_id in {"unbounded_numeric_field", "authorization_model_classifier"}:
                exploit_severity = ExploitSeverity.GRIEFING
            elif severity == Severity.CRITICAL:
                exploit_severity = ExploitSeverity.DIRECT_FUND_LOSS

            if rule_id == "authorization_model_classifier" and severity == Severity.INFO:
                exploit_severity = ExploitSeverity.NOT_APPLICABLE

            if (effective_mode or "").lower() == "parser" and "missing" in rule_id:
                deferred_validation = True

            v_reason = violation.reason or ""
            v_exploit = violation.exploit or ""
            if (
                severity == Severity.HIGH
                and rule_id not in _NO_GRIEF_CAP_TOLL_RULES
                and not is_exploitable(v_reason, v_exploit)
            ):
                severity = Severity.MEDIUM
                exploit_severity = ExploitSeverity.GRIEFING

            description = v_exploit or v_reason
            issues.append(
                _emit_issue(
                    summary=rule_id.replace("_", " "),
                    description=description,
                    recommendation=violation.fix_hint
                    or "Review contract architecture and apply secure patterns.",
                    rule_id=rule_id,
                    line=violation.location.get("line", 0) if violation.location else 0,
                    proposed_severity=severity,
                    exploit_severity=exploit_severity,
                    deferred_validation=deferred_validation,
                    provenance=Provenance.DETERMINISTIC,
                )
            )

        # ── 3.5 Intent invariant verification (deterministic) ─────────────
        if compile_success and (intent or intent_model):
            intent_issues = verify_intent_invariants(code, intent, intent_model)
            issues.extend(intent_issues)

        # ── 3.6 Capabilities + fact bundle (before semantic judge) ─────────
        sem_caps = extract_semantic_capabilities(code, contract_mode=effective_mode)
        engine_invariants: dict = {}
        if compile_success:
            try:
                engine_invariants = InvariantEngine(CashScriptAST(code)).analyze()
            except Exception as exc:
                logger.warning("[Audit] InvariantEngine analyze failed: %s", exc)

        fact_bundle = build_audit_fact_bundle(
            code=code,
            intent=intent,
            intent_model=intent_model,
            invariant_matrix=invariant_matrix,
            sem_caps=sem_caps,
            engine_invariants=engine_invariants,
            existing_issues=issues,
            effective_mode=effective_mode,
        )

        # ── 4. Semantic Security Judge (LLM) ─────────────────────────────
        semantic_category = "none"
        business_logic_score = 5

        if compile_success:
            try:
                from src.services.llm.factory import LLMFactory
                import json

                audit_provider = LLMFactory.get_provider(
                    "audit",
                    api_key=api_key,
                    provider_type=provider,
                    openrouter_key=openrouter_key,
                )

                if semantic_judge_v2_enabled():
                    judgment = await run_semantic_judge(
                        code=code,
                        intent=intent,
                        bundle=fact_bundle,
                        audit_provider=audit_provider,
                    )
                    log_judgment_contradictions(judgment, fact_bundle)

                    business_logic_score = judgment.intent_fidelity_score
                    business_logic_notes = judgment.intent_fidelity_notes
                    semantic_confidence = (
                        judgment.finding.confidence
                        if judgment.finding
                        else None
                    )

                    logger.info(
                        "[Semantic Judge V2] verdict=%s fidelity=%s/10 confidence=%s",
                        judgment.verdict.value,
                        business_logic_score,
                        semantic_confidence,
                    )

                    if judgment.verdict == SemanticVerdict.FINDING and judgment.finding:
                        finalized = finalize_from_judgment(judgment)
                        if finalized:
                            finding = judgment.finding
                            description = finding.reasoning or finding.summary
                            semantic_issue = _emit_issue(
                                summary=finding.summary[:80]
                                if finding.summary
                                else finalized.title,
                                description=description
                                or "Semantic security judgment.",
                                recommendation=finding.recommendation
                                or business_logic_notes
                                or "Review the contract logic.",
                                rule_id=f"semantic_{kind_to_semantic_category(finalized.kind)}",
                                can_fix=False,
                                source="semantic",
                                semantic_label="",
                                exploit_severity=finalized.exploit_severity,
                                provenance=Provenance.LLM,
                                confidence_score=judgment.finding.confidence
                                if judgment.finding
                                else None,
                                deferred_validation=finding.deferred_validation,
                                kind=finalized.kind,
                                triggerability=finalized.triggerability,
                                proposed_severity=finalized.severity,
                            )
                            if finalized.kind == FindingKind.VULNERABILITY and (
                                "unspendable" in (finding.gap_id or "").lower()
                                or finding.affected_invariant == "funds_unspendable"
                            ):
                                semantic_issue = semantic_issue.model_copy(
                                    update={
                                        "rule_id": "semantic_funds_unspendable",
                                        "severity": Severity.CRITICAL,
                                    }
                                )

                            issues.append(semantic_issue)
                            gap_lower = (finding.gap_id or "").lower()
                            is_unspendable = (
                                "unspendable" in gap_lower
                                or finding.affected_invariant == "funds_unspendable"
                            )
                            if is_unspendable:
                                semantic_category = "funds_unspendable"
                            else:
                                semantic_category = kind_to_semantic_category(finalized.kind)
                else:
                    user_prompt = _build_semantic_user_prompt(
                        code, intent, invariant_matrix_text
                    )

                    raw_response = await audit_provider.complete(
                        user_prompt, system=SEMANTIC_SYSTEM_PROMPT
                    )

                    decoder = json.JSONDecoder()
                    start = raw_response.find("{")
                    if start == -1:
                        raise ValueError("No JSON object found in LLM audit response.")
                    semantic_data, _ = decoder.raw_decode(raw_response, start)

                    judgment = parse_legacy_semantic_response(semantic_data)
                    business_logic_score = judgment.intent_fidelity_score
                    business_logic_notes = judgment.intent_fidelity_notes
                    semantic_confidence = (
                        judgment.finding.confidence if judgment.finding else None
                    )

                    if judgment.verdict == SemanticVerdict.FINDING and judgment.finding:
                        finalized = finalize_from_judgment(judgment)
                        if finalized:
                            finding = judgment.finding
                            semantic_category = kind_to_semantic_category(finalized.kind)
                            semantic_issue = _emit_issue(
                                summary=finding.summary[:80]
                                if finding.summary
                                else finalized.title,
                                description=finding.reasoning or finding.summary,
                                recommendation=finding.recommendation
                                or business_logic_notes
                                or "Review the contract logic.",
                                rule_id=f"semantic_{semantic_category}",
                                can_fix=False,
                                source="semantic",
                                semantic_label="",
                                exploit_severity=finalized.exploit_severity,
                                provenance=Provenance.LLM,
                                confidence_score=semantic_confidence,
                                deferred_validation=finding.deferred_validation,
                                kind=finalized.kind,
                                triggerability=finalized.triggerability,
                                proposed_severity=finalized.severity,
                            )
                            if semantic_category == "funds_unspendable":
                                semantic_issue = semantic_issue.model_copy(
                                    update={
                                        "rule_id": "semantic_funds_unspendable",
                                        "severity": Severity.CRITICAL,
                                    }
                                )
                            issues.append(semantic_issue)

            except Exception as e:
                logger.error(
                    f"[Semantic Audit] LLM classification failed: {e} — defaulting to 'none'."
                )
                semantic_category = "none"
                business_logic_score = 5
                semantic_confidence = None
        else:
            logger.info("[Semantic Audit] Skipped — compile failed.")

        # ── 5. Aggregate, Score, Return ───────────────────────────────────
        auth_caps = sem_caps.authorization
        if auth_caps.get("has_multisig_auth"):
            authorization_confidence = 1.0
        elif auth_caps.get("has_signature_auth"):
            authorization_confidence = 0.85
        elif compile_success:
            authorization_confidence = 0.35
        else:
            authorization_confidence = None

        report = calculate_audit_report(
            issues=issues,
            compile_success=compile_success,
            dsl_passed=dsl_passed,
            structural_score=structural_score,
            semantic_category=semantic_category,
            business_logic_score=business_logic_score,
            semantic_confidence=semantic_confidence,
            original_code=code,
            compile_toolchain_error=compile_toolchain_error,
            authorization_confidence=authorization_confidence,
        )

        return report


def get_audit_agent() -> AuditAgent:
    return AuditAgent()
