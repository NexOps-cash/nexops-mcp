import logging
from typing import Dict, Any, List, Optional

from src.models import (
    ContractIR,
    TollGateResult,
    IntentModel,
    ViolationDetail,
)
from src.services.pipeline import Phase1, Phase2, Phase3
from src.services.pipeline import build_unified_dsl_rules
from src.services.language_guard import get_language_guard
from src.services.compiler import get_compiler_service
from src.services.sanity_checker import get_sanity_checker
from src.services.dsl_lint import get_dsl_linter

logger = logging.getLogger("nexops.pipeline_engine")

class GuardedPipelineEngine:
    """
    NexOps — Guarded Synthesis Engine
    Orchestrates the 4-stage multi-layer guarded loop.
    """

    def __init__(self):
        self.language_guard = get_language_guard()
        self.compiler = get_compiler_service()
        self.sanity_checker = get_sanity_checker()
        self.dsl_linter = get_dsl_linter()

    async def generate_guarded(
        self, 
        intent: str, 
        security_level: str = "high",
        on_update: Optional[Any] = None
    ) -> Dict[str, Any]:
        """
        Execute the full 4-stage guarded pipeline.
        """
        async def _notify(stage: str, message: str, attempt: int = 1, status: str = "processing"):
            if on_update:
                await on_update({
                    "type": "update",
                    "stage": stage,
                    "status": status,
                    "message": message,
                    "attempt": attempt
                })

        # PHASE 1: Structured Intent Parsing
        await _notify("phase1_parsing", "Analyzing user intent and extracting contract features...")
        ir = await Phase1.run(intent, security_level)
        intent_model = ir.metadata.intent_model
        
        if not intent_model:
            return {"type": "error", "error": {"code": "intent_parse_failed", "message": "Failed to parse intent model."}}

        await _notify("phase1_complete", f"Intent parsed: {intent_model.contract_type} with features {intent_model.features}")

        # PHASE 2: Constrained Generation Loop
        max_gen_retries = 2
        last_error = "None"
        previous_violations: Optional[List[ViolationDetail]] = None
        lint_violation_context: str = ""
        
        for gen_attempt in range(max_gen_retries):
            # Step 2A: Draft
            await _notify("phase2_drafting", "Generating code draft...", gen_attempt + 1)
            code = await Phase2.run(ir, violations=previous_violations, retry_count=gen_attempt)

            contract_mode = (
                getattr(ir.metadata, "effective_mode", None)
                or (intent_model.contract_type or "")
            ).lower()
            
            logger.info(f"--- Generation Attempt {gen_attempt + 1} (mode={contract_mode}) ---")
            
            # Step 2B: Language Guard (Fast Static Filter)
            guard_failure = self.language_guard.validate(code)
            if guard_failure:
                logger.warning(f"Language Guard failed: {guard_failure}. Regenerating...")
                await _notify("phase2_guard_fail", f"Draft failed basic language safety: {guard_failure}", gen_attempt + 1, "warning")
                previous_violations = None
                lint_violation_context = ""
                continue

            # Step 2B.5: DSL Lint Gate — deterministic structural check BEFORE compile
            # contract_mode drives conditional rules (e.g. LNC-008 skips for multisig)
            max_lint_retries = 3
            for lint_attempt in range(max_lint_retries):
                await _notify("phase2_linting", f"Running DSL linter (attempt {lint_attempt + 1})...", gen_attempt + 1)
                lint_result = self.dsl_linter.lint(code, contract_mode=contract_mode)
                if lint_result["passed"]:
                    lint_violation_context = ""
                    break
                # Summarize violations for targeted Phase 2 retry
                lint_summary = self.dsl_linter.format_for_prompt(lint_result["violations"])
                logger.warning(
                    f"[DSLLint] {len(lint_result['violations'])} violations on attempt {lint_attempt+1}. "
                    f"Injecting into Phase2 retry..."
                )
                if lint_attempt < max_lint_retries - 1:
                    await _notify("phase2_lint_fail", f"DSL Lint failed {len(lint_result['violations'])} rules. Attempting self-correction...", gen_attempt + 1, "warning")
                    # Inject lint violations as violation_context for next Phase2 call
                    from src.models import ViolationDetail
                    lint_violations = [
                        ViolationDetail(
                            rule=v["rule_id"],
                            reason=v["message"],
                            exploit="",
                            fix_hint=f"Line {v['line_hint']}",
                        )
                        for v in lint_result["violations"]
                    ]
                    code = await Phase2.run(ir, violations=lint_violations, retry_count=gen_attempt)
                else:
                    logger.error("[DSLLint] Lint loop exhausted — forcing full regeneration.")
                    await _notify("phase2_lint_exhausted", "DSL Linting failed to converge. Forcing full regeneration...", gen_attempt + 1, "error")
                    previous_violations = None
                    lint_violation_context = ""
                    break  # Exit lint loop and trigger full generation retry

            # If lint failed after retries, restart generation attempt
            if lint_result and not lint_result["passed"]:
                continue

            # Step 2C: Compile Gate (Internal Fix Loop)
            max_fix_retries = 3
            compile_success = False
            last_error = ""
            
            for fix_attempt in range(max_fix_retries):
                await _notify("phase2_compiling", f"Compiling CashScript (fix attempt {fix_attempt + 1})...", gen_attempt + 1)
                compile_result = self.compiler.compile(code)
                
                if compile_result["success"]:
                    compile_success = True
                    ir.metadata.compile_fix_count = fix_attempt
                    break
                
                error_obj = compile_result.get("error") or {}
                raw_error = error_obj.get("raw", "") if isinstance(error_obj, dict) else str(error_obj)

                last_error = raw_error

                logger.warning(f"Compile failed [{error_obj.get('type', 'UnknownError')}]: {raw_error[:120]}. Attempting fix...")
                await _notify("phase2_compile_fix", f"Syntax error: {raw_error[:60]}... Attempting repair.", gen_attempt + 1, "warning")

                code = await self._request_syntax_fix(
                    code=code,
                    error_obj=error_obj,
                    ir=ir
                )

            if not compile_success:
                logger.error(f"Compile loop exhausted after {max_fix_retries} attempts. Retrying full generation...")
                await _notify("phase2_compile_error", "Failed to resolve syntax errors. Retrying full synthesis...", gen_attempt + 1, "error")
                previous_violations = None
                lint_violation_context = ""
                continue

            # PHASE 3: Toll Gate (Security Invariants)
            await _notify("phase3_validation", "Running Phase 3 Security Guard (Toll Gate)...", gen_attempt + 1)
            toll_gate = Phase3.validate(code)
            if not toll_gate.passed:
                logger.warning(f"Toll Gate failed with {len(toll_gate.violations)} violations. Retrying with violation feedback...")
                await _notify("phase3_fail", f"Security violations found: {len(toll_gate.violations)}. Retrying generation with feedback...", gen_attempt + 1, "warning")
                previous_violations = toll_gate.violations
                ir.metadata.retry_count = gen_attempt + 1
                continue

            # PHASE 4: Intent Sanity Check
            await _notify("phase4_sanity", "Verifying contract against original intent...", gen_attempt + 1)
            sanity_result = self.sanity_checker.validate(code, intent_model)
            if not sanity_result["success"]:
                logger.warning(f"Sanity Check failed: {sanity_result['violations']}. Retrying full generation...")
                await _notify("phase4_fail", "Contract logic does not match intent. Regenerating...", gen_attempt + 1, "warning")
                previous_violations = None
                lint_violation_context = ""
                continue

            # SUCCESS !
            await _notify("complete", "Synthesis complete. Verified and secured.", gen_attempt + 1, "success")
            return {
                "type": "success",
                "data": {
                    "contract_name": ir.contract_name or "GeneratedContract",
                    "code": code,
                    "intent_model": intent_model.dict(),
                    "toll_gate": toll_gate.dict(),
                    "sanity_check": sanity_result,
                    "session_id": "guarded-session"
                }
            }

        # FALLBACK: If all retries fail, return a fallback error or template
        return {
            "type": "error", 
            "error": {
                "code": "generation_exhausted", 
                "message": "Guarded pipeline failed to converge after multiple attempts.",
                "last_compiler_error": last_error
            }
        }

    async def _request_syntax_fix(
        self,
        code: str,
        error_obj: Dict[str, Any],
        ir: ContractIR
    ) -> str:
        """Helper to fix syntax errors. Tries deterministic fixes first, then LLM."""
        import re as _re

        # Extract fields from structured error dict
        error_type  = error_obj.get("type", "UnknownError")
        error_raw   = error_obj.get("raw", "")
        error_token = error_obj.get("token", "")
        error_hint  = error_obj.get("hint", "")

        # ── Deterministic: UnusedVariableError ───────────────────────────────────
        if error_type == "UnusedVariableError" and error_token:
            var_name = error_token
            fixed = _re.sub(
                rf"^\s*\w[\w\[\]]*\s+{_re.escape(var_name)}\s*=.*?;\s*$",
                "",
                code,
                flags=_re.MULTILINE,
            )
            if fixed != code:
                logger.info(f"[Fix] Deterministic: stripped unused variable '{var_name}' (no LLM call)")
                return fixed.strip()

        # ── Deterministic: ExtraneousInputError — missing closing brace ──────────
        if error_type == "ExtraneousInputError" and error_token == "<EOF>":
            if code.count("{") > code.count("}"):
                logger.info("[Fix] Deterministic: adding missing closing brace")
                return (code + "\n}").strip()

        # ── Deterministic: Extraneous tx.time / tx.age (malformed timelock) ──────
        if error_type == "ExtraneousInputError" and error_token in ("tx.time", "tx.age"):
            fixed = _re.sub(
                r"require\s*\(\s*(.*?)tx\.(time|age)\s*>=\s*(.*?)&&.*?\);",
                r"require(tx.\2 >= \3);",
                code,
            )
            if fixed != code:
                logger.info("[Fix] Deterministic: normalized malformed timelock usage")
                return fixed.strip()

        # ── Deterministic: TypeMismatchError — bytes → bytes32 ───────────────────
        if error_type == "TypeMismatchError" and "bytes32" in error_raw:
            fixed = _re.sub(r"\bbytes\s+(\w+)", r"bytes32 \1", code)
            if fixed != code:
                logger.info("[Fix] Deterministic: upgraded bytes → bytes32")
                return fixed.strip()

        # ── Deterministic: ParseError — stray ternary '?' ────────────────────────
        if error_type == "ParseError" and error_token == "?":
            fixed = code.replace("?", "")
            logger.info("[Fix] Deterministic: stripped unsupported ternary '?' token")
            return fixed.strip()

        # ── LLM fallback for non-deterministic errors ────────────────────────────
        from src.services.llm.factory import LLMFactory
        import json

        unified_rules = build_unified_dsl_rules()
        system = f"""You are performing CashScript syntax repair ONLY.

You MUST preserve ALL structural invariants below.
You MUST NOT weaken value anchoring.
You MUST NOT introduce hardcoded indices.
You MUST NOT remove output length guards.
You MUST NOT change business logic, thresholds, or signatures.
Fix ONLY token-level grammar errors shown in the compiler error.

{unified_rules}

Return ONLY the complete fixed .cash source. No markdown. No explanation."""

        error_payload = json.dumps(error_obj, indent=2)
        user = f"""STRUCTURED COMPILER ERROR (JSON):
{error_payload}

CODE:
{code}

Fix ONLY the error described above.
Return ONLY the complete fixed .cash source."""

        llm = LLMFactory.get_provider("fix")
        raw_response = await llm.complete(user, system=system, max_tokens=400)

        from src.services.pipeline import _extract_cash_code
        return _extract_cash_code(raw_response)

def get_guarded_pipeline_engine() -> GuardedPipelineEngine:
    return GuardedPipelineEngine()
