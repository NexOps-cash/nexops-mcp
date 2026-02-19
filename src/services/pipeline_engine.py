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

    async def generate_guarded(self, intent: str, security_level: str = "high") -> Dict[str, Any]:
        """
        Execute the full 4-stage guarded pipeline.
        """
        # PHASE 1: Structured Intent Parsing
        ir = await Phase1.run(intent, security_level)
        intent_model = ir.metadata.intent_model
        
        if not intent_model:
            return {"type": "error", "error": {"code": "intent_parse_failed", "message": "Failed to parse intent model."}}

        # PHASE 2: Constrained Generation Loop
        max_gen_retries = 2
        last_error = "None"
        previous_violations: Optional[List[ViolationDetail]] = None
        lint_violation_context: str = ""
        for gen_attempt in range(max_gen_retries):
            logger.info(f"--- Generation Attempt {gen_attempt + 1} ---")
            
            # Step 2A: Draft
            code = await Phase2.run(ir, violations=previous_violations, retry_count=gen_attempt)
            
            # Step 2B: Language Guard (Fast Static Filter)
            guard_failure = self.language_guard.validate(code)
            if guard_failure:
                logger.warning(f"Language Guard failed: {guard_failure}. Regenerating...")
                previous_violations = None
                lint_violation_context = ""
                continue

            # Step 2B.5: DSL Lint Gate — deterministic structural check BEFORE compile
            # If this fails, we retry Phase 2 directly, skipping the compile loop entirely.
            # This prevents the fix loop from corrupting structural invariants.
            max_lint_retries = 2
            for lint_attempt in range(max_lint_retries):
                lint_result = self.dsl_linter.lint(code)
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
                    logger.error("[DSLLint] Lint loop exhausted — proceeding to compile with violations")

            # Step 2C: Compile Gate (Internal Fix Loop)
            max_fix_retries = 3
            compile_success = False
            last_error = ""
            
            for fix_attempt in range(max_fix_retries):
                logger.info(f"Compile Attempt {fix_attempt + 1}...")
                compile_result = self.compiler.compile(code)
                
                if compile_result["success"]:
                    compile_success = True
                    ir.metadata.compile_fix_count = fix_attempt
                    break
                
                last_error = compile_result["error"]
                logger.warning(f"Compile failed: {last_error}. Attempting fix...")
                code = await self._request_syntax_fix(code, last_error, ir)

            if not compile_success:
                logger.error(f"Compile loop exhausted after {max_fix_retries} attempts. Retrying full generation...")
                previous_violations = None
                lint_violation_context = ""
                continue

            # PHASE 3: Toll Gate (Security Invariants)
            toll_gate = Phase3.validate(code)
            if not toll_gate.passed:
                logger.warning(f"Toll Gate failed with {len(toll_gate.violations)} violations. Retrying with violation feedback...")
                previous_violations = toll_gate.violations
                ir.metadata.retry_count = gen_attempt + 1
                continue

            # PHASE 4: Intent Sanity Check
            sanity_result = self.sanity_checker.validate(code, intent_model)
            if not sanity_result["success"]:
                logger.warning(f"Sanity Check failed: {sanity_result['violations']}. Retrying full generation...")
                previous_violations = None
                lint_violation_context = ""
                continue

            # SUCCESS !
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

    async def _request_syntax_fix(self, code: str, error: str, ir: ContractIR) -> str:
        """Helper to fix syntax errors. Tries deterministic fixes first, then LLM."""
        import re as _re

        # ── Optimization 5: Deterministic fix for 'Unused variable X' ──────────
        # This avoids 2-3 wasted LLM calls per failure. Regex strips the declaration.
        unused_match = _re.search(r"Unused variable (\w+)", error)
        if unused_match:
            var_name = unused_match.group(1)
            # Remove the line declaring this variable (e.g. "int foo = ...")
            fixed = _re.sub(
                rf"^\s*\w[\w\[\]]*\s+{_re.escape(var_name)}\s*=.*?;\s*$",
                "",
                code,
                flags=_re.MULTILINE,
            )
            if fixed != code:
                logger.info(f"[Fix] Deterministic: stripped unused variable '{var_name}' (no LLM call)")
                return fixed.strip()

        # ── LLM fallback for non-deterministic errors ────────────────────────────
        from src.services.llm.factory import LLMFactory

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

        user = f"COMPILER ERROR:\n{error}\n\nCODE:\n{code}\n\nFixed code:"

        llm = LLMFactory.get_provider("fix")
        raw_response = await llm.complete(user, system=system, max_tokens=400)

        from src.services.pipeline import _extract_cash_code
        return _extract_cash_code(raw_response)

def get_guarded_pipeline_engine() -> GuardedPipelineEngine:
    return GuardedPipelineEngine()
