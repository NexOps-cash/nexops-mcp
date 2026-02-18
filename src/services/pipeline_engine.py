import logging
from typing import Dict, Any, List, Optional

from src.models import (
    ContractIR,
    TollGateResult,
    IntentModel,
    ViolationDetail,
)
from src.services.pipeline import Phase1, Phase2, Phase3
from src.services.language_guard import get_language_guard
from src.services.compiler import get_compiler_service
from src.services.sanity_checker import get_sanity_checker

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
        for gen_attempt in range(max_gen_retries):
            logger.info(f"--- Generation Attempt {gen_attempt + 1} ---")
            
            # Step 2A: Draft
            # Pass violations from previous Phase 3 failure for targeted retry feedback
            code = await Phase2.run(ir, violations=previous_violations, retry_count=gen_attempt)
            
            # Step 2B: Language Guard (Fast Static Filter)
            guard_failure = self.language_guard.validate(code)
            if guard_failure:
                logger.warning(f"Language Guard failed: {guard_failure}. Regenerating...")
                # Clear previous violations since this is a language-level failure
                previous_violations = None
                continue # Retry generation

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
                
                # Feedback loop to LLM for syntax fix
                code = await self._request_syntax_fix(code, last_error, ir)

            if not compile_success:
                logger.error(f"Compile loop exhausted after {max_fix_retries} attempts. Retrying full generation...")
                # Clear previous violations since syntax errors need full regeneration
                previous_violations = None
                continue # Full Generation Retry

            # PHASE 3: Toll Gate (Security Invariants)
            toll_gate = Phase3.validate(code)
            if not toll_gate.passed:
                logger.warning(f"Toll Gate failed with {len(toll_gate.violations)} violations. Retrying with violation feedback...")
                # Store violations for next retry - Phase2 will use them for targeted fixes
                previous_violations = toll_gate.violations
                ir.metadata.retry_count = gen_attempt + 1
                continue # Full Generation Retry with violation context

            # PHASE 4: Intent Sanity Check
            sanity_result = self.sanity_checker.validate(code, intent_model)
            if not sanity_result["success"]:
                logger.warning(f"Sanity Check failed: {sanity_result['violations']}. Retrying full generation...")
                # Clear previous violations since sanity check failures need full regeneration
                previous_violations = None
                continue # Full Generation Retry

            # SUCCESS !
            return {
                "type": "success",
                "data": {
                    "contract_name": ir.contract_name or "GeneratedContract",
                    "code": code,
                    "intent_model": intent_model.dict(),
                    "toll_gate": toll_gate.dict(),
                    "sanity_check": sanity_result,
                    "session_id": "guarded-session" # Placeholder
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

        system = (
            "You are a CashScript syntax fixer. "
            "Fix ONLY the compiler error shown. "
            "Do NOT change logic, intent, or structure. "
            "Return ONLY the complete fixed .cash code. No markdown. No explanation."
        )
        user = f"COMPILER ERROR:\n{error}\n\nCODE:\n{code}\n\nFixed code:"

        llm = LLMFactory.get_provider("fix")
        raw_response = await llm.complete(user, system=system)

        from src.services.pipeline import _extract_cash_code
        return _extract_cash_code(raw_response)

def get_guarded_pipeline_engine() -> GuardedPipelineEngine:
    return GuardedPipelineEngine()
