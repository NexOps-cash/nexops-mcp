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
from src.services.structural_integrity import (
    apply_deterministic_micro_fixes,
    diagnose_structure,
    is_structurally_valid,
    save_repair_cycle,
)
from pathlib import Path
from datetime import datetime

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

    @staticmethod
    def _reset_generation_context() -> tuple:
        """Clear retry state when forcing full regeneration."""
        return None, ""

    async def generate_guarded(
        self, 
        intent: str, 
        security_level: str = "high",
        on_update: Optional[Any] = None,
        api_key: Optional[str] = None,
        provider: Optional[str] = None,
        openrouter_key: Optional[str] = None,
        disable_golden: bool = False,
        disable_fallbacks: bool = False,
        resolution_mode: str = "non_interactive",
        existing_spec: Optional[Any] = None,
        skip_composition_check: bool = False,
        allow_experimental: bool = False,
        force_generate: bool = False,
    ) -> Dict[str, Any]:
        """
        Execute the full 4-stage guarded pipeline.
        """
        start_time_full = datetime.now()
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
        ir = await Phase1.run(
            intent, 
            security_level, 
            api_key=api_key, 
            provider=provider,
            openrouter_key=openrouter_key,
            disable_golden=disable_golden,
            disable_fallbacks=disable_fallbacks,
            resolution_mode=resolution_mode,
            existing_spec=existing_spec,
        )
        ir.metadata.disable_golden = disable_golden
        ir.metadata.disable_fallbacks = disable_fallbacks
        intent_model = ir.metadata.intent_model
        contract_mode = intent_model.contract_type if intent_model else ""
        
        if not intent_model:
            return {"type": "error", "error": {"code": "intent_parse_failed", "message": "Failed to parse intent model."}}

        if intent_model.contract_type == "semantic_unsupported":
            return {
                "type": "error",
                "error": {
                    "code": "semantic_unsupported",
                    "message": (
                        "Prompt mixes CashToken class with pure BCH escrow — "
                        "add explicit NFT/token custody or remove token_class."
                    ),
                },
            }

        if ir.metadata.clarification_plan and resolution_mode == "interactive":
            return {
                "type": "needs_input",
                "data": {
                    "specification": ir.metadata.specification.model_dump() if ir.metadata.specification else {},
                    "clarification_plan": ir.metadata.clarification_plan.model_dump(),
                    "planning_report": ir.metadata.planning_report.model_dump() if ir.metadata.planning_report else {},
                },
            }

        if resolution_mode == "interactive" and ir.metadata.specification:
            from src.models import SpecStatus
            from src.services.spec.review import render_specification

            status = ir.metadata.specification.status
            status_val = status.value if isinstance(status, SpecStatus) else str(status)
            if status_val != SpecStatus.CONFIRMED.value:
                if status_val == SpecStatus.IN_REVIEW.value:
                    review = render_specification(
                        ir.metadata.specification,
                        ir.metadata.utxo_architecture,
                    )
                    from src.services.spec.support_assessment import assess_composition_support

                    support = assess_composition_support(
                        ir.metadata.specification,
                        ir.metadata.planning_report,
                    )
                    return {
                        "type": "review",
                        "data": {
                            "specification": ir.metadata.specification.model_dump(),
                            "review": review.model_dump(),
                            "composition_support": support.model_dump(),
                            "planning_report": ir.metadata.planning_report.model_dump(),
                        },
                    }
                return {
                    "type": "needs_input",
                    "data": {
                        "specification": ir.metadata.specification.model_dump(),
                        "message": "Specification must be confirmed before generation.",
                    },
                }

        await _notify("phase1_complete", f"Intent parsed: {intent_model.contract_type} with features {intent_model.features}")

        composition_support = None
        if (
            not skip_composition_check
            and ir.metadata.specification
            and ir.metadata.planning_report
        ):
            from src.services.spec.support_assessment import assess_composition_support

            composition_support = assess_composition_support(
                ir.metadata.specification,
                ir.metadata.planning_report,
            )
            if composition_support.status == "unsupported" and not force_generate:
                return {
                    "type": "unsupported_composition",
                    "data": {
                        "composition_support": composition_support.model_dump(),
                        "specification": ir.metadata.specification.model_dump(),
                        "planning_report": ir.metadata.planning_report.model_dump(),
                        "intent_model": intent_model.model_dump() if intent_model else {},
                    },
                }
            if composition_support.status == "experimental" and not allow_experimental and not force_generate:
                return {
                    "type": "experimental_composition",
                    "data": {
                        "composition_support": composition_support.model_dump(),
                        "specification": ir.metadata.specification.model_dump(),
                        "planning_report": ir.metadata.planning_report.model_dump(),
                        "intent_model": intent_model.model_dump() if intent_model else {},
                        "message": (
                            "This composition is experimental. "
                            "Set context.allow_experimental=true to generate anyway."
                        ),
                    },
                }

        # PHASE 2: Constrained Generation Loop
        max_gen_retries = 3 if disable_fallbacks else 2
        last_error = "None"
        previous_violations: Optional[List[ViolationDetail]] = None
        lint_violation_context: str = ""
        
        for gen_attempt in range(max_gen_retries):
            # Step 2A: Draft
            await _notify("phase2_drafting", "Generating code draft...", gen_attempt + 1)
            code = await Phase2.run(
                ir, 
                violations=previous_violations, 
                retry_count=gen_attempt, 
                api_key=api_key, 
                provider=provider,
                openrouter_key=openrouter_key
            )

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
            max_lint_retries = 4
            prev_blocking_sig: tuple = ()
            stuck_lint_repeats = 0
            lint_proceed_to_compile = False
            lint_result = {"passed": True, "violations": []}
            for lint_attempt in range(max_lint_retries):
                await _notify("phase2_linting", f"Running DSL linter (attempt {lint_attempt + 1})...", gen_attempt + 1)
                semantic_ctx = None
                if intent_model:
                    semantic_ctx = {
                        "ownership_mode": intent_model.ownership_mode,
                        "lifecycle_mode": intent_model.lifecycle_mode,
                        "supply_mode": intent_model.supply_mode,
                        "commitment_schema": intent_model.commitment_schema,
                    }
                lint_result = self.dsl_linter.lint(
                    code, contract_mode=contract_mode, semantic=semantic_ctx
                )
                if lint_result["passed"]:
                    lint_violation_context = ""
                    break
                blocking = [
                    v for v in lint_result["violations"]
                    if v.get("severity") != "warning"
                ]
                blocking_sig = tuple(
                    sorted((v.get("rule_id", ""), v.get("line_hint", 0)) for v in blocking)
                )
                if blocking_sig and blocking_sig == prev_blocking_sig:
                    stuck_lint_repeats += 1
                else:
                    stuck_lint_repeats = 0
                prev_blocking_sig = blocking_sig

                lint_summary = self.dsl_linter.format_for_prompt(lint_result["violations"])
                logger.warning(
                    f"[DSLLint] {len(lint_result['violations'])} violations on attempt {lint_attempt+1}. "
                    f"Injecting into Phase2 retry..."
                )
                if stuck_lint_repeats >= 2:
                    if not is_structurally_valid(code):
                        logger.warning(
                            "[DSLLint] Stuck lint + structurally invalid code — hard regen"
                        )
                        previous_violations, lint_violation_context = (
                            self._reset_generation_context()
                        )
                        lint_proceed_to_compile = False
                        break
                    logger.warning(
                        "[DSLLint] Same violations repeated — breaking lint loop to compile gate"
                    )
                    lint_violation_context = lint_summary
                    lint_proceed_to_compile = True
                    break
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
                    code = await Phase2.run(
                        ir, 
                        violations=lint_violations, 
                        retry_count=gen_attempt, 
                        api_key=api_key, 
                        provider=provider,
                        openrouter_key=openrouter_key
                    )
                else:
                    logger.error("[DSLLint] Lint loop exhausted — forcing full regeneration.")
                    await _notify("phase2_lint_exhausted", "DSL Linting failed to converge. Forcing full regeneration...", gen_attempt + 1, "error")
                    previous_violations, lint_violation_context = (
                        self._reset_generation_context()
                    )
                    break  # Exit lint loop and trigger full generation retry

            # If lint failed after retries, restart generation attempt
            if lint_result and not lint_result["passed"] and not lint_proceed_to_compile:
                continue

            if lint_proceed_to_compile and not is_structurally_valid(code):
                logger.warning(
                    "[DSLLint] Proceed-to-compile blocked: structurally invalid code"
                )
                previous_violations, lint_violation_context = (
                    self._reset_generation_context()
                )
                continue

            if not is_structurally_valid(code):
                logger.warning(
                    "[StructuralIntegrity] Post-lint code invalid — skipping compile, regen"
                )
                previous_violations, lint_violation_context = (
                    self._reset_generation_context()
                )
                continue

            # Step 2C: Compile Gate (Internal Fix Loop)
            max_fix_retries = 3
            compile_success = False
            last_error = ""
            
            case_label = (
                (intent_model.contract_type or "unknown")
                if intent_model
                else "unknown"
            )
            compile_aborted_structural = False

            for fix_attempt in range(max_fix_retries):
                if not is_structurally_valid(code):
                    logger.warning(
                        "[StructuralIntegrity] Pre-compile structure invalid — abort fix loop"
                    )
                    compile_aborted_structural = True
                    break

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

                pre_code = code
                diag_pre = diagnose_structure(pre_code)
                code, aborted = await self._request_syntax_fix(
                    code=code,
                    error_obj=error_obj,
                    ir=ir,
                    api_key=api_key,
                    provider=provider,
                    openrouter_key=openrouter_key,
                    gen_attempt=gen_attempt,
                    fix_attempt=fix_attempt,
                    case_label=case_label,
                )
                if aborted:
                    compile_aborted_structural = True
                    break

            if compile_aborted_structural or (
                not compile_success and not is_structurally_valid(code)
            ):
                logger.error(
                    "Compile repair aborted due to structural corruption — full regeneration"
                )
                previous_violations, lint_violation_context = (
                    self._reset_generation_context()
                )
                continue

            if not compile_success:
                logger.error(f"Compile loop exhausted after {max_fix_retries} attempts. Retrying full generation...")
                await _notify("phase2_compile_error", "Failed to resolve syntax errors. Retrying full synthesis...", gen_attempt + 1, "error")
                previous_violations = None
                lint_violation_context = ""
                continue

            # PHASE 3: Toll Gate (Security Invariants)
            await _notify("phase3_validation", "Running Phase 3 Security Guard (Toll Gate)...", gen_attempt + 1)
            toll_gate = Phase3.validate(code, contract_mode=contract_mode)
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
                # If security level is HIGH, we never compromise on intent
                if security_level == "high":
                    logger.warning(f"Sanity Check failed (STRICT): {sanity_result['violations']}. Retrying full generation...")
                    await _notify("phase4_fail", "Contract logic does not match intent. Regenerating...", gen_attempt + 1, "warning")
                    previous_violations = None
                    lint_violation_context = ""
                    continue
                else:
                    # REAL AIM of relaxation: proceed but track warnings
                    logger.info(f"Sanity Check missed features (RELAXED): {sanity_result['violations']}. Proceeding with intent warnings.")
                    await _notify("phase4_warning", f"Warning: {len(sanity_result['violations'])} features missing, but proceeding as requested.", gen_attempt + 1, "warning")
                    # We continue to SUCCESS below, bypasses the "continue" loop
            
            # SUCCESS !
            generation_seconds = (datetime.now() - start_time_full).total_seconds()
            await _notify("complete", "Synthesis complete. Verified and secured.", gen_attempt + 1, "success")
            return {
                "type": "success",
                "data": {
                    "contract_name": ir.contract_name or "GeneratedContract",
                    "code": code,
                    "intent_model": intent_model.dict(),
                    "toll_gate": toll_gate.dict(),
                    "sanity_check": sanity_result,
                    "session_id": "guarded-session",
                    "fallback_used": False,
                    "attempt_number": gen_attempt + 1,
                    "compile_fix_count": getattr(ir.metadata, "compile_fix_count", 0),
                    "generation_seconds": generation_seconds,
                    "is_perfect_match": sanity_result["success"]
                }
            }

        # Synthesis failed to converge -- Reverting to pre-verified secure fallback
        if ir.metadata.disable_fallbacks:
            logger.warning(f"Pipeline exhausted after {max_gen_retries} attempts. Fallbacks DISABLED for benchmark.")
            await _notify("fallback_disabled", "Synthesis failed and fallbacks are disabled. Returning last generated code.", max_gen_retries, "error")
            return {
                "type": "error",
                "error": {
                    "code": "synthesis_failed_no_fallback",
                    "message": "Pipeline failed to converge and fallbacks are disabled.",
                    "last_code": code
                }
            }
        
        logger.warning(f"Pipeline exhausted after {max_gen_retries} attempts. Activating secure fallback. (Last Error: {last_error})")
        await _notify("fallback", "Synthesis failed to converge. Deploying pre-verified secure fallback...", max_gen_retries, "warning")
        
        fallback_code = self._get_fallback_contract(intent_model) or ""
        # Still run Phase 3 on the fallback for report consistency
        fallback_toll_gate = Phase3.validate(fallback_code, contract_mode=contract_mode)
        
        return {
            "type": "success",
            "data": {
                "contract_name": f"fallback_{ir.contract_name or 'unnamed'}",
                "code": fallback_code,
                "intent_model": intent_model.dict(),
                "toll_gate": fallback_toll_gate.dict(),
                "sanity_check": {"success": True, "violations": ["FALLBACK_PROTECTOR_ENGAGED"]},
                "session_id": "guarded-session-fallback",
                "fallback_used": True
            }
        }


    def _get_fallback_contract(self, intent_model: IntentModel) -> str:
        """Map intent to a canonical, pre-verified physical fallback file."""
        tags = intent_model.features
        btype = intent_model.contract_type.lower()
        
        filename = "fallback_default.cash"
        
        if "escrow" in tags or btype == "escrow":
            filename = "fallback_escrow.cash"
        elif "swap" in tags or "htlc" in tags or btype == "swap":
            filename = "fallback_swap.cash"
        elif "split" in tags:
            filename = "fallback_split.cash"
        elif "vesting" in tags or btype == "vesting":
            filename = "fallback_vesting.cash"
        elif "timelock" in tags or btype == "timelock":
            filename = "fallback_timelock.cash"
        elif "tokens" in tags or "nft" in tags or btype == "token":
            filename = "fallback_token.cash"
        elif "vault" in tags or btype == "vault":
            filename = "fallback_vault.cash"
        elif "stateful" in tags or btype == "stateful":
            filename = "fallback_stateful.cash"
        elif "multisig" in tags or btype == "multisig":
            filename = "fallback_multisig.cash"
            
        fallback_path = Path(f"src/services/fallbacks/{filename}")
        
        try:
            with open(fallback_path, "r", encoding="utf-8") as f:
                return f.read()
        except FileNotFoundError:
            logger.error(f"Fallback file missing: {fallback_path}. Returning default.")
            # Absolute worst-case hardcoded fallback if even files are missing
            return "pragma cashscript ^0.13.0;\ncontract DefaultFallback(pubkey owner) {\n    function spend(sig ownerSig) {\n        require(checkSig(ownerSig, owner));\n    }\n}"

    async def _request_syntax_fix(
        self,
        code: str,
        error_obj: Dict[str, Any],
        ir: ContractIR,
        api_key: Optional[str] = None,
        provider: Optional[str] = None,
        openrouter_key: Optional[str] = None,
        gen_attempt: int = 0,
        fix_attempt: int = 0,
        case_label: str = "unknown",
    ) -> tuple[str, bool]:
        """
        Syntax repair: deterministic micro-fixes, then LLM only on structurally valid code.
        Returns (code, aborted_structural). When aborted, caller must force full regen.
        """
        import json

        pre_code = code
        diag_pre = diagnose_structure(pre_code)
        code, repairs = apply_deterministic_micro_fixes(code, error_obj)
        diag_after_micro = diagnose_structure(code)

        if repairs:
            logger.info("[Fix] Deterministic micro-fixes: %s", repairs)

        if not diag_after_micro.valid:
            save_repair_cycle(
                case_label=case_label,
                gen_attempt=gen_attempt,
                fix_attempt=fix_attempt,
                pre_code=pre_code,
                post_code=code,
                diagnostics_pre=diag_pre,
                diagnostics_post=diag_after_micro,
                repairs=repairs,
                error_obj=error_obj,
                aborted_llm=True,
            )
            return pre_code, True

        error_raw = error_obj.get("raw", "")
        # LockingBytecodeP2PKH undefined — often fixed by micro-fix; if compile still fails, try LLM
        if "LockingBytecodeP2PKH" in error_raw and "undefined" in error_raw:
            if diag_after_micro.valid:
                return code, False

        from src.services.llm.factory import LLMFactory
        from src.services.pipeline import build_pattern_rails, build_unified_dsl_rules
        intent_model = ir.metadata.intent_model
        tags = intent_model.features if intent_model else []
        contract_type = intent_model.contract_type if intent_model else ""
        pattern_rails = build_pattern_rails(tags, contract_type=contract_type, intent_model=intent_model)
        unified_rules = build_unified_dsl_rules()

        system = f"""You are performing CashScript syntax repair ONLY.
You MUST preserve ALL structural invariants below.
You MUST NOT weaken value anchoring.
You MUST NOT introduce hardcoded indices.
You MUST NOT remove output length guards.
You MUST NOT change business logic, thresholds, or signatures.
Fix ONLY token-level grammar errors shown in the compiler error.

{unified_rules}

{pattern_rails}

Return ONLY the complete fixed .cash source. No markdown. No explanation."""
        error_payload = json.dumps(error_obj, indent=2)
        user = f"""STRUCTURED COMPILER ERROR (JSON):
{error_payload}
CODE:
{code}
Fix ONLY the error described above.
Return ONLY the complete fixed .cash source."""
        llm = LLMFactory.get_provider(
            "fix", 
            api_key=api_key, 
            provider_type=provider,
            openrouter_key=openrouter_key
        )
        raw_response = await llm.complete(user, system=system)

        from src.services.pipeline import _extract_cash_code
        post_code = _extract_cash_code(raw_response)
        diag_post = diagnose_structure(post_code)
        save_repair_cycle(
            case_label=case_label,
            gen_attempt=gen_attempt,
            fix_attempt=fix_attempt,
            pre_code=pre_code,
            post_code=post_code,
            diagnostics_pre=diag_pre,
            diagnostics_post=diag_post,
            repairs=repairs + ["llm_syntax_fix"],
            error_obj=error_obj,
            aborted_llm=not diag_post.valid,
        )
        if not diag_post.valid:
            logger.warning(
                "[StructuralIntegrity] LLM repair produced invalid structure — rejecting"
            )
            return pre_code, True
        return post_code, False

def get_guarded_pipeline_engine() -> GuardedPipelineEngine:
    return GuardedPipelineEngine()
