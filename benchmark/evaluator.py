import time
import yaml
import asyncio
from pathlib import Path
from typing import List, Dict, Any, Optional
from datetime import datetime

from benchmark.schemas import BenchmarkCase, CaseResult
from benchmark.feature_extractor import FeatureExtractor
from src.services.pipeline_engine import get_guarded_pipeline_engine

class BenchmarkEvaluator:
    def __init__(self, weights_path: str = "benchmark/config/scoring_weights.yaml"):
        self.weights_path = Path(weights_path)
        self.weights = {}
        self.extractor = FeatureExtractor()
        self.engine = get_guarded_pipeline_engine()
        self.load_weights()

    def load_weights(self):
        if not self.weights_path.exists():
            print(f"Warning: Scoring weights not found at {self.weights_path}")
            return
        with open(self.weights_path, "r", encoding="utf-8") as f:
            self.weights = yaml.safe_load(f)

    async def evaluate(self, case: BenchmarkCase, model_override: str = None) -> CaseResult:
        start_time = time.time()
        
        # Determine failure layer and state
        failure_layer = None
        converged = False
        fallback_used = False
        compile_pass = False
        lint_errors = 0
        lint_warnings = 0
        code = None
        
        # Metrics placeholders
        tokens_prompt = 0
        tokens_completion = 0
        
        try:
            # We call the production engine with benchmark safety flags
            # Note: generate_guarded handles inner retry loops
            result = await asyncio.wait_for(
                self.engine.generate_guarded(
                    case.intent, 
                    security_level="high",
                    disable_golden=True,
                    disable_fallbacks=True
                ),
                timeout=240 # 4 minute timeout per case
            )
            
            latency = time.time() - start_time
            
            if result.get("type") == "success":
                data = result["data"]
                code = data["code"]
                compile_pass = True
                fallback_used = bool(data.get("fallback_used", False))
                
                # Metadata from engine
                attempt_number = data.get("attempt_number", 1)
                gen_seconds = data.get("generation_seconds", time.time() - start_time)
                
                # 1. Extraction (Structured)
                extracted = self.extractor.extract(code)
                detected = extracted["features"]
                functions = extracted["functions"]
                
                # 2. Capability Saturation (Semantic Mapping)
                # Map abstract required features to sets of satisfyable concrete detections
                has_time_check = (
                    "timelock_unlock" in detected
                    or "timelock_refund" in detected
                    or ("this.age" in code)
                )
                capabilities = {
                    "signature_verification": any("_signature" in f or f == "multisig" for f in detected),
                    "covenant_continuation": any(f.get("has_anchor") and f.get("has_value_check") for f in functions if f["role"] == "INTERMEDIATE"),
                    "time_validation": has_time_check,
                    "timelock_unlock": has_time_check,
                    "multiple_paths": len(functions) >= 2,
                    "token_validation": (
                        ("token_amount" in detected)
                        or ("token_nft" in detected)
                        or ("tokenCategory" in code and "tokenAmount" in code)
                    ),
                    "output_destination_validation": "locking_bytecode" in detected,
                    "output_value_validation": ("output_value_validation" in detected) or ("value_check" in detected),
                }
                
                def requirement_satisfied(req: str) -> bool:
                    # Direct capability or feature hit first.
                    if capabilities.get(req) or req in detected:
                        return True

                    # Alias mappings used in benchmark suites.
                    alias_checks = {
                        "valid_signature_check": capabilities.get("signature_verification", False),
                        "covenant_self_reference": capabilities.get("covenant_continuation", False),
                        "locktime_check": capabilities.get("time_validation", False),
                        "output_amount_check": capabilities.get("output_value_validation", False),
                        "amount_threshold_logic": ("<=" in code or ">=" in code),
                        "tiered_delay_logic": ("smallDelay" in code or "largeDelay" in code or "threshold" in code.lower()),
                        "emergency_path": any(f.get("role") == "RECOVERY" for f in functions),
                        "cancellation_path": ("cancel" in code.lower()),
                        "two_of_three_logic": ("multisig_2of3" in detected or "checkMultiSig" in code),
                    }
                    return bool(alias_checks.get(req, False))

                # 3. Intent Coverage Calculation (Proportional)
                matched_required = []
                missing_required = []
                for req in (case.required_features or []):
                    if requirement_satisfied(req):
                        matched_required.append(req)
                    else:
                        missing_required.append(req)
                
                # Proportional score instead of binary
                if case.required_features:
                    intent_coverage = len(matched_required) / len(case.required_features)
                else:
                    intent_coverage = 1.0
                
                # 4. Vault-Specific Semantic Guard (Production-Grade)
                semantic_pass = True
                
                # RULE: INTERMEDIATE functions MUST re-anchor (Covenant Continuation)
                intermediate_funcs = [f for f in functions if f["role"] == "INTERMEDIATE"]
                if intermediate_funcs and not any(f["has_anchor"] for f in intermediate_funcs):
                    semantic_pass = False # Vault cannot continue to next stage
                
                # RULE: TERMINAL functions MUST NOT re-anchor (Cleanup)
                terminal_funcs = [f for f in functions if f["role"] == "TERMINAL"]
                if any(f["has_anchor"] for f in terminal_funcs):
                    semantic_pass = False # Vault leaked funds back into covenant?
                
                # 5. Final Scoring
                structure_score = data.get("toll_gate", {}).get("structural_score", 0.0)
                adj_structure_score = structure_score # Legacy name, simplified
                
                critical_missing = [f for f in case.critical_features if not requirement_satisfied(f)]
                
                lint_factor = self.weights.get("factors", {}).get("lint_no_error", 1.0)
                final_score = (1.0 if compile_pass else 0.0) * lint_factor * intent_coverage * (1.0 if semantic_pass else 0.5)
                
                if critical_missing:
                    # Critical features remain high-stakes
                    final_score *= 0.2
                
                # Convergence should represent usable production quality, not only "compiled".
                # For failure/vulnerability benchmark cases, force non-converged unless
                # the "must_fail_*" critical expectation is actually detected.
                has_failure_tag = any(t in {"failure", "vulnerability"} for t in (case.tags or []))
                has_must_fail_critical = any(str(c).startswith("must_fail_") for c in (case.critical_features or []))
                converged = (
                    (not fallback_used)
                    and compile_pass
                    and semantic_pass
                    and intent_coverage >= 0.70
                    and len(critical_missing) == 0
                    and not (has_failure_tag and has_must_fail_critical)
                )

                return CaseResult(
                    id=case.id,
                    pattern=case.pattern,
                    difficulty=case.difficulty,
                    compile_pass=compile_pass,
                    lint_errors=0,
                    lint_warnings=0,
                    lint_factor=lint_factor,
                    structure_score=structure_score,
                    adj_structure_score=adj_structure_score,
                    required_features=case.required_features,
                    detected_features=detected,
                    missing_features=missing_required,
                    extraneous_features=[], # Removed penalty
                    hallucinated_features=[],
                    intent_coverage=intent_coverage,
                    final_score=final_score,
                    latency_seconds=gen_seconds,
                    retries_used=attempt_number,
                    first_pass_attempt=attempt_number if compile_pass else None,
                    max_retries=case.max_retries,
                    converged=converged,
                    fallback_used=fallback_used,
                    failure_layer=None,
                    elapsed_seconds=time.time() - start_time,
                    code=code
                )
            else:
                # Failure Case
                latency = time.time() - start_time
                error = result.get("error", {})
                code_err = error.get("code", "")
                
                if "intent_parse_failed" in code_err:
                    failure_layer = "Phase1"
                elif "lint" in str(error).lower():
                    failure_layer = "DSLLint"
                else:
                    failure_layer = "Compile"
                
                return self._failed_result(case, latency, failure_layer)

        except (asyncio.TimeoutError, asyncio.CancelledError):
            latency = time.time() - start_time
            return self._failed_result(case, latency, "Timeout")
        except Exception as e:
            latency = time.time() - start_time
            return self._failed_result(case, latency, f"Error: {str(e)[:50]}")

    def _failed_result(self, case: BenchmarkCase, latency: float, failure_layer: str) -> CaseResult:
        return CaseResult(
            id=case.id,
            pattern=case.pattern,
            difficulty=case.difficulty,
            compile_pass=False,
            lint_errors=0, # Unknown
            lint_warnings=0,
            lint_factor=0.5,
            structure_score=0.0,
            adj_structure_score=0.0,
            required_features=case.required_features,
            detected_features=[],
            missing_features=case.required_features,
            extraneous_features=[],
            hallucinated_features=[],
            intent_coverage=0.0,
            final_score=0.0,
            latency_seconds=latency,
            retries_used=case.max_retries,
            max_retries=case.max_retries,
            converged=False,
            fallback_used=False,
            failure_layer=failure_layer,
            elapsed_seconds=latency
        )
