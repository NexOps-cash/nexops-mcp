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
        compile_pass = False
        lint_errors = 0
        lint_warnings = 0
        code = None
        
        # Metrics placeholders
        tokens_prompt = 0
        tokens_completion = 0
        
        try:
            # We call the production engine
            # Note: generate_guarded handles inner retry loops
            result = await asyncio.wait_for(
                self.engine.generate_guarded(case.intent, security_level="high"),
                timeout=120 # 2 minute timeout per case
            )
            
            latency = time.time() - start_time
            
            if result["type"] == "success":
                data = result["data"]
                code = data["code"]
                compile_pass = True # If success, it compiled at some point
                converged = not data.get("fallback_used", False)
                
                # Extract lint info if possible (though pipeline doesn't explicitly return counts)
                # We'll rely on the fact that if it passed, errors are 0.
                lint_errors = 0
                lint_warnings = 0 # Placeholder
                
                # Toll Gate structure score
                structure_score = data.get("toll_gate", {}).get("structural_score", 0.0)
                
                # Feature Extraction
                detected = self.extractor.extract(code)
                missing = self.extractor.get_missing(case.required_features, detected)
                hallucinated = self.extractor.get_hallucinated(case.required_features, detected)
                
                # Intent Coverage
                if case.required_features:
                    intent_coverage = len(set(detected) & set(case.required_features)) / len(case.required_features)
                else:
                    intent_coverage = 1.0
                
                # Structural Penalty for Missing Requires
                require_count_min = case.expected_structure.get("require_count_min", 0)
                actual_require_count = code.count("require(")
                adj_structure_score = structure_score
                if require_count_min > 0:
                    penalty_factor = min(1.0, actual_require_count / require_count_min)
                    adj_structure_score *= penalty_factor

                # Critical Feature Guard
                critical_missing = [f for f in case.critical_features if f not in detected]
                
                # Final Scoring
                lint_factor = self.weights.get("factors", {}).get("lint_no_error", 1.0)
                final_score = (1.0 if compile_pass else 0.0) * lint_factor * adj_structure_score * intent_coverage
                
                if critical_missing:
                    final_score = 0.0
                
                # Retries/Attempts
                # Looking at pipeline_engine.py, it uses gen_attempt loop
                # We can't easily get the exact attempt from the current result dict reliably 
                # without modifying pipeline_engine.py, but we can assume converged = success within retries.
                retries_used = 1 # Placeholder
                first_pass_attempt = 1 # Placeholder
                
                return CaseResult(
                    id=case.id,
                    pattern=case.pattern,
                    difficulty=case.difficulty,
                    compile_pass=compile_pass,
                    lint_errors=lint_errors,
                    lint_warnings=lint_warnings,
                    lint_factor=lint_factor,
                    structure_score=structure_score,
                    adj_structure_score=adj_structure_score,
                    required_features=case.required_features,
                    detected_features=detected,
                    missing_features=missing,
                    hallucinated_features=hallucinated,
                    intent_coverage=intent_coverage,
                    final_score=final_score,
                    latency_seconds=latency,
                    retries_used=retries_used,
                    max_retries=case.max_retries,
                    converged=converged,
                    failure_layer=None,
                    elapsed_seconds=latency,
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

        except asyncio.TimeoutError:
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
            hallucinated_features=[],
            intent_coverage=0.0,
            final_score=0.0,
            latency_seconds=latency,
            retries_used=case.max_retries,
            max_retries=case.max_retries,
            converged=False,
            failure_layer=failure_layer,
            elapsed_seconds=latency
        )
