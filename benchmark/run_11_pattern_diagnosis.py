import asyncio
import json
import os
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any

from benchmark.runner import BenchmarkRunner


SUITE_FILES = {
    "single_sig_transfer": "benchmark/suites/single_sig_transfer.yaml",
    "timelock": "benchmark/suites/timelock.yaml",
    "hashlock": "benchmark/suites/hashlock.yaml",
    "multisig": "benchmark/suites/multisig.yaml",
    "escrow": "benchmark/suites/escrow.yaml",
    "refundable_payment": "benchmark/suites/refundable_payment.yaml",
    "split_payment": "benchmark/suites/split_payment.yaml",
    "vault": "benchmark/suites/vaults.yaml",
    "covenant": "benchmark/suites/covenant.yaml",
    "conditional_spend": "benchmark/suites/conditional_spend.yaml",
    "decay": "benchmark/suites/decay.yaml",
}


def _bucket(convergence_rate: float) -> str:
    if convergence_rate >= 0.85:
        return "Good convergence"
    if convergence_rate >= 0.50:
        return "Medium convergence"
    return "Not converging"


def _phase_from_failure_layer(layer: str) -> str:
    text = (layer or "").lower()
    if "phase1" in text:
        return "Phase1"
    if "dsl" in text or "lint" in text:
        return "Phase2"
    if "compile" in text:
        return "Phase2"
    if "phase3" in text or "toll" in text:
        return "Phase3"
    if "phase4" in text or "sanity" in text:
        return "Phase4"
    if "timeout" in text:
        return "Timeout"
    if text:
        return "Unknown"
    return "None"


def _false_positive_candidates(results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    candidates = []
    for r in results:
        # Heuristic for cross-pattern false positives:
        # compile passed but intent coverage weak OR repeated lint/toll failures.
        compile_pass = bool(r.get("compile_pass"))
        intent_coverage = float(r.get("intent_coverage", 0.0))
        layer = r.get("failure_layer") or ""
        missing = r.get("missing_features") or []
        if compile_pass and intent_coverage < 0.7:
            candidates.append(
                {
                    "id": r.get("id"),
                    "pattern": r.get("pattern"),
                    "reason": "compile_pass_but_low_intent_coverage",
                    "failure_layer": layer or "None",
                    "missing_features": missing,
                }
            )
        elif ("DSLLint" in layer or "Phase3" in layer) and missing:
            candidates.append(
                {
                    "id": r.get("id"),
                    "pattern": r.get("pattern"),
                    "reason": "gate_failure_with_missing_features",
                    "failure_layer": layer,
                    "missing_features": missing,
                }
            )
    return candidates


async def run():
    max_cases_per_pattern = int(os.getenv("NEXOPS_BENCH_MAX_CASES_PER_PATTERN", "2"))
    started = datetime.utcnow()
    per_pattern = {}
    all_case_results: List[Dict[str, Any]] = []

    for pattern, suite in SUITE_FILES.items():
        runner = BenchmarkRunner(suite)
        runner.load_suite()
        if max_cases_per_pattern > 0:
            runner.cases = runner.cases[:max_cases_per_pattern]
        report = await runner.run_all()
        report_dict = report.model_dump()

        pattern_summary = next(
            (s for s in report_dict.get("pattern_summaries", []) if s.get("pattern") == pattern),
            None,
        )
        if not pattern_summary:
            pattern_summary = report_dict.get("pattern_summaries", [{}])[0]

        case_results = [r for r in report_dict.get("results", []) if r.get("pattern") == pattern]
        all_case_results.extend(case_results)

        phase_counts: Dict[str, int] = {}
        for cr in case_results:
            phase = _phase_from_failure_layer(cr.get("failure_layer", ""))
            phase_counts[phase] = phase_counts.get(phase, 0) + 1

        dominant_failure_phase = "None"
        failing_counts = {k: v for k, v in phase_counts.items() if k not in {"None"}}
        if failing_counts:
            dominant_failure_phase = sorted(failing_counts.items(), key=lambda kv: kv[1], reverse=True)[0][0]

        per_pattern[pattern] = {
            "total_cases": len(case_results),
            "compile_rate": pattern_summary.get("compile_rate", 0.0),
            "convergence_rate": pattern_summary.get("convergence_rate", 0.0),
            "intent_coverage": pattern_summary.get("avg_intent_coverage", 0.0),
            "avg_final_score": pattern_summary.get("avg_final_score", 0.0),
            "severity_bucket": _bucket(pattern_summary.get("convergence_rate", 0.0)),
            "dominant_failure_phase": dominant_failure_phase,
            "phase_distribution": phase_counts,
            "fallback_rate": (
                sum(1 for cr in case_results if cr.get("converged") is False and cr.get("compile_pass") is False)
                / len(case_results)
                if case_results
                else 0.0
            ),
            "false_positive_candidates": _false_positive_candidates(case_results),
        }

    completed = datetime.utcnow()
    output = {
        "run_type": "11_pattern_diagnosis",
        "max_cases_per_pattern": max_cases_per_pattern,
        "started_at": started.isoformat(),
        "completed_at": completed.isoformat(),
        "elapsed_seconds": (completed - started).total_seconds(),
        "patterns": per_pattern,
        "global_false_positive_candidates": _false_positive_candidates(all_case_results),
    }

    out_dir = Path("benchmark/results")
    out_dir.mkdir(parents=True, exist_ok=True)
    out_file = out_dir / f"diagnosis_11_patterns_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    out_file.write_text(json.dumps(output, indent=2), encoding="utf-8")
    print(f"Saved 11-pattern diagnosis to: {out_file}")


if __name__ == "__main__":
    asyncio.run(run())
