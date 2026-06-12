"""Deep generation RCA for refundable_payment hard cases (rp_003, rp_004).

Captures Phase1 routing, final draft, lint, compile, toll gate, and sanity per attempt.
Writes JSON to benchmark/results/refundable_generation/<case_id>.json
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from dotenv import load_dotenv

load_dotenv(ROOT / ".env")

REFUNDABLE_YAML = ROOT / "benchmark/suites/refundable_payment.yaml"
OUT_DIR = ROOT / "benchmark/results/refundable_generation"

DEFAULT_CASE_IDS = ["rp_003", "rp_004"]


def _load_case(case_id: str):
    from benchmark.runner import BenchmarkRunner

    runner = BenchmarkRunner(str(REFUNDABLE_YAML), case_ids=[case_id])
    runner.load_suite()
    return runner.cases[0] if runner.cases else None


def _routing_snapshot(ir, benchmark_pattern: str) -> Dict[str, Any]:
    from src.services.pattern_profiles import canonical_pattern, get_pattern_profile
    from src.services.pipeline import build_pattern_rails, build_structured_knowledge, resolve_effective_mode

    intent_model = ir.metadata.intent_model
    contract_type = intent_model.contract_type or ""
    features = list(intent_model.features or [])
    effective_mode = resolve_effective_mode(intent_model)
    canonical = canonical_pattern(effective_mode)
    profile = get_pattern_profile(effective_mode)
    knowledge_yaml = build_structured_knowledge(ir)
    rails = build_pattern_rails(
        features,
        contract_type=contract_type,
        effective_mode=effective_mode,
        intent_model=intent_model,
    )
    return {
        "contract_type": contract_type,
        "effective_mode": effective_mode,
        "canonical_pattern": canonical,
        "features": features,
        "knowledge_files": profile.get("knowledge_files", []),
        "refundable_rules_loaded": (
            "RP-REFUND" in knowledge_yaml or "family: refundable_payment" in knowledge_yaml
        ),
        "escrow_rules_loaded": "family: escrow" in knowledge_yaml,
        "decay_rules_loaded": "family: decay" in knowledge_yaml,
        "swap_rail_loaded": "[RAIL: SWAP (HTLC) MODE]" in rails,
        "escrow_rail_loaded": "[RAIL: ESCROW MODE]" in rails,
        "routing_mismatch": benchmark_pattern == "refundable_payment"
        and canonical != "refundable_payment",
    }


def _llm_kwargs() -> Dict[str, Any]:
    provider = os.getenv("REFUNDABLE_GEN_PROVIDER", "openai")
    if provider == "openai":
        key = os.getenv("OPENAI_API_KEY")
        if key:
            return {"api_key": key, "provider": "openai"}
    return {}


async def _trace_generation(case_id: str, intent: str) -> Dict[str, Any]:
    from src.services.compiler import CompilerService
    from src.services.dsl_lint import get_dsl_linter
    from src.services.language_guard import get_language_guard
    from src.services.pipeline import Phase1, Phase2, Phase3, resolve_effective_mode
    from src.services.sanity_checker import get_sanity_checker
    from src.services.structural_integrity import is_structurally_valid

    llm = _llm_kwargs()
    try:
        ir = await Phase1.run(
            intent,
            security_level="high",
            disable_golden=True,
            disable_fallbacks=True,
            **llm,
        )
    except RuntimeError as exc:
        return {"case_id": case_id, "error": "phase1_llm_failed", "error_detail": str(exc)[:500]}
    intent_model = ir.metadata.intent_model if ir.metadata else None
    if not intent_model:
        return {"case_id": case_id, "error": "phase1_intent_parse_failed"}

    contract_mode = (
        resolve_effective_mode(intent_model) or intent_model.contract_type or ""
    ).lower()
    routing = _routing_snapshot(ir, "refundable_payment")
    linter = get_dsl_linter()
    compiler = CompilerService()
    sanity_checker = get_sanity_checker()
    language_guard = get_language_guard()

    attempts: List[Dict[str, Any]] = []
    previous_violations = None
    last_code: Optional[str] = None
    first_hard_failure: Optional[Dict[str, Any]] = None

    max_gen_retries = 3

    for gen_attempt in range(max_gen_retries):
        attempt_rec: Dict[str, Any] = {
            "gen_attempt": gen_attempt + 1,
            "draft_exists": False,
            "structurally_valid": False,
            "lint_passed": None,
            "lint_violations": [],
            "compile_passed": None,
            "compile_error": None,
            "toll_gate_passed": None,
            "toll_gate_violations": [],
            "sanity_passed": None,
            "sanity_violations": [],
            "first_failure_in_attempt": None,
        }

        try:
            code = await Phase2.run(
                ir,
                violations=previous_violations,
                retry_count=gen_attempt,
                **llm,
            )
        except Exception as exc:
            attempt_rec["phase2_error"] = str(exc)[:500]
            attempt_rec["first_failure_in_attempt"] = "Phase2"
            if not first_hard_failure:
                first_hard_failure = {
                    "layer": "Phase2",
                    "detail": str(exc)[:500],
                    "gen_attempt": gen_attempt + 1,
                }
            attempts.append(attempt_rec)
            continue
        last_code = code
        attempt_rec["draft_exists"] = bool(code and code.strip())
        attempt_rec["draft_preview"] = (code or "")[:2000]
        attempt_rec["structurally_valid"] = is_structurally_valid(code) if code else False

        if not attempt_rec["draft_exists"]:
            attempt_rec["first_failure_in_attempt"] = "Phase2_empty_draft"
            if not first_hard_failure:
                first_hard_failure = {
                    "layer": "Phase2",
                    "detail": "empty draft",
                    "gen_attempt": gen_attempt + 1,
                }
            attempts.append(attempt_rec)
            continue

        guard_failure = language_guard.validate(code)
        if guard_failure:
            attempt_rec["language_guard_failure"] = guard_failure
            attempt_rec["first_failure_in_attempt"] = "LanguageGuard"
            if not first_hard_failure:
                first_hard_failure = {
                    "layer": "LanguageGuard",
                    "detail": guard_failure,
                    "gen_attempt": gen_attempt + 1,
                }
            attempts.append(attempt_rec)
            continue

        if not attempt_rec["structurally_valid"]:
            attempt_rec["first_failure_in_attempt"] = "StructuralIntegrity"
            if not first_hard_failure:
                first_hard_failure = {
                    "layer": "StructuralIntegrity",
                    "detail": "post-Phase2 structure invalid",
                    "gen_attempt": gen_attempt + 1,
                }
            attempts.append(attempt_rec)
            continue

        lint_result = linter.lint(code, contract_mode=contract_mode)
        attempt_rec["lint_passed"] = lint_result.get("passed", False)
        attempt_rec["lint_violations"] = [
            {
                "rule_id": v.get("rule_id"),
                "message": v.get("message"),
                "severity": v.get("severity"),
            }
            for v in lint_result.get("violations", [])
        ]
        if not lint_result.get("passed"):
            attempt_rec["first_failure_in_attempt"] = "DSLLint"
            if not first_hard_failure:
                first_hard_failure = {
                    "layer": "DSLLint",
                    "detail": attempt_rec["lint_violations"][:5],
                    "gen_attempt": gen_attempt + 1,
                }
            attempts.append(attempt_rec)
            continue

        compile_result = compiler.compile(code)
        attempt_rec["compile_passed"] = compile_result.get("success", False)
        if not compile_result.get("success"):
            err = compile_result.get("error") or {}
            raw = err.get("raw", str(err)) if isinstance(err, dict) else str(err)
            attempt_rec["compile_error"] = raw[:1500]
            attempt_rec["compile_error_type"] = (
                err.get("type", "UnknownError") if isinstance(err, dict) else "UnknownError"
            )
            attempt_rec["first_failure_in_attempt"] = "Compile"
            if not first_hard_failure:
                first_hard_failure = {
                    "layer": "Compile",
                    "detail": attempt_rec["compile_error"][:500],
                    "gen_attempt": gen_attempt + 1,
                }
            attempts.append(attempt_rec)
            continue

        toll_gate = Phase3.validate(code, contract_mode=contract_mode)
        attempt_rec["toll_gate_passed"] = toll_gate.passed
        attempt_rec["toll_gate_violations"] = [
            {"rule": v.rule, "reason": v.reason, "severity": v.severity}
            for v in toll_gate.violations
        ]
        if not toll_gate.passed:
            attempt_rec["first_failure_in_attempt"] = "TollGate"
            if not first_hard_failure:
                first_hard_failure = {
                    "layer": "TollGate",
                    "detail": attempt_rec["toll_gate_violations"][:5],
                    "gen_attempt": gen_attempt + 1,
                }
            attempts.append(attempt_rec)
            previous_violations = toll_gate.violations
            continue

        sanity_result = sanity_checker.validate(code, intent_model)
        attempt_rec["sanity_passed"] = sanity_result.get("success", False)
        attempt_rec["sanity_violations"] = sanity_result.get("violations", [])
        if not sanity_result.get("success"):
            attempt_rec["first_failure_in_attempt"] = "Sanity"
            if not first_hard_failure:
                first_hard_failure = {
                    "layer": "Sanity",
                    "detail": attempt_rec["sanity_violations"][:5],
                    "gen_attempt": gen_attempt + 1,
                }
            attempts.append(attempt_rec)
            continue

        attempt_rec["first_failure_in_attempt"] = None
        attempts.append(attempt_rec)
        return {
            "case_id": case_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "routing": routing,
            "pipeline_converged": True,
            "first_hard_failure": None,
            "attempts": attempts,
            "final_draft": code,
        }

    return {
        "case_id": case_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "routing": routing,
        "pipeline_converged": False,
        "first_hard_failure": first_hard_failure,
        "attempts": attempts,
        "final_draft": last_code,
        "final_draft_exists": bool(last_code and last_code.strip()),
    }


async def main() -> None:
    parser = argparse.ArgumentParser(description="Refundable generation RCA")
    parser.add_argument("case_id", nargs="?", default="all")
    args = parser.parse_args()

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    case_ids = DEFAULT_CASE_IDS
    if args.case_id and args.case_id != "all":
        case_ids = [args.case_id]

    results = []
    for cid in case_ids:
        case = _load_case(cid)
        if not case:
            print(f"Case {cid} not found")
            continue
        diag = await _trace_generation(cid, case.intent)
        diag["intent_preview"] = case.intent.strip()[:200]
        out_path = OUT_DIR / f"{cid}.json"
        draft_path = OUT_DIR / f"{cid}_final_draft.cash"
        if diag.get("final_draft"):
            draft_path.write_text(diag["final_draft"], encoding="utf-8")
            diag["final_draft_path"] = str(draft_path)
        out_path.write_text(json.dumps(diag, indent=2) + "\n", encoding="utf-8")
        results.append(diag)
        print(json.dumps({k: v for k, v in diag.items() if k != "final_draft"}, indent=2))
        print(f"Wrote {out_path}\n")

    summary_path = OUT_DIR / "summary.json"
    summary_path.write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    asyncio.run(main())
