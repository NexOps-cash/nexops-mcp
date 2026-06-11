"""Capture structural integrity failures for split benchmark cases."""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from dotenv import load_dotenv

load_dotenv(ROOT / ".env")

SUITE = ROOT / "benchmark/suites/split_payment.yaml"
OUT_DIR = ROOT / "benchmark/results/structural_failures_split"

CASE_IDS = [
    "split_001_treasury",
    "split_002_payroll",
    "split_003_multisig_distribution",
    "split_004_revenue_share",
]


def classify_issue(issue: str) -> str:
    if issue.startswith("brace_imbalance") or issue == "extra_closing_braces":
        return "bracket_imbalance"
    if issue == "dangling_require":
        return "dangling_require"
    if issue.startswith("incomplete_functions"):
        return "truncated_function"
    if issue == "truncated_constructor":
        return "truncated_contract"
    if issue.startswith("missing_new_p2pkh"):
        return "malformed_signature"
    if issue.startswith("paren_imbalance") or issue == "unterminated_string":
        return "invalid_cashscript_syntax"
    if issue.startswith("duplicate_functions"):
        return "duplicate_function"
    if issue == "empty_code":
        return "other"
    return "other"


def classify_diagnostics(diag_dict: Dict[str, Any]) -> List[str]:
    classes = [classify_issue(i) for i in diag_dict.get("issues", [])]
    return list(dict.fromkeys(classes))


async def investigate_case(case_id: str) -> Dict[str, Any]:
    from benchmark.runner import BenchmarkRunner
    from src.models import ViolationDetail
    from src.services.pipeline import Phase1, Phase2, resolve_effective_mode
    from src.services.pipeline_engine import get_guarded_pipeline_engine
    from src.services.structural_integrity import diagnose_structure, is_structurally_valid

    runner = BenchmarkRunner(str(SUITE), case_ids=[case_id])
    runner.load_suite()
    case = runner.cases[0]
    engine = get_guarded_pipeline_engine()

    ir = await Phase1.run(
        case.intent,
        security_level="high",
        disable_golden=True,
        disable_fallbacks=True,
    )
    intent_model = ir.metadata.intent_model
    contract_mode = (
        getattr(ir.metadata, "effective_mode", None)
        or resolve_effective_mode(intent_model)
        or (intent_model.contract_type if intent_model else "")
    ).lower()

    attempts: List[Dict[str, Any]] = []
    previous_violations: Optional[List[ViolationDetail]] = None
    max_gen_retries = 3
    last_draft = ""
    last_diag: Dict[str, Any] = {}

    for gen_attempt in range(max_gen_retries):
        code = await Phase2.run(
            ir,
            violations=previous_violations,
            retry_count=gen_attempt,
        )
        last_draft = code or ""
        diag = diagnose_structure(code or "")
        last_diag = diag.to_dict()
        struct_ok = is_structurally_valid(code or "")

        guard_failure = engine.language_guard.validate(code)
        lint_result = {"passed": True, "violations": []}
        if not guard_failure and code:
            semantic_ctx = None
            if intent_model:
                semantic_ctx = {
                    "ownership_mode": intent_model.ownership_mode,
                    "lifecycle_mode": intent_model.lifecycle_mode,
                    "supply_mode": intent_model.supply_mode,
                    "commitment_schema": intent_model.commitment_schema,
                }
            lint_result = engine.dsl_linter.lint(
                code, contract_mode=contract_mode, semantic=semantic_ctx
            )

        attempt_record = {
            "gen_attempt": gen_attempt + 1,
            "code_chars": len(code or ""),
            "code_lines": len((code or "").splitlines()),
            "language_guard_failure": guard_failure,
            "structural_valid": struct_ok,
            "structural_diagnostics": last_diag,
            "structural_classes": classify_diagnostics(last_diag),
            "lint_passed": lint_result.get("passed", False),
            "lint_violations": [
                {
                    "rule_id": v.get("rule_id"),
                    "message": v.get("message"),
                    "line_hint": v.get("line_hint"),
                }
                for v in lint_result.get("violations", [])[:10]
            ],
            "rejection_reason": None,
        }

        if guard_failure:
            attempt_record["rejection_reason"] = "language_guard"
        elif not struct_ok:
            attempt_record["rejection_reason"] = "structural_integrity_post_lint"
        elif not lint_result.get("passed"):
            attempt_record["rejection_reason"] = "dsl_lint"
        else:
            attempt_record["rejection_reason"] = "proceeded_to_compile"

        attempts.append(attempt_record)

        draft_path = OUT_DIR / f"{case_id}_attempt{gen_attempt + 1}.cash"
        draft_path.write_text(code or "", encoding="utf-8")

        if guard_failure or not struct_ok:
            previous_violations = None
            continue

        if lint_result.get("passed"):
            break

    result = {
        "case_id": case_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "contract_mode": contract_mode,
        "intent_model": intent_model.dict() if intent_model else {},
        "attempts": attempts,
        "final_draft_path": str(OUT_DIR / f"{case_id}_final_draft.cash"),
        "final_diagnostics": last_diag,
        "final_structural_classes": classify_diagnostics(last_diag),
    }

    final_path = OUT_DIR / f"{case_id}_final_draft.cash"
    final_path.write_text(last_draft, encoding="utf-8")
    meta_path = OUT_DIR / f"{case_id}_analysis.json"
    meta_path.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return result


async def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--ids", default=",".join(CASE_IDS))
    args = parser.parse_args()
    case_ids = [c.strip() for c in args.ids.split(",") if c.strip()]

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    all_results = []
    for cid in case_ids:
        print(f"Investigating {cid}...")
        result = await investigate_case(cid)
        all_results.append(result)
        print(json.dumps({k: v for k, v in result.items() if k != "intent_model"}, indent=2))

    summary_path = OUT_DIR / "summary.json"
    summary_path.write_text(json.dumps(all_results, indent=2) + "\n", encoding="utf-8")
    print(f"\nWrote artifacts to {OUT_DIR}")


if __name__ == "__main__":
    asyncio.run(main())
