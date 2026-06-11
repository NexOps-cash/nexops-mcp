"""Dump escrow routing diagnostics for benchmark cases.

Writes JSON to benchmark/results/escrow_diagnostics/<case_id>.json.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from dotenv import load_dotenv

load_dotenv(ROOT / ".env")

ESCROW_YAML = ROOT / "benchmark/suites/escrow.yaml"
ESCROW_SUITE_YAML = ROOT / "benchmark/suites/escrow_suite.yaml"
OUT_DIR = ROOT / "benchmark/results/escrow_diagnostics"

DEFAULT_CASE_IDS = [
    "esc_001",
    "esc_002",
    "esc_003",
    "esc_004",
    "esc_005",
    "esc_006",
    "escrow_basic_multisig",
    "escrow_timeout_refund",
    "escrow_arbiter_resolution",
    "escrow_2of3_release",
    "escrow_timeout_with_arbiter",
    "escrow_value_preservation",
    "escrow_single_output_rule",
    "escrow_dual_resolution",
    "escrow_role_separation",
    "escrow_extreme_protocol",
]


def _load_case(case_id: str):
    from benchmark.runner import BenchmarkRunner

    for suite_path in (ESCROW_YAML, ESCROW_SUITE_YAML):
        runner = BenchmarkRunner(str(suite_path), case_ids=[case_id])
        runner.load_suite()
        if runner.cases:
            return runner.cases[0], suite_path.name
    return None, None


async def diagnose_case(case_id: str) -> dict:
    from src.services.pattern_profiles import canonical_pattern, get_pattern_profile
    from src.services.pipeline import (
        Phase1,
        build_pattern_rails,
        build_structured_knowledge,
        resolve_effective_mode,
    )

    case, suite_name = _load_case(case_id)
    if not case:
        return {"case_id": case_id, "error": "case not found in escrow suites"}

    ir = await Phase1.run(
        case.intent,
        security_level="high",
        disable_golden=True,
        disable_fallbacks=True,
    )
    intent_model = ir.metadata.intent_model if ir.metadata else None

    if not intent_model:
        return {
            "case_id": case_id,
            "suite": suite_name,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "error": "phase1_intent_parse_failed",
        }

    contract_type = intent_model.contract_type or ""
    features = list(intent_model.features or [])
    effective_mode = resolve_effective_mode(intent_model)
    canonical = canonical_pattern(effective_mode)
    profile = get_pattern_profile(effective_mode)
    knowledge_yaml = build_structured_knowledge(ir)

    pattern_profile_loaded = bool(profile.get("knowledge_files"))
    escrow_rules_loaded = (
        "pattern_escrow_rules" in knowledge_yaml
        or "ESCROW-RELEASE-AUTH" in knowledge_yaml
        or "family: escrow" in knowledge_yaml
    )

    rails = build_pattern_rails(
        features,
        contract_type=contract_type,
        effective_mode=effective_mode,
        intent_model=intent_model,
    )
    escrow_rail_loaded = "[RAIL: ESCROW MODE]" in rails
    golden_candidate = contract_type == "escrow_2of3_nft"

    return {
        "case_id": case_id,
        "suite": suite_name,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "contract_type": contract_type,
        "effective_mode": effective_mode,
        "features": features,
        "canonical_pattern": canonical,
        "pattern_profile_loaded": pattern_profile_loaded,
        "escrow_rules_loaded": escrow_rules_loaded,
        "escrow_rail_loaded": escrow_rail_loaded,
        "golden_path_candidate": golden_candidate,
        "knowledge_files": profile.get("knowledge_files", []),
        "signers": intent_model.signers or [],
        "threshold": intent_model.threshold,
        "timeout_days": intent_model.timeout_days,
        "intent_preview": case.intent.strip()[:140],
    }


async def main() -> None:
    parser = argparse.ArgumentParser(description="Escrow routing diagnostics")
    parser.add_argument(
        "case_id",
        nargs="?",
        default="all",
        help="Case id or 'all' for default escrow benchmark set",
    )
    args = parser.parse_args()

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    case_ids = DEFAULT_CASE_IDS
    if args.case_id and args.case_id != "all":
        case_ids = [args.case_id]

    results = []
    for cid in case_ids:
        diag = await diagnose_case(cid)
        out_path = OUT_DIR / f"{cid}.json"
        out_path.write_text(json.dumps(diag, indent=2) + "\n", encoding="utf-8")
        results.append(diag)
        print(json.dumps(diag, indent=2))
        print(f"Wrote {out_path}\n")

    summary_path = OUT_DIR / "summary.json"
    summary_path.write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    asyncio.run(main())
