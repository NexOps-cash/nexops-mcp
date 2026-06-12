"""Dump refundable_payment routing diagnostics for benchmark cases.

Writes JSON to benchmark/results/refundable_diagnostics/<case_id>.json.
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

REFUNDABLE_YAML = ROOT / "benchmark/suites/refundable_payment.yaml"
OUT_DIR = ROOT / "benchmark/results/refundable_diagnostics"

PHASE1_CASE_IDS = [
    "rp_001",
    "rp_002",
    "rp_003",
    "rp_004",
    "rp_005",
    "rp_006",
]


def _load_case(case_id: str):
    from benchmark.runner import BenchmarkRunner

    runner = BenchmarkRunner(str(REFUNDABLE_YAML), case_ids=[case_id])
    runner.load_suite()
    if runner.cases:
        return runner.cases[0], REFUNDABLE_YAML.name
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
        return {"case_id": case_id, "error": "case not found in refundable_payment.yaml"}

    try:
        ir = await Phase1.run(
            case.intent,
            security_level="high",
            disable_golden=True,
            disable_fallbacks=True,
        )
    except RuntimeError as exc:
        return {
            "case_id": case_id,
            "suite": suite_name,
            "benchmark_pattern": case.pattern,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "error": "phase1_llm_failed",
            "error_detail": str(exc)[:240],
        }

    intent_model = ir.metadata.intent_model if ir.metadata else None

    if not intent_model:
        return {
            "case_id": case_id,
            "suite": suite_name,
            "benchmark_pattern": case.pattern,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "error": "phase1_intent_parse_failed",
        }

    contract_type = intent_model.contract_type or ""
    features = list(intent_model.features or [])
    effective_mode = resolve_effective_mode(intent_model)
    canonical = canonical_pattern(effective_mode)
    profile = get_pattern_profile(effective_mode)
    knowledge_yaml = build_structured_knowledge(ir)

    refundable_rules_loaded = (
        "pattern_refundable_payment_rules" in knowledge_yaml
        or "RP-REFUND" in knowledge_yaml
        or "family: refundable_payment" in knowledge_yaml
    )
    conditional_spend_rules_loaded = (
        "pattern_conditional_spend_rules" in knowledge_yaml
        or "family: conditional_spend" in knowledge_yaml
    )
    escrow_rules_loaded = (
        "pattern_escrow_rules" in knowledge_yaml
        or "family: escrow" in knowledge_yaml
    )

    rails = build_pattern_rails(
        features,
        contract_type=contract_type,
        effective_mode=effective_mode,
        intent_model=intent_model,
    )
    swap_rail_loaded = "[RAIL: SWAP (HTLC) MODE]" in rails
    escrow_rail_loaded = "[RAIL: ESCROW MODE]" in rails
    vault_rail_loaded = "[RAIL: EXCLUSIVE VAULT RULES" in rails

    golden_eligible = contract_type == "refundable_crowdfund"

    routing_mismatch = case.pattern == "refundable_payment" and canonical != "refundable_payment"

    return {
        "case_id": case_id,
        "suite": suite_name,
        "benchmark_pattern": case.pattern,
        "benchmark_tags": list(case.tags or []),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "contract_type": contract_type,
        "effective_mode": effective_mode,
        "canonical_pattern": canonical,
        "features": features,
        "pattern_profile_loaded": bool(profile.get("knowledge_files")),
        "knowledge_files": profile.get("knowledge_files", []),
        "refundable_rules_loaded": refundable_rules_loaded,
        "conditional_spend_rules_loaded": conditional_spend_rules_loaded,
        "escrow_rules_loaded": escrow_rules_loaded,
        "swap_rail_loaded": swap_rail_loaded,
        "escrow_rail_loaded": escrow_rail_loaded,
        "vault_rail_loaded": vault_rail_loaded,
        "golden_eligible": golden_eligible,
        "routing_mismatch": routing_mismatch,
        "signers": intent_model.signers or [],
        "timeout_days": intent_model.timeout_days,
        "intent_preview": case.intent.strip()[:160],
    }


async def main() -> None:
    parser = argparse.ArgumentParser(description="Refundable payment routing diagnostics")
    parser.add_argument(
        "case_id",
        nargs="?",
        default="all",
        help="Case id or 'all' for full suite",
    )
    args = parser.parse_args()

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    case_ids = PHASE1_CASE_IDS
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
