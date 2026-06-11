"""Dump split-payment routing diagnostics for benchmark cases.

Writes JSON to benchmark/results/split_diagnostics/<case_id>.json.
Reusable pattern for future multisig/escrow/vault/hashlock/timelock diagnostics.
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

SUITE = ROOT / "benchmark/suites/split_payment.yaml"
OUT_DIR = ROOT / "benchmark/results/split_diagnostics"

PHASE1_CASE_IDS = [
    "split_001_treasury",
    "split_002_payroll",
    "split_003_multisig_distribution",
    "split_004_revenue_share",
]


async def diagnose_case(case_id: str) -> dict:
    from benchmark.runner import BenchmarkRunner
    from src.services.pattern_profiles import canonical_pattern, get_pattern_profile
    from src.services.pipeline import (
        Phase1,
        build_pattern_rails,
        build_structured_knowledge,
        resolve_effective_mode,
    )

    runner = BenchmarkRunner(str(SUITE), case_ids=[case_id])
    runner.load_suite()
    if not runner.cases:
        return {"case_id": case_id, "error": f"case not found in {SUITE.name}"}

    case = runner.cases[0]
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
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "error": "phase1_intent_parse_failed",
            "contract_type": None,
            "effective_mode": None,
            "features": [],
            "pattern_profile_loaded": False,
            "split_rules_loaded": False,
            "split_rail_loaded": False,
        }

    contract_type = intent_model.contract_type or ""
    features = list(intent_model.features or [])
    effective_mode = resolve_effective_mode(intent_model)
    canonical = canonical_pattern(effective_mode)
    profile = get_pattern_profile(effective_mode)
    knowledge_yaml = build_structured_knowledge(ir)

    pattern_profile_loaded = bool(profile.get("knowledge_files"))
    split_rules_loaded = (
        "pattern_split_rules" in knowledge_yaml
        or "SPLIT-LENGTH-GUARD" in knowledge_yaml
        or "SPLIT-SUM-INVARIANT" in knowledge_yaml
        or ("split" in features and "family: split" in knowledge_yaml)
    )

    rails = build_pattern_rails(
        features,
        contract_type=contract_type,
        effective_mode=effective_mode,
        intent_model=intent_model,
    )
    split_rail_loaded = "[RAIL: SPLIT MODE]" in rails

    return {
        "case_id": case_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "contract_type": contract_type,
        "effective_mode": effective_mode,
        "features": features,
        "canonical_pattern": canonical,
        "pattern_profile_loaded": pattern_profile_loaded,
        "split_rules_loaded": split_rules_loaded,
        "split_rail_loaded": split_rail_loaded,
        "knowledge_files": profile.get("knowledge_files", []),
        "intent_preview": case.intent.strip()[:120],
    }


async def main() -> None:
    parser = argparse.ArgumentParser(description="Split payment routing diagnostics")
    parser.add_argument(
        "case_id",
        nargs="?",
        default="all",
        help="Case id (e.g. split_001_treasury) or 'all' for Phase 1 subset",
    )
    args = parser.parse_args()

    OUT_DIR.mkdir(parents=True, exist_ok=True)

    case_ids = PHASE1_CASE_IDS
    if args.case_id and args.case_id != "all":
        case_ids = [args.case_id]

    for cid in case_ids:
        diag = await diagnose_case(cid)
        out_path = OUT_DIR / f"{cid}.json"
        out_path.write_text(json.dumps(diag, indent=2) + "\n", encoding="utf-8")
        print(json.dumps(diag, indent=2))
        print(f"Wrote {out_path}\n")


if __name__ == "__main__":
    asyncio.run(main())
