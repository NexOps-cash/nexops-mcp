"""Dump vault routing diagnostics for benchmark cases.

Writes JSON to benchmark/results/vault_diagnostics/<case_id>.json.
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

VAULTS_YAML = ROOT / "benchmark/suites/vaults.yaml"
VAULTS_REAL = ROOT / "benchmark/suites/vaults_real"
VAULT_DEBUG = ROOT / "benchmark/suites/vault_debug.yaml"
OUT_DIR = ROOT / "benchmark/results/vault_diagnostics"

PHASE1_CASE_IDS = [
    "v_001",
    "v_002",
    "v_003",
    "v_007",
    "vr_001",
    "vr_003",
    "vr_006",
    "vr_009",
]


def _load_case(case_id: str):
    from benchmark.runner import BenchmarkRunner

    for suite_path in (VAULTS_YAML, VAULTS_REAL, VAULT_DEBUG):
        if not suite_path.exists():
            continue
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
        return {"case_id": case_id, "error": "case not found in vault-related suites"}

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

    pattern_profile_loaded = bool(profile.get("knowledge_files"))
    vault_rules_loaded = (
        "pattern_vault_rules" in knowledge_yaml
        or "VLT-INTERMEDIATE" in knowledge_yaml
        or "family: vault" in knowledge_yaml
    )

    rails = build_pattern_rails(
        features,
        contract_type=contract_type,
        effective_mode=effective_mode,
        intent_model=intent_model,
    )
    vault_rail_loaded = "[RAIL: EXCLUSIVE VAULT RULES" in rails

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
        "pattern_profile_loaded": pattern_profile_loaded,
        "vault_rules_loaded": vault_rules_loaded,
        "vault_rail_loaded": vault_rail_loaded,
        "knowledge_files": profile.get("knowledge_files", []),
        "signers": intent_model.signers or [],
        "timeout_days": intent_model.timeout_days,
        "intent_preview": case.intent.strip()[:160],
    }


async def main() -> None:
    parser = argparse.ArgumentParser(description="Vault routing diagnostics")
    parser.add_argument(
        "case_id",
        nargs="?",
        default="all",
        help="Case id or 'all' for Phase 1 validation subset",
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
