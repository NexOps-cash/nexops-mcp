"""
Replay benchmark requirement checks on saved result JSON (no OpenRouter).

Usage:
  python scripts/bench_replay_requirements.py benchmark/results/bench_20260604_2229_81de.json
  python scripts/bench_replay_requirements.py benchmark/results/bench_20260604_2229_81de.json --ids ct_ft_mint_001
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from benchmark.evaluator import _cashtoken_alias_pool, _invalid_detector_alias_pool
from benchmark.feature_extractor import FeatureExtractor
from benchmark.schemas import BenchmarkCase
from benchmark.semantic_requirements import satisfies_requirement
from src.services.semantic_capabilities import extract_semantic_capabilities


def replay_case(case: BenchmarkCase, code: str) -> dict:
    extractor = FeatureExtractor()
    extracted = extractor.extract(code)
    detected = extracted["features"]
    functions = extracted["functions"]

    legacy_capabilities = {
        "signature_verification": any("_signature" in f or f == "multisig" for f in detected),
    }
    sem_caps = extract_semantic_capabilities(code, contract_mode=case.pattern or "")
    legacy_capabilities["enforces_supply_cap"] = sem_caps.get("enforces_supply_cap") is True

    pattern_key = (case.pattern or "").strip()
    if pattern_key in {"token_ft", "ft_mint", "nft_immutable", "nft_mutable", "nft_minting", "hybrid_token"}:
        legacy_alias_checks = _cashtoken_alias_pool(
            pattern_key, legacy_capabilities, detected, code, functions
        )
    else:
        legacy_alias_checks = _cashtoken_alias_pool("", legacy_capabilities, detected, code, functions)
    legacy_alias_checks.update(_invalid_detector_alias_pool(code, case.pattern or ""))

    def satisfied(req: str) -> bool:
        ok, _ = satisfies_requirement(
            req,
            sem_caps,
            legacy_alias_checks=legacy_alias_checks,
            detected_features=set(detected),
            legacy_capabilities=legacy_capabilities,
        )
        return ok

    required = case.required_features or []
    critical = case.critical_features or []
    missing_required = [r for r in required if not satisfied(r)]
    missing_critical = [c for c in critical if not satisfied(c)]
    intent_coverage = (
        (len(required) - len(missing_required)) / len(required) if required else 1.0
    )

    has_failure_tag = any(t in {"failure", "vulnerability"} for t in (case.tags or []))
    has_must_fail_critical = any(str(c).startswith("must_fail_") for c in critical)
    converged = (
        intent_coverage >= 0.70
        and not missing_critical
        and not (has_failure_tag and has_must_fail_critical)
    )

    return {
        "id": case.id,
        "intent_coverage": intent_coverage,
        "missing_required": missing_required,
        "missing_critical": missing_critical,
        "converged_replay": converged,
        "preserves_token_category": sem_caps.get("preserves_token_category"),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("result_json", type=Path)
    parser.add_argument("--ids", default="", help="Comma-separated case ids")
    args = parser.parse_args()

    data = json.loads(args.result_json.read_text(encoding="utf-8"))
    filter_ids = {x.strip() for x in args.ids.split(",") if x.strip()}

    # Load suite cases from same-era yaml is optional; use minimal case defs from results
    for row in data.get("results", []):
        cid = row["id"]
        if filter_ids and cid not in filter_ids:
            continue
        code = row.get("code")
        if not code:
            print(f"{cid}: no code (compile failed) — skip replay")
            continue
        case = BenchmarkCase(
            id=cid,
            pattern=row.get("pattern", ""),
            difficulty=row.get("difficulty", "medium"),
            intent="",
            required_features=row.get("required_features") or [],
            critical_features=[],  # not stored in json; load from yaml if needed
        )
        out = replay_case(case, code)
        print(
            f"{cid}: coverage={out['intent_coverage']:.2f} "
            f"missing_req={out['missing_required']} "
            f"preserves_cat={out['preserves_token_category']} "
            f"replay_converged={out['converged_replay']}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
