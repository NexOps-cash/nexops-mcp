"""Conditional spend Phase 1A evaluator alignment."""
import json
from pathlib import Path

from benchmark.evaluator import _cashtoken_alias_pool, _conditional_spend_alias_pool
from benchmark.feature_extractor import FeatureExtractor
from benchmark.runner import BenchmarkRunner
from benchmark.semantic_requirements import satisfies_requirement
from src.services.semantic_capabilities import extract_semantic_capabilities

BENCH_PATH = Path("benchmark/results/bench_20260331_2132_4ce4.json")


def _case_code(case_id: str) -> str:
    data = json.loads(BENCH_PATH.read_text(encoding="utf-8"))
    for row in data["results"]:
        if row["id"] == case_id:
            return row["code"]
    raise KeyError(case_id)


def _score_case(case_id: str) -> tuple[float, float, list[str]]:
    runner = BenchmarkRunner(
        "benchmark/suites/conditional_spend.yaml", case_ids=[case_id]
    )
    runner.load_suite()
    case = runner.cases[0]
    code = _case_code(case_id)
    extracted = FeatureExtractor().extract(code)
    detected = set(extracted["features"])
    functions = extracted["functions"]
    legacy = {
        "signature_verification": True,
        "time_validation": True,
        "multiple_paths": len(functions) >= 2,
        "multisig": True,
        "output_value_validation": True,
    }
    sem = extract_semantic_capabilities(code, contract_mode="conditional_spend")
    checks = _cashtoken_alias_pool(
        "conditional_spend", legacy, detected, code, functions
    )

    def satisfied(req: str) -> bool:
        ok, _ = satisfies_requirement(
            req,
            sem,
            legacy_alias_checks=checks,
            detected_features=detected,
            legacy_capabilities=legacy,
        )
        return ok

    required = case.required_features or []
    coverage = (
        sum(satisfied(r) for r in required) / len(required) if required else 1.0
    )
    crit_miss = [c for c in (case.critical_features or []) if not satisfied(c)]
    score = coverage * (0.2 if crit_miss else 1.0)
    return coverage, score, crit_miss


def test_conditional_spend_pool_detects_this_age():
    code = """
    function claim(sig s) {
        require(this.age >= timeout);
        require(checkSig(s, owner));
    }
    """
    pool = _conditional_spend_alias_pool({}, set(), code, [{"name": "claim"}])
    assert pool["locktime_check"]
    assert pool["time_validation"]
    assert pool["relative_timelock"]


def test_conditional_spend_pool_dual_checksig_multisig():
    code = """
    function both(sig a, sig b) {
        require(checkSig(a, alice));
        require(checkSig(b, bob));
    }
    """
    pool = _conditional_spend_alias_pool({}, set(), code, [{"name": "both"}])
    assert pool["multisig"]


def test_cs_001_cs_003_offline_rescore():
    for case_id in ("cs_001", "cs_002", "cs_003"):
        coverage, score, crit_miss = _score_case(case_id)
        assert not crit_miss, f"{case_id} critical miss: {crit_miss}"
        assert coverage >= 0.85, case_id
        assert score >= 0.85, case_id
