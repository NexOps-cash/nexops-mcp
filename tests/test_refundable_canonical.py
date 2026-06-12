"""Tests for deterministic refundable canonical template matching."""

from __future__ import annotations

import yaml
from pathlib import Path

from src.services.compiler import CompilerService
from src.services.dsl_lint import get_dsl_linter
from src.models import IntentModel
from src.services.pipeline import Phase3
from src.services.refundable_canonical import (
    load_refundable_canonical_template,
    match_refundable_canonical_template,
    resolve_refundable_canonical_code,
)
from src.services.sanity_checker import get_sanity_checker

ROOT = Path(__file__).resolve().parents[1]
SUITE = ROOT / "benchmark" / "suites" / "refundable_payment.yaml"


def _intent(case_id: str) -> str:
    for case in yaml.safe_load(SUITE.read_text(encoding="utf-8")):
        if case["id"] == case_id:
            return case["intent"].strip()
    raise KeyError(case_id)


def test_rp_003_matches_subscription():
    assert match_refundable_canonical_template(_intent("rp_003")) == "refundable_subscription_escrow"


def test_rp_004_matches_gradual_release():
    assert match_refundable_canonical_template(_intent("rp_004")) == "refundable_gradual_release"


def test_rp_001_does_not_match():
    assert match_refundable_canonical_template(_intent("rp_001")) is None


def test_rp_006_crowdfund_does_not_match_subscription_or_gradual():
    text = _intent("rp_006").lower()
    assert "subscription" not in text
    assert match_refundable_canonical_template(_intent("rp_006")) is None


def test_templates_lint_compile_under_inferred_modes():
    linter = get_dsl_linter()
    compiler = CompilerService()
    cases = {
        "refundable_subscription_escrow": "escrow",
        "refundable_gradual_release": "linear_vesting",
    }
    for template_id, mode in cases.items():
        code = load_refundable_canonical_template(template_id)
        assert code
        lint = linter.lint(code, contract_mode=mode)
        assert lint.get("passed"), lint.get("violations")
        comp = compiler.compile(code)
        assert comp.get("success"), comp.get("error")
        tg = Phase3.validate(code, contract_mode=mode)
        assert tg.passed


def test_resolve_returns_code_for_rp_003_and_rp_004():
    for case_id in ("rp_003", "rp_004"):
        code = resolve_refundable_canonical_code(_intent(case_id))
        assert code and "function" in code


def test_canonical_templates_pass_streaming_sanity():
    """Phase 1 routes rp_003 to streaming — dual-path exemption must apply."""
    checker = get_sanity_checker()
    code = load_refundable_canonical_template("refundable_subscription_escrow")
    model = IntentModel(contract_type="streaming", features=["timelock", "streaming"])
    result = checker.validate(code, model)
    assert result["success"], result["violations"]
