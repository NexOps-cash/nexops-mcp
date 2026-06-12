"""Tests for deterministic vault canonical template matching."""

from __future__ import annotations

import yaml
from pathlib import Path

from src.services.vault_canonical import (
    load_vault_canonical_template,
    match_vault_canonical_template,
    resolve_vault_canonical_code,
)
from src.services.compiler import CompilerService
from src.services.dsl_lint import get_dsl_linter
from src.services.pipeline import Phase3, resolve_effective_mode
from src.models import IntentModel

ROOT = Path(__file__).resolve().parents[1]
SUITE = ROOT / "benchmark" / "suites" / "vaults_real"


def _case_intent(case_id: str) -> str:
    cases = yaml.safe_load(SUITE.read_text(encoding="utf-8"))
    for case in cases:
        if case["id"] == case_id:
            return case["intent"].strip()
    raise KeyError(case_id)


def test_vr_010_matches_backup_cancel():
    intent = _case_intent("vr_010")
    assert match_vault_canonical_template(intent, effective_mode="vault") == "vault_backup_cancel"


def test_vr_023_matches_founder_treasury():
    intent = _case_intent("vr_023")
    assert match_vault_canonical_template(intent, effective_mode="vault") == "vault_founder_treasury"


def test_vr_001_does_not_match_canonical():
    intent = _case_intent("vr_001")
    assert match_vault_canonical_template(intent, effective_mode="vault") is None


def test_canonical_templates_compile_and_lint():
    linter = get_dsl_linter()
    compiler = CompilerService()
    for template_id in ("vault_backup_cancel", "vault_founder_treasury"):
        code = load_vault_canonical_template(template_id)
        assert code and "pragma cashscript" in code
        lint = linter.lint(code, contract_mode="vault")
        assert lint.get("passed"), lint.get("violations")
        comp = compiler.compile(code)
        assert comp.get("success"), comp.get("error")
        tg = Phase3.validate(code, contract_mode="vault")
        assert tg.passed, [v.reason for v in tg.violations if v.severity == "critical"]


def test_resolve_returns_code_for_benchmark_intents():
    for case_id in ("vr_010", "vr_023"):
        intent = _case_intent(case_id)
        code = resolve_vault_canonical_code(intent, effective_mode="vault")
        assert code and "function" in code


def test_non_vault_mode_skips():
    intent = _case_intent("vr_010")
    assert resolve_vault_canonical_code(intent, effective_mode="escrow") is None


def test_vr_009_also_matches_founder_treasury():
    intent = _case_intent("vr_009")
    assert match_vault_canonical_template(intent, effective_mode="vault") == "vault_founder_treasury"
