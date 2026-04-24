"""Policy: LNC-001c output[0], token-pair gating, semantic exploit downgrade."""

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


@pytest.fixture
def anyio_backend():
    return "asyncio"

from src.models import Severity, TollGateResult
from src.services.dsl_lint import DSLLinter
from src.utils.cashscript_ast import CashScriptAST


def test_lnc001c_skips_constant_output_index_zero():
    code = """
    contract T() {
        function f() {
            require(tx.outputs[0].value == 1000);
        }
    }
    """
    res = DSLLinter().lint(code, contract_mode="")
    assert all(v.get("rule_id") != "LNC-001c" for v in res.get("violations", []))


def test_lnc001c_still_flags_high_output_index_without_guard():
    code = """
    contract T() {
        function f() {
            require(tx.outputs[2].value == 1000);
        }
    }
    """
    res = DSLLinter().lint(code, contract_mode="")
    assert any(v.get("rule_id") == "LNC-001c" for v in res.get("violations", []))


def test_find_token_pair_empty_when_no_token_amount_in_source():
    code = """
    contract X() {
        function r() {
            require(tx.outputs[0].tokenCategory == 0x00);
        }
    }
    """
    assert CashScriptAST(code).find_token_pair_violations() == []


@pytest.mark.anyio
async def test_semantic_exploit_downgrades_without_direct_fund_loss():
    from src.services.audit_agent import AuditAgent

    mock_response = {
        "category": "EXPLOIT",
        "exploit_severity": "griefing",
        "explanation": "Design concern without proven direct loss.",
        "confidence": 0.9,
        "business_logic_score": 5,
        "business_logic_notes": "Review.",
    }
    mock_provider = MagicMock()
    mock_provider.complete = AsyncMock(return_value=json.dumps(mock_response))

    with patch("src.services.llm.factory.LLMFactory.get_provider", return_value=mock_provider), \
         patch("src.services.audit_agent.get_compiler_service") as mock_compiler, \
         patch("src.services.audit_agent.get_dsl_linter") as mock_linter, \
         patch("src.services.audit_agent.Phase3.validate") as mock_p3:
        mock_compiler.return_value.compile.return_value = {"success": True}
        mock_linter.return_value.lint.return_value = {"passed": True, "violations": []}
        mock_p3.return_value = TollGateResult(passed=True, violations=[], structural_score=1.0)

        report = await AuditAgent.audit("pragma cashscript ^0.13.0; contract T() { function f() { require(true); } }")

    assert report.semantic_category == "moderate_logic_risk"
    assert any(i.rule_id == "semantic_moderate_logic_risk" for i in report.issues)
    assert not any(i.rule_id == "semantic_major_protocol_flaw" for i in report.issues)
    sem = next(i for i in report.issues if i.rule_id.startswith("semantic_"))
    assert sem.severity == Severity.HIGH
