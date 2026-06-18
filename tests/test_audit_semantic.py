import pytest
import json
from unittest.mock import AsyncMock, patch, MagicMock
from src.services.audit_agent import AuditAgent
from src.models import FindingKind, Severity


@pytest.fixture
def anyio_backend():
    return "asyncio"


def _toll_gate_ok(_code, contract_mode=""):
    r = MagicMock()
    r.passed = True
    r.violations = []
    r.structural_score = 1.0
    return r


def _v2_unspendable_payload():
    return {
        "judge_version": "2.0",
        "verdict": "finding",
        "intent_fidelity_score": 0,
        "intent_fidelity_notes": "Add a spending function with require() guards to allow the owner to withdraw funds.",
        "finding": {
            "gap_id": "semantic.funds_unspendable",
            "attacker_gain": False,
            "authorization_impact": False,
            "value_impact": "none",
            "affected_invariant": "funds_unspendable",
            "attacker_controlled_inputs": [],
            "reasoning_steps": [
                "Examined spend paths and found none.",
                "No attacker-controlled inputs apply.",
                "No value movement possible.",
                "No attacker gain; funds are unspendable.",
            ],
            "summary": "The contract has no spending path, funds are effectively burnt.",
            "reasoning": "The contract has no spending path, funds are effectively burnt.",
            "recommendation": "Add a spending function with require() guards to allow the owner to withdraw funds.",
            "confidence": 0.95,
        },
    }


@pytest.mark.anyio
async def test_semantic_issue_injection():
    """Verify that semantic risks identified by LLM are injected into issues list."""

    mock_provider = MagicMock()
    mock_provider.complete = AsyncMock(return_value=json.dumps(_v2_unspendable_payload()))

    with patch("src.services.llm.factory.LLMFactory.get_provider", return_value=mock_provider), \
         patch("src.services.audit_agent.get_compiler_service") as mock_compiler, \
         patch("src.services.audit_agent.get_dsl_linter") as mock_linter, \
         patch("src.services.audit_agent.validate_audit", side_effect=_toll_gate_ok):

        mock_compiler.return_value.compile.return_value = {"success": True}
        mock_linter.return_value.lint.return_value = {"passed": True, "violations": []}

        code = "pragma cashscript ^0.13.0; contract DeadVault() { }"
        report = await AuditAgent.audit(code)

        assert report.semantic_category == "funds_unspendable"
        assert len(report.issues) == 1

        issue = report.issues[0]
        assert issue.rule_id == "semantic_funds_unspendable"
        assert issue.severity == Severity.CRITICAL
        assert issue.kind == FindingKind.VULNERABILITY
        assert "Security Vulnerability" in issue.title
        assert issue.can_fix is False


@pytest.mark.anyio
async def test_semantic_none_no_injection():
    """Verify that no_issue verdict does NOT inject an issue."""
    mock_response = {
        "judge_version": "2.0",
        "verdict": "no_issue",
        "intent_fidelity_score": 10,
        "intent_fidelity_notes": "Good implementation.",
    }

    mock_provider = MagicMock()
    mock_provider.complete = AsyncMock(return_value=json.dumps(mock_response))

    with patch("src.services.llm.factory.LLMFactory.get_provider", return_value=mock_provider), \
         patch("src.services.audit_agent.get_compiler_service") as mock_compiler, \
         patch("src.services.audit_agent.get_dsl_linter") as mock_linter, \
         patch("src.services.audit_agent.validate_audit", side_effect=_toll_gate_ok):

        mock_compiler.return_value.compile.return_value = {"success": True}
        mock_linter.return_value.lint.return_value = {"passed": True, "violations": []}

        code = "pragma cashscript ^0.13.0; contract OK() { function spend() { require(true); } }"
        report = await AuditAgent.audit(code)

        assert report.semantic_category == "none"
        assert len(report.issues) == 0
