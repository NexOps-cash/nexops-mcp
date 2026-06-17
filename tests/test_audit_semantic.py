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


@pytest.mark.anyio
async def test_semantic_issue_injection():
    """Verify that semantic risks identified by LLM are injected into issues list."""

    mock_response = {
        "category": "funds_unspendable",
        "exploit_severity": "n/a",
        "explanation": "The contract has no spending path, funds are effectively burnt.",
        "confidence": 0.95,
        "business_logic_score": 0,
        "business_logic_notes": "Add a spending function with require() guards to allow the owner to withdraw funds.",
    }

    mock_provider = MagicMock()
    mock_provider.complete = AsyncMock(return_value=json.dumps(mock_response))

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
        assert issue.description == mock_response["explanation"]
        assert issue.recommendation == mock_response["business_logic_notes"]
        assert issue.can_fix is False


@pytest.mark.anyio
async def test_semantic_none_no_injection():
    """Verify that 'none' category does NOT inject an issue."""
    mock_response = {
        "category": "SAFE",
        "exploit_severity": "n/a",
        "explanation": "Logic looks sound.",
        "confidence": 1.0,
        "business_logic_score": 10,
        "business_logic_notes": "Good implementation.",
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
