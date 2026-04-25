from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.models import IssueClass, Severity
from src.services.audit_agent import AuditAgent


AUTH_HEAD_VAULT = """
pragma cashscript ^0.13.0;

contract AuthHeadVault(bytes32 authorization) {
    function spend() {
        require(tx.outputs[0].tokenCategory == authorization);
    }
}
"""


def get_issue_ids(result):
    return [issue.rule_id for issue in result.issues]


def _safe_provider():
    provider = MagicMock()
    provider.complete = AsyncMock(
        return_value=(
            '{"category":"SAFE","exploit_severity":"n/a","explanation":"No semantic issue",'
            '"confidence":0.95,"business_logic_score":10,"business_logic_notes":"Clean"}'
        )
    )
    return provider


def _compile_ok(_code):
    return {"success": True, "error": None}


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.mark.anyio
async def test_auth_head_output_binding():
    with patch("src.services.audit_agent.get_compiler_service", return_value=MagicMock(compile=_compile_ok)), \
         patch("src.services.llm.factory.LLMFactory.get_provider", return_value=_safe_provider()):
        result = await AuditAgent.audit(AUTH_HEAD_VAULT, effective_mode="vault")

    issue_ids = get_issue_ids(result)
    assert "output_binding_missing" in issue_ids
    assert "LNC-001c" not in issue_ids
    assert not any("token_amount" in issue_id or "tokenAmount" in issue_id for issue_id in issue_ids)
    issue = next(i for i in result.issues if i.rule_id == "output_binding_missing")
    assert issue.severity == Severity.MEDIUM
    assert issue.issue_class == IssueClass.CONTEXTUAL


@pytest.mark.anyio
async def test_no_false_positive_suite():
    with patch("src.services.audit_agent.get_compiler_service", return_value=MagicMock(compile=_compile_ok)), \
         patch("src.services.llm.factory.LLMFactory.get_provider", return_value=_safe_provider()):
        result = await AuditAgent.audit(AUTH_HEAD_VAULT, effective_mode="vault")

    assert all(issue.issue_class.value != "false_positive" for issue in result.issues)
    issue_ids = get_issue_ids(result)
    assert "LNC-013" not in issue_ids
    assert "LNC-014" not in issue_ids
    assert "LNC-018" not in issue_ids
