from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.models import IssueClass
from src.services.audit_agent import AuditAgent


SIMPLE_VAULT = """
pragma cashscript ^0.13.0;

contract SimpleVault(pubkey owner) {
    function spend(sig ownerSig) {
        require(checkSig(ownerSig, owner));
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
async def test_simple_vault_clean():
    with patch("src.services.audit_agent.get_compiler_service", return_value=MagicMock(compile=_compile_ok)), \
         patch("src.services.llm.factory.LLMFactory.get_provider", return_value=_safe_provider()):
        result = await AuditAgent.audit(SIMPLE_VAULT, effective_mode="vault")

    issue_ids = get_issue_ids(result)
    assert "index_underflow" not in issue_ids
    assert not any("token_amount" in issue_id or "tokenAmount" in issue_id for issue_id in issue_ids)
    assert not any(issue_id.startswith("LNC-") for issue_id in issue_ids)
    assert result.total_score >= 80
    assert all(issue.issue_class != IssueClass.REAL_ISSUE for issue in result.issues)


@pytest.mark.anyio
async def test_no_false_positive_suite():
    contracts = [SIMPLE_VAULT]
    with patch("src.services.audit_agent.get_compiler_service", return_value=MagicMock(compile=_compile_ok)), \
         patch("src.services.llm.factory.LLMFactory.get_provider", return_value=_safe_provider()):
        for code in contracts:
            result = await AuditAgent.audit(code, effective_mode="vault")
            assert all(issue.issue_class.value != "false_positive" for issue in result.issues)
            assert "LNC-013" not in get_issue_ids(result)
            assert "LNC-014" not in get_issue_ids(result)
            assert "LNC-018" not in get_issue_ids(result)
