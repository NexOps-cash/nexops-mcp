from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.models import IssueClass
from src.services.audit_agent import AuditAgent


FEE_MINTER = """
pragma cashscript ^0.13.0;

contract FeeMinter(bytes32 authorization, bytes32 token, bytes destination) {
    function mint() {
        require(tx.inputs[this.activeInputIndex].tokenCategory == authorization);
        require(tx.outputs[0].lockingBytecode == destination);
        bytes fee_category, bytes fee_next = tx.outputs[0].nftCommitment.split(32);
        bytes fee_amount = fee_next.slice(0, 8);
        require(fee_category != 0x);
        require(int(fee_amount) > 0);
    }
}
"""


def get_issue_ids(result):
    return [issue.rule_id for issue in result.issues]


def _tradeoff_provider():
    provider = MagicMock()
    provider.complete = AsyncMock(
        return_value=(
            '{"category":"DESIGN_TRADEOFF","exploit_severity":"n/a",'
            '"explanation":"Commitment routing details require human review",'
            '"confidence":0.8,"business_logic_score":6,'
            '"business_logic_notes":"Contextual semantic issue"}'
        )
    )
    return provider


def _compile_ok(_code):
    return {"success": True, "error": None}


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.mark.anyio
async def test_commitment_length_detected():
    with patch("src.services.audit_agent.get_compiler_service", return_value=MagicMock(compile=_compile_ok)), \
         patch("src.services.llm.factory.LLMFactory.get_provider", return_value=_tradeoff_provider()):
        result = await AuditAgent.audit(FEE_MINTER, effective_mode="minting")

    issue_ids = get_issue_ids(result)
    assert "commitment_length_missing" in issue_ids
    assert "LNC-013" not in issue_ids
    assert "LNC-018" not in issue_ids
    issue = next(i for i in result.issues if i.rule_id == "commitment_length_missing")
    assert issue.issue_class == IssueClass.REAL_ISSUE
    semantic_issue = next(i for i in result.issues if i.rule_id.startswith("semantic_"))
    assert semantic_issue.issue_class == IssueClass.CONTEXTUAL
