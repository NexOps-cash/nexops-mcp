"""Pytest wrapper for audit classification matrix scenarios."""

import pytest

from tests.audit_classification_matrix.runner import run_scenario
from tests.audit_classification_matrix.scenarios import SCENARIOS


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.mark.anyio
@pytest.mark.parametrize(
    "scenario",
    SCENARIOS,
    ids=[s.scenario_id for s in SCENARIOS],
)
async def test_classification_matrix(scenario):
    result = await run_scenario(scenario)
    assert result.passed, (
        f"Scenario {result.scenario_id} failed: "
        + "; ".join(result.mismatches)
        + f" | issues: {result.all_issue_summaries}"
    )
