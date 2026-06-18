"""Pytest entry for adversarial Semantic Judge V2 red-team scenarios."""

import pytest

from tests.adversarial_semantic_judge.runner import run_adversarial_scenario, run_all_adversarial
from tests.adversarial_semantic_judge.scenarios import ADVERSARIAL_SCENARIOS


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.mark.anyio
async def test_adversarial_suite_runs_all_scenarios():
    """Smoke test: adversarial runner completes for every scenario."""
    results = await run_all_adversarial()
    assert len(results) == len(ADVERSARIAL_SCENARIOS)
    ids = {r.scenario_id for r in results}
    assert ids == {s.scenario_id for s in ADVERSARIAL_SCENARIOS}


@pytest.mark.parametrize(
    "scenario_id",
    [s.scenario_id for s in ADVERSARIAL_SCENARIOS],
    ids=[s.scenario_id for s in ADVERSARIAL_SCENARIOS],
)
@pytest.mark.anyio
async def test_adversarial_scenario_runs(scenario_id: str):
    """Each adversarial scenario runs without error; see adversarial report for pass/fail."""
    scenario = next(s for s in ADVERSARIAL_SCENARIOS if s.scenario_id == scenario_id)
    result = await run_adversarial_scenario(scenario)
    assert result.scenario_id == scenario_id
    assert result.bundle_json
    assert result.judgment_json


@pytest.mark.anyio
async def test_v2_1_compliant_adversarial_meets_pass_target():
    """V2.1 prompt-compliant judgments should pass 18+ adversarial scenarios."""
    results = await run_all_adversarial(use_v2_1_compliant=True)
    passed = sum(1 for r in results if r.passed)
    assert passed >= 18, f"V2.1 compliant pass rate {passed}/{len(results)} below target 18"
