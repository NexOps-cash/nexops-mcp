"""Run audit classification matrix scenarios and return results."""

from __future__ import annotations

import json
import os
from typing import List
from unittest.mock import AsyncMock, MagicMock, patch

from src.services.audit_agent import AuditAgent

from tests.audit_classification_matrix.scenarios import (
    SCENARIOS,
    ClassificationScenario,
    ScenarioResult,
    _safe_llm_legacy,
    evaluate_scenario,
)


def _compile_ok(_code):
    return {"success": True}


def _payload_for_scenario(scenario: ClassificationScenario, *, v2: bool) -> dict:
    if v2:
        return scenario.llm_payload or {
            "judge_version": "2.0",
            "verdict": "no_issue",
            "intent_fidelity_score": 8,
            "intent_fidelity_notes": "",
        }
    if scenario.legacy_llm_payload:
        return scenario.legacy_llm_payload
    return _safe_llm_legacy()


async def run_scenario(
    scenario: ClassificationScenario,
    *,
    v2: bool | None = None,
) -> ScenarioResult:
    use_v2 = v2 if v2 is not None else os.environ.get("SEMANTIC_JUDGE_V2", "1") != "0"
    llm_payload = _payload_for_scenario(scenario, v2=use_v2)
    provider = MagicMock()
    provider.complete = AsyncMock(return_value=json.dumps(llm_payload))

    env_patch = {"SEMANTIC_JUDGE_V2": "1" if use_v2 else "0"}
    with patch.dict(os.environ, env_patch, clear=False), \
         patch("src.services.llm.factory.LLMFactory.get_provider", return_value=provider), \
         patch("src.services.audit_agent.get_compiler_service", return_value=MagicMock(compile=_compile_ok)):
        report = await AuditAgent.audit(
            code=scenario.code,
            intent=scenario.intent,
            effective_mode=scenario.effective_mode,
            intent_model=scenario.intent_model,
        )

    return evaluate_scenario(report, scenario)


async def run_all_scenarios(*, v2: bool | None = None) -> List[ScenarioResult]:
    results: List[ScenarioResult] = []
    for scenario in SCENARIOS:
        results.append(await run_scenario(scenario, v2=v2))
    return results
