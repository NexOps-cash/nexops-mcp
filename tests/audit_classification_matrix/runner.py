"""Run audit classification matrix scenarios and return results."""

from __future__ import annotations

import json
from typing import List
from unittest.mock import AsyncMock, MagicMock, patch

from src.services.audit_agent import AuditAgent

from tests.audit_classification_matrix.scenarios import (
    SCENARIOS,
    ClassificationScenario,
    ScenarioResult,
    evaluate_scenario,
)


def _compile_ok(_code):
    return {"success": True}


async def run_scenario(scenario: ClassificationScenario) -> ScenarioResult:
    llm_payload = scenario.llm_payload or {
        "category": "SAFE",
        "exploit_severity": "n/a",
        "explanation": "",
        "confidence": 0.9,
        "business_logic_score": 8,
        "business_logic_notes": "",
    }
    provider = MagicMock()
    provider.complete = AsyncMock(return_value=json.dumps(llm_payload))

    with patch("src.services.llm.factory.LLMFactory.get_provider", return_value=provider), \
         patch("src.services.audit_agent.get_compiler_service", return_value=MagicMock(compile=_compile_ok)):
        report = await AuditAgent.audit(
            code=scenario.code,
            intent=scenario.intent,
            effective_mode=scenario.effective_mode,
            intent_model=scenario.intent_model,
        )

    return evaluate_scenario(report, scenario)


async def run_all_scenarios() -> List[ScenarioResult]:
    results: List[ScenarioResult] = []
    for scenario in SCENARIOS:
        results.append(await run_scenario(scenario))
    return results
