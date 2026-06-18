#!/usr/bin/env python3
"""
Generate docs/semantic_judge_v2_comparison_report.md — legacy vs V2 side-by-side.

Usage (from nexops-mcp/):
    python scripts/generate_semantic_judge_comparison_report.py
"""

from __future__ import annotations

import asyncio
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tests.audit_classification_matrix.runner import run_scenario  # noqa: E402
from tests.audit_classification_matrix.scenarios import SCENARIOS  # noqa: E402


def _semantic_issues(report) -> list:
    return [i for i in report.issues if i.source == "semantic" or i.rule_id.startswith("semantic_")]


async def main() -> int:
    rows: list[str] = []
    suite_stats: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    fp_eliminated = 0
    contradiction_count = 0
    uncertainty_count = 0

    for scenario in SCENARIOS:
        legacy_result = await run_scenario(scenario, v2=False)
        v2_result = await run_scenario(scenario, v2=True)

        legacy_report_issues = {i.rule_id: i for i in _semantic_issues(
            await _report_for(scenario, v2=False)
        )}
        v2_report_issues = {i.rule_id: i for i in _semantic_issues(
            await _report_for(scenario, v2=True)
        )}

        added = set(v2_report_issues) - set(legacy_report_issues)
        removed = set(legacy_report_issues) - set(v2_report_issues)
        if removed and any(
            legacy_report_issues[r].kind.value == "vulnerability"
            for r in removed
            if r in legacy_report_issues
        ):
            fp_eliminated += 1

        payload = scenario.llm_payload or {}
        finding = payload.get("finding") or {}
        if finding.get("contradicts_fact_ids"):
            contradiction_count += 1
        if finding.get("evidence_gaps") or finding.get("uncertainty_reason"):
            uncertainty_count += 1

        kind_changes = []
        for rid in set(legacy_report_issues) & set(v2_report_issues):
            l = legacy_report_issues[rid]
            v = v2_report_issues[rid]
            if l.kind != v.kind or l.severity != v.severity:
                kind_changes.append(
                    f"{rid}: {l.kind.value}/{l.severity.value} → {v.kind.value}/{v.severity.value}"
                )

        status = "OK" if legacy_result.passed and v2_result.passed else "REVIEW"
        rows.append(
            f"| {scenario.scenario_id} | {scenario.suite} | {status} | "
            f"{legacy_result.passed} | {v2_result.passed} | "
            f"{len(added)} | {len(removed)} | "
            f"{'; '.join(kind_changes) or '—'} |"
        )
        suite_stats[scenario.suite]["total"] += 1

    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    out = ROOT / "docs" / "semantic_judge_v2_comparison_report.md"
    content = f"""# Semantic Judge V2 Comparison Report

Generated: {now}

## Summary

| Metric | Value |
|--------|-------|
| Scenarios | {len(SCENARIOS)} |
| False positive eliminations (VULNERABILITY removed) | {fp_eliminated} |
| V2 payloads with contradicts_fact_ids | {contradiction_count} |
| V2 payloads with uncertainty fields | {uncertainty_count} |

## Per-scenario diff

| ID | Suite | Status | Legacy PASS | V2 PASS | Findings added | Findings removed | Kind/severity changes |
|----|-------|--------|-------------|---------|----------------|------------------|----------------------|
"""
    content += "\n".join(rows)
    content += "\n"
    out.write_text(content, encoding="utf-8")
    print(f"Wrote {out}")
    return 0


async def _report_for(scenario, *, v2: bool):
    from tests.audit_classification_matrix.runner import run_scenario
    from src.services.audit_agent import AuditAgent
    import json
    import os
    from unittest.mock import AsyncMock, MagicMock, patch
    from tests.audit_classification_matrix.runner import _payload_for_scenario, _compile_ok

    llm_payload = _payload_for_scenario(scenario, v2=v2)
    provider = MagicMock()
    provider.complete = AsyncMock(return_value=json.dumps(llm_payload))
    env_patch = {"SEMANTIC_JUDGE_V2": "1" if v2 else "0"}
    with patch.dict(os.environ, env_patch, clear=False), \
         patch("src.services.llm.factory.LLMFactory.get_provider", return_value=provider), \
         patch("src.services.audit_agent.get_compiler_service", return_value=MagicMock(compile=_compile_ok)):
        return await AuditAgent.audit(
            code=scenario.code,
            intent=scenario.intent,
            effective_mode=scenario.effective_mode,
            intent_model=scenario.intent_model,
        )


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
