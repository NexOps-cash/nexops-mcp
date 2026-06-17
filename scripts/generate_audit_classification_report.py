#!/usr/bin/env python3
"""
Generate docs/audit_classification_validation_report.md from the classification matrix.

Usage (from nexops-mcp/):
    python scripts/generate_audit_classification_report.py
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

from tests.audit_classification_matrix.runner import run_all_scenarios  # noqa: E402
from tests.audit_classification_matrix.scenarios import SCENARIOS  # noqa: E402


def _status(passed: bool) -> str:
    return "PASS" if passed else "FAIL"


async def main() -> int:
    results = await run_all_scenarios()
    passed = sum(1 for r in results if r.passed)
    failed = len(results) - passed

    by_suite: dict = defaultdict(list)
    for r in results:
        by_suite[r.suite].append(r)

    lines = [
        "# Audit Classification Validation Report",
        "",
        f"**Generated:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
        f"**Scenarios:** {len(results)} | **Passed:** {passed} | **Failed:** {failed}",
        "",
        "## Summary",
        "",
    ]

    if failed == 0:
        lines.append(
            "All classification matrix scenarios passed. Payroll-style false positives "
            "are suppressed; deterministic intent gaps classify as `INVARIANT_GAP` / `PROVEN`."
        )
    else:
        lines.append(
            f"**{failed} scenario(s) failed** — review mismatches below before merge/push."
        )

    lines.extend(
        [
            "",
            "## Results by suite",
            "",
            "| Suite | Pass | Fail | Total |",
            "|-------|------|------|-------|",
        ]
    )
    for suite, items in sorted(by_suite.items()):
        s_pass = sum(1 for i in items if i.passed)
        lines.append(f"| {suite} | {s_pass} | {len(items) - s_pass} | {len(items)} |")

    lines.extend(["", "## Scenario detail", ""])

    for scenario, result in zip(SCENARIOS, results):
        status = "PASS" if result.passed else "FAIL"
        lines.append(f"### {scenario.scenario_id} — {scenario.suite} ({status})")
        lines.append("")
        lines.append(f"**Description:** {scenario.description}")
        lines.append("")
        lines.append(f"**Expected:** {result.expected_summary}")
        lines.append("")
        if result.primary_rule_id or result.actual_kind:
            lines.append("| Field | Actual |")
            lines.append("|-------|--------|")
            if result.primary_rule_id:
                lines.append(f"| rule_id | `{result.primary_rule_id}` |")
            if result.actual_kind:
                lines.append(f"| FindingKind | `{result.actual_kind}` |")
                lines.append(f"| Severity | `{result.actual_severity}` |")
                lines.append(f"| Triggerability | `{result.actual_triggerability}` |")
                lines.append(f"| Confidence | `{result.actual_confidence}` |")
                lines.append(f"| Provenance | `{result.actual_provenance}` |")
                lines.append(f"| Title | {result.actual_title} |")
            lines.append("")
        if result.mismatches:
            lines.append("**Mismatches:**")
            for m in result.mismatches:
                lines.append(f"- {m}")
            lines.append("")
        if result.all_issue_summaries:
            lines.append("<details><summary>All findings</summary>")
            lines.append("")
            for s in result.all_issue_summaries:
                lines.append(f"- `{s}`")
            lines.append("")
            lines.append("</details>")
            lines.append("")

    # Remaining risks section
    failures = [r for r in results if not r.passed]
    lines.extend(["## Remaining false positives / severity inflation", ""])
    if failures:
        for r in failures:
            lines.append(
                f"- **{r.scenario_id}**: {', '.join(r.mismatches) or 'classification mismatch'}"
            )
    else:
        lines.append(
            "No matrix failures detected. Known limitations (outside this matrix):"
        )
        lines.append(
            "- `UNKNOWN` triggerability on deterministic paths may still default permissive in `is_exploitable()`"
        )
        lines.append(
            "- Intent fixed-amount detection is text-heuristic; proportional splits without literal amounts are not flagged"
        )
        lines.append(
            "- Semantic `rule_id` may retain legacy `semantic_major_protocol_flaw` label while kind/severity are policy-correct"
        )
        lines.append(
            "- Token-based payroll fixtures may emit incidental `unrestricted_token_transfer` (CRITICAL) from deterministic detectors; primary scenario assertions still pass but real audits should use cleaner fixtures or mode profiles"
        )

    lines.extend(
        [
            "",
            "## Forbidden classification checks",
            "",
            "Matrix enforces, per scenario:",
            "- Forbidden `FindingKind` (e.g. `VULNERABILITY` on treasury underfunding)",
            "- Forbidden severities (`CRITICAL` / `HIGH` on non-attacker findings)",
            "- Forbidden title substrings (`Security`, `Major Protocol Flaw`)",
            "- `PROVEN` confidence only on deterministic findings",
            "- `max_severity` cap for `UNKNOWN` / non-attacker cases",
            "",
            "---",
            "",
            f"*Generated by `scripts/generate_audit_classification_report.py` from {len(SCENARIOS)} scenarios.*",
        ]
    )

    out_path = ROOT / "docs" / "audit_classification_validation_report.md"
    out_path.write_text("\n".join(lines), encoding="utf-8")
    print(f"Wrote {out_path} ({passed}/{len(results)} passed)")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
