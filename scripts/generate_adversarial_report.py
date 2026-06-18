#!/usr/bin/env python3
"""Generate docs/semantic_judge_v2_adversarial_report.md from adversarial scenarios."""

from __future__ import annotations

import asyncio
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.models import FindingKind  # noqa: E402
from tests.adversarial_semantic_judge.runner import run_all_adversarial  # noqa: E402


def _truncate_json(text: str, limit: int = 1200) -> str:
    if len(text) <= limit:
        return text
    return text[: limit - 3] + "..."


def _expected_kinds_str(kinds: set[FindingKind]) -> str:
    return ", ".join(sorted(k.value for k in kinds)) if kinds else "none"


def _classify_failure(r, scenario) -> tuple[list[str], list[str], list[str], list[str]]:
    """Return (false_positives, false_negatives, misclassifications, confidence_inflation)."""
    false_positives: list[str] = []
    false_negatives: list[str] = []
    misclassifications: list[str] = []
    confidence_inflation: list[str] = []

    if r.passed:
        return false_positives, false_negatives, misclassifications, confidence_inflation

    gt = r.ground_truth.lower()
    kind = r.final_kind or "none"
    expects_vuln = FindingKind.VULNERABILITY in scenario.ground_truth_kinds
    forbids_vuln = FindingKind.VULNERABILITY in scenario.forbidden_kinds

    if kind == "vulnerability" and forbids_vuln:
        false_positives.append(
            f"{r.scenario_id}: classified as VULNERABILITY despite non-exploit ground truth "
            f"(confidence={r.confidence_score}, contradicts={r.contradicts_fact_ids})"
        )
    elif expects_vuln and kind in ("operational_risk", "design_trade_off", "observation", "deployment_requirement"):
        false_negatives.append(
            f"{r.scenario_id}: downgraded real security issue to {kind} "
            f"(adversarial judgment minimized attacker_gain/value_impact)"
        )

    for f in r.failures:
        if "Confidence" in f and "exceeds cap" in f:
            confidence_inflation.append(
                f"{r.scenario_id}: confidence={r.confidence_score} exceeds cap "
                f"(contradicts={r.contradicts_fact_ids}, gaps={r.evidence_gaps})"
            )
        elif "Expected contradicts_fact_ids" in f:
            misclassifications.append(
                f"{r.scenario_id}: contradiction guard missed fact bundle conflict"
            )
        elif "not in ground truth" in f and kind != "vulnerability":
            if not any(r.scenario_id in x for x in false_negatives):
                misclassifications.append(f"{r.scenario_id}: {f}")

    return false_positives, false_negatives, misclassifications, confidence_inflation


async def main() -> int:
    results = await run_all_adversarial()
    passed = sum(1 for r in results if r.passed)
    failed = len(results) - passed

    all_fp: list[str] = []
    all_fn: list[str] = []
    all_misc: list[str] = []
    all_conf: list[str] = []

    lines: list[str] = [
        "# Semantic Security Judge V2 — Adversarial Validation Report",
        "",
        f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
        "",
        "## Executive summary",
        "",
        "| Metric | Count |",
        "|--------|-------|",
        f"| Scenarios | {len(results)} |",
        f"| V2 handled correctly (PASS) | {passed} |",
        f"| V2 weakness exposed (FAIL) | {failed} |",
        "",
        "PASS = guards + policy + deterministic layers produced acceptable outcome against adversarial LLM input.",
        "FAIL = red-team found misclassification, missing telemetry, or confidence abuse.",
        "",
        "### Scenario scorecard",
        "",
        "| ID | Category | Pass | Expected kind(s) | Actual kind | Confidence | Contradicts |",
        "|----|----------|------|------------------|-------------|------------|-------------|",
    ]

    for r in results:
        from tests.adversarial_semantic_judge.scenarios import ADVERSARIAL_SCENARIOS

        scenario = next(s for s in ADVERSARIAL_SCENARIOS if s.scenario_id == r.scenario_id)
        expected = _expected_kinds_str(scenario.ground_truth_kinds)
        status = "PASS" if r.passed else "FAIL"
        contra = ", ".join(r.contradicts_fact_ids) if r.contradicts_fact_ids else "—"
        conf = f"{r.confidence_score:.2f}" if r.confidence_score is not None else "—"
        lines.append(
            f"| {r.scenario_id} | {r.category} | {status} | {expected} | {r.final_kind or 'none'} | {conf} | {contra} |"
        )

        fp, fn, misc, conf_inf = _classify_failure(r, scenario)
        all_fp.extend(fp)
        all_fn.extend(fn)
        all_misc.extend(misc)
        all_conf.extend(conf_inf)

    lines.append("")

    for r in results:
        from tests.adversarial_semantic_judge.scenarios import ADVERSARIAL_SCENARIOS

        scenario = next(s for s in ADVERSARIAL_SCENARIOS if s.scenario_id == r.scenario_id)
        expected = _expected_kinds_str(scenario.ground_truth_kinds)
        status = "PASS" if r.passed else "**FAIL**"
        lines.extend(
            [
                f"## {r.scenario_id} — {r.category} ({status})",
                "",
                "### 1. Contract intent",
                r.intent,
                "",
                "### 2. Contract behavior",
                r.behavior,
                "",
                "### 3. AuditFactBundle (excerpt)",
                "```json",
                _truncate_json(r.bundle_json),
                "```",
                "",
                "### 4. Adversarial semantic judgment",
                "```json",
                _truncate_json(r.judgment_json, 800),
                "```",
                "",
                "### 5. Final classification",
                "",
                "| Field | Value |",
                "|-------|-------|",
                f"| Expected kind(s) | {expected} |",
                f"| Actual kind | {r.final_kind or 'none'} |",
                f"| Pass/fail | {'PASS' if r.passed else 'FAIL'} |",
                f"| Severity | {r.final_severity or 'n/a'} |",
                f"| Triggerability | {r.final_triggerability or 'n/a'} |",
                f"| Confidence level | {r.final_confidence or 'n/a'} |",
                f"| Confidence score | {r.confidence_score if r.confidence_score is not None else 'n/a'} |",
                f"| Semantic rule_id | {r.semantic_rule_id or 'none'} |",
                f"| Deterministic findings | {', '.join(r.deterministic_findings) or 'none'} |",
                "",
                "### 6. Correctness",
                "",
                f"**Ground truth:** {r.ground_truth}",
                "",
                f"**Classification correct:** {'Yes' if r.passed else 'No — weakness exposed'}",
                "",
                "**Telemetry**",
                f"- contradicts_fact_ids: {r.contradicts_fact_ids or '[]'}",
                f"- evidence_gaps: {r.evidence_gaps or '[]'}",
                f"- uncertainty_reason: {r.uncertainty_reason or '(empty)'}",
                "",
            ]
        )
        if r.failures:
            lines.append("**Failures:**")
            for f in r.failures:
                lines.append(f"- {f}")
            lines.append("")

    # Deduplicate summary lists
    all_fp = list(dict.fromkeys(all_fp))
    all_fn = list(dict.fromkeys(all_fn))
    all_misc = list(dict.fromkeys(all_misc))
    all_conf = list(dict.fromkeys(all_conf))

    lines.extend(
        [
            "## Findings summary",
            "",
            "### 1. False positives found",
            "",
        ]
    )
    lines.extend([f"- {x}" for x in all_fp] or ["- None"])
    lines.extend(["", "### 2. False negatives found", ""])
    lines.extend([f"- {x}" for x in all_fn] or ["- None"])
    lines.extend(["", "### 3. Misclassifications", ""])
    lines.extend([f"- {x}" for x in all_misc] or ["- None"])
    lines.extend(["", "### 4. Confidence inflation cases", ""])
    lines.extend([f"- {x}" for x in all_conf] or ["- None"])
    lines.extend(
        [
            "",
            "### 5. Recommended fixes (no code changes in this pass)",
            "",
            "1. **Contradiction → kind downgrade:** When `contradicts_fact_ids` is non-empty after guards, cap confidence *and* suppress VULNERABILITY (map to OBSERVATION or reject finding). AUTH-2, CONTRA-1, CONF-2 all cap confidence but still emit VULNERABILITY.",
            "2. **AG-1 / small-value redirects:** Policy trusts LLM `attacker_gain=false` + `value_impact=none` → OPERATIONAL_RISK. Add policy path: unconstrained output + attacker-controlled destination ⇒ minimum INVARIANT_GAP even for dust.",
            "3. **AG-2 / destructive burns:** Unauthorized burn with `attacker_gain=false` maps to DESIGN_TRADE_OFF. Treat unauthorized destructive capability as authorization_impact regardless of profit.",
            "4. **CONTRA-2 / CONTRA-3:** Extend contradiction guard beyond auth-phrase patterns to ENFORCED `inv.value_conservation` and `inv.recipient_binding` when judge claims leak/redirect.",
            "5. **TRUST-1/2/3:** Treasury/oracle/off-chain operator scenarios still map to VULNERABILITY when adversarial judgment sets `attacker_gain=true` without matching `trust_assumption`. Policy should consult bundle trust signals and intent keywords.",
            "6. **INTENT-3 / BCH-3:** Over-escalation to VULNERABILITY on business metadata and signed mutable NFT paths; bundle `cap.has_signature_auth` + intent tier should gate escalation.",
            "7. **CONF-3:** Uncertainty cap via `evidence_gaps` works (PASS); extend same cap when `fact_refs` empty with high confidence.",
            "8. **MIXED-1/2:** Deterministic layer compensates for single semantic slot (PASS today); document as architectural limit until multi-finding Phase 2.",
            "",
        ]
    )

    out = ROOT / "docs" / "semantic_judge_v2_adversarial_report.md"
    out.write_text("\n".join(lines), encoding="utf-8")
    print(f"Wrote {out} ({passed}/{len(results)} PASS, {failed} weaknesses exposed)")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
