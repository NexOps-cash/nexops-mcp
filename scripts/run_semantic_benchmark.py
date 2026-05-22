"""
Run the 11-case CashTokens semantic benchmark suite (free synthesis).

Usage:
  python scripts/run_semantic_benchmark.py --all
  python scripts/run_semantic_benchmark.py --ids semantic_002 semantic_005
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from dotenv import load_dotenv

load_dotenv(ROOT / ".env")

SUITE = ROOT / "benchmark/suites/cashtokens_semantic.yaml"
DOC = ROOT / "docs/cashtokens_semantic_runs.md"


async def run_cases(case_ids: list[str] | None) -> dict:
    from benchmark.runner import BenchmarkRunner

    runner = BenchmarkRunner(str(SUITE))
    runner.load_suite()
    if case_ids:
        runner.cases = [c for c in runner.cases if c.id in case_ids]
    report = await runner.run_all(disable_golden=True)
    return report.model_dump()


def _append_doc(report: dict) -> None:
    ts = datetime.now(timezone.utc).isoformat()
    lines = [
        f"\n## Run {report.get('run_id', 'unknown')} — {ts}\n",
        "",
        "| Case | Compile | Converged | Coverage |",
        "|------|---------|-----------|----------|",
    ]
    for r in report.get("results", []):
        lines.append(
            f"| {r['id']} | {'yes' if r['compile_pass'] else 'no'} | "
            f"{'yes' if r['converged'] else 'no'} | {r.get('intent_coverage', 0):.0%} |"
        )
    tier_b = sum(1 for r in report.get("results", []) if r.get("converged"))
    total = len(report.get("results", []))
    lines.append("")
    lines.append(f"**Tier B (converged): {tier_b}/{total}** (gate: ≥7/11)")
    lines.append("")

    DOC.parent.mkdir(parents=True, exist_ok=True)
    if not DOC.exists():
        DOC.write_text(
            "# CashTokens semantic benchmark runs\n\n"
            "Free synthesis (`disable_golden=True`). LP (#10) excluded.\n",
            encoding="utf-8",
        )
    with open(DOC, "a", encoding="utf-8") as f:
        f.write("\n".join(lines))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--all", action="store_true", help="Run all 11 cases")
    parser.add_argument("--ids", nargs="*", help="Specific case ids")
    args = parser.parse_args()

    ids = None if args.all or not args.ids else args.ids
    if not args.all and not args.ids:
        parser.error("Use --all or --ids semantic_001 ...")

    report = asyncio.run(run_cases(ids))
    out = ROOT / "benchmark/results" / f"{report['run_id']}.json"
    print(json.dumps({"run_id": report["run_id"], "path": str(out), "tier_b": sum(
        1 for r in report.get("results", []) if r.get("converged")
    )}, indent=2))
    _append_doc(report)


if __name__ == "__main__":
    main()
