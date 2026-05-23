"""
Run the 8-case CashTokens semantic benchmark suite (free synthesis).

Usage:
  python scripts/run_semantic_benchmark.py --all
  python scripts/run_semantic_benchmark.py --all --resume
  python scripts/run_semantic_benchmark.py --ids semantic_003
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
CHECKPOINT = ROOT / "benchmark/results/semantic_checkpoint.json"

CASE_ORDER = [
    "semantic_001",
    "semantic_002",
    "semantic_003",
    "semantic_004",
    "semantic_005",
    "semantic_006",
    "semantic_007",
    "semantic_008",
]


def _load_checkpoint() -> dict:
    if CHECKPOINT.exists():
        return json.loads(CHECKPOINT.read_text(encoding="utf-8"))
    return {"completed": {}, "run_id": None}


def _save_checkpoint(data: dict) -> None:
    CHECKPOINT.parent.mkdir(parents=True, exist_ok=True)
    CHECKPOINT.write_text(json.dumps(data, indent=2), encoding="utf-8")
    sys.stdout.flush()


async def run_one_case(case_id: str, run_id: str) -> dict:
    from benchmark.runner import BenchmarkRunner
    from benchmark.evaluator import BenchmarkEvaluator
    from benchmark.schemas import CaseResult

    runner = BenchmarkRunner(str(SUITE), case_ids=[case_id])
    runner.load_suite()
    if not runner.cases:
        raise ValueError(f"Case not found: {case_id}")

    evaluator = BenchmarkEvaluator()
    case = runner.cases[0]
    print(f"\n>>> [{case_id}] starting...", flush=True)
    result = await evaluator.evaluate(case, disable_golden=True)
    row = {
        "id": result.id,
        "compile_pass": result.compile_pass,
        "converged": result.converged,
        "intent_coverage": result.intent_coverage,
        "failure_layer": result.failure_layer,
        "latency_seconds": result.latency_seconds,
    }
    status = "PASS" if result.converged else ("COMPILE" if result.compile_pass else "FAIL")
    print(
        f">>> [{case_id}] {status} | compile={result.compile_pass} "
        f"converged={result.converged} coverage={result.intent_coverage:.0%}",
        flush=True,
    )
    return row


async def run_cases(case_ids: list[str], resume: bool) -> dict:
    cp = _load_checkpoint()
    if not resume and not cp.get("completed"):
        cp = {"completed": {}, "run_id": None}
    run_id = cp.get("run_id") or f"bench_{datetime.now().strftime('%Y%m%d_%H%M')}_sem"
    cp["run_id"] = run_id
    results: list[dict] = []

    for cid in case_ids:
        if resume and cid in cp.get("completed", {}):
            row = cp["completed"][cid]
            print(f">>> [{cid}] skipped (checkpoint)", flush=True)
            results.append(row)
            continue
        try:
            row = await run_one_case(cid, run_id)
        except Exception as exc:
            row = {
                "id": cid,
                "compile_pass": False,
                "converged": False,
                "intent_coverage": 0.0,
                "failure_layer": str(exc)[:80],
                "latency_seconds": 0.0,
            }
            print(f">>> [{cid}] ERROR: {exc}", flush=True)
        cp.setdefault("completed", {})[cid] = row
        _save_checkpoint(cp)
        results.append(row)

    all_rows = [cp["completed"][cid] for cid in CASE_ORDER if cid in cp.get("completed", {})]
    tier_b = sum(1 for r in all_rows if r.get("converged"))
    report = {
        "run_id": run_id,
        "results": all_rows,
        "tier_b": tier_b,
        "total": len(all_rows),
    }
    out = ROOT / "benchmark/results" / f"{run_id}.json"
    out.write_text(json.dumps(report, indent=2), encoding="utf-8")
    return report


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
    tier_b = report.get("tier_b", 0)
    total = report.get("total", len(report.get("results", [])))
    lines.append("")
    lines.append(f"**Tier B (converged): {tier_b}/{total}** (gate: ≥6/8)")
    lines.append("")

    DOC.parent.mkdir(parents=True, exist_ok=True)
    if not DOC.exists():
        DOC.write_text(
            "# CashTokens semantic benchmark runs\n\n"
            "Free synthesis (`disable_golden=True`). Eight in-scope cases only.\n",
            encoding="utf-8",
        )
    with open(DOC, "a", encoding="utf-8") as f:
        f.write("\n".join(lines))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--all", action="store_true", help="Run all 8 in-scope cases")
    parser.add_argument("--resume", action="store_true", help="Skip cases in checkpoint")
    parser.add_argument("--ids", nargs="*", help="Specific case ids")
    parser.add_argument("--fresh", action="store_true", help="Clear checkpoint before run")
    parser.add_argument(
        "--retry-failed",
        action="store_true",
        help="Re-run cases that did not converge (uses checkpoint)",
    )
    args = parser.parse_args()

    if args.fresh and CHECKPOINT.exists():
        CHECKPOINT.unlink()

    if args.ids:
        ids = args.ids
    elif args.retry_failed:
        cp = _load_checkpoint()
        ids = [
            cid for cid, row in cp.get("completed", {}).items()
            if not row.get("converged")
        ] or CASE_ORDER
        for cid in ids:
            cp.get("completed", {}).pop(cid, None)
        _save_checkpoint(cp)
    elif args.all:
        ids = CASE_ORDER
    else:
        parser.error("Use --all, --retry-failed, or --ids semantic_001 ...")

    report = asyncio.run(run_cases(ids, resume=args.resume and not args.retry_failed))
    print(
        json.dumps(
            {
                "run_id": report["run_id"],
                "tier_b": report["tier_b"],
                "total": report["total"],
                "checkpoint": str(CHECKPOINT),
            },
            indent=2,
        ),
        flush=True,
    )
    _append_doc(report)


if __name__ == "__main__":
    main()
