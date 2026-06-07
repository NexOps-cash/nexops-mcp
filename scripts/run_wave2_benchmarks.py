"""
Run Wave 2 benchmark suites and print gate summary.

Prefer small subsets to save OpenRouter credits:
  python scripts/run_wave2_benchmarks.py --suite 2A_ft_mint --ids ct_ft_mint_001
  python -m benchmark.runner benchmark/suites/cashtokens_ft_mint.yaml --ids ct_ft_mint_001
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

WAVE2_SUITES = [
    ("2A_ft_mint", "benchmark/suites/cashtokens_ft_mint.yaml"),
    ("2B_invalid_negative", "benchmark/suites/cashtokens_invalid_negative.yaml"),
    ("2C_audit_parity", "benchmark/suites/cashtokens_audit_parity.yaml"),
    ("2D_validation", "benchmark/suites/cashtokens_validation.yaml"),
]


async def run_suite(name: str, path: str, case_ids: list[str] | None = None) -> dict:
    from benchmark.runner import BenchmarkRunner

    runner = BenchmarkRunner(str(ROOT / path), case_ids=case_ids or [])
    runner.load_suite()
    report = await runner.run_all(disable_golden=True)
    results = report.results
    tag_by_id = {c.id: set(c.tags or []) for c in runner.cases}

    def _tags(r):
        return tag_by_id.get(r.id, set())

    positive = [r for r in results if "failure" not in _tags(r) and "vulnerability" not in _tags(r)]
    negative = [r for r in results if "failure" in _tags(r) or "vulnerability" in _tags(r)]

    pos_ok = sum(1 for r in positive if r.converged and r.compile_pass)
    neg_ok = sum(1 for r in negative if not r.converged)

    return {
        "suite": name,
        "path": path,
        "run_id": report.run_id,
        "total": len(results),
        "positive_expected_converge": len(positive),
        "positive_converged": pos_ok,
        "negative_expected_fail": len(negative),
        "negative_non_converged": neg_ok,
        "cases": [
            {
                "id": r.id,
                "converged": r.converged,
                "compile_pass": r.compile_pass,
                "critical_missing": getattr(r, "critical_missing", None) or [],
                "tags": list(_tags(r)),
            }
            for r in results
        ],
    }


async def main() -> int:
    import os

    parser = argparse.ArgumentParser(description="Run Wave 2 benchmark suites (subset-friendly)")
    parser.add_argument(
        "--suite",
        action="append",
        default=[],
        help="Suite key(s): 2A_ft_mint, 2B_invalid_negative, 2C_audit_parity, 2D_validation",
    )
    parser.add_argument("--ids", default="", help="Comma-separated case ids to run")
    args = parser.parse_args()

    if not os.getenv("OPENROUTER_API_KEY"):
        print("ERROR: OPENROUTER_API_KEY not set")
        return 1

    suite_map = dict(WAVE2_SUITES)
    selected = WAVE2_SUITES
    if args.suite:
        selected = []
        for key in args.suite:
            if key not in suite_map:
                print(f"ERROR: unknown suite {key!r}; choose from {list(suite_map)}")
                return 1
            selected.append((key, suite_map[key]))

    case_ids = [x.strip() for x in args.ids.split(",") if x.strip()]

    sections = []
    all_ok = True
    for name, path in selected:
        print(f"\n=== Running {name}: {path} ===", flush=True)
        if case_ids:
            print(f"    case ids: {', '.join(case_ids)}", flush=True)
        sec = await run_suite(name, path, case_ids=case_ids or None)
        sections.append(sec)
        pos_gate = sec["positive_converged"] == sec["positive_expected_converge"]
        neg_gate = sec["negative_non_converged"] == sec["negative_expected_fail"]
        gate = pos_gate and neg_gate
        all_ok = all_ok and gate
        print(
            f"  positive: {sec['positive_converged']}/{sec['positive_expected_converge']} converged | "
            f"negative: {sec['negative_non_converged']}/{sec['negative_expected_fail']} non-converged | "
            f"gate={'PASS' if gate else 'FAIL'}",
            flush=True,
        )
        for c in sec["cases"]:
            status = "OK" if c["converged"] else "FAIL"
            tags = set(c.get("tags") or [])
            if "failure" in tags or "vulnerability" in tags:
                status = "OK" if not c["converged"] else "BAD(converged)"
            print(f"    {c['id']}: compile={c['compile_pass']} {status}", flush=True)

    out = ROOT / "benchmark/results/wave2_benchmark_summary.json"
    payload = {
        "generated": datetime.now(timezone.utc).isoformat(),
        "all_gates_pass": all_ok,
        "suites": sections,
    }
    out.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print(f"\nWrote {out}")
    print(f"Overall: {'PASS' if all_ok else 'FAIL'}")
    return 0 if all_ok else 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
