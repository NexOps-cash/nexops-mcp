#!/usr/bin/env python3
"""
Run audit benchmark suite — NO OpenRouter / LLM calls.

Usage:
  python scripts/run_benchmark_suite.py --mode fast
  python scripts/run_benchmark_suite.py --mode standard --registry docs/benchmark_registry_executable.json
  python scripts/run_benchmark_suite.py --dry-run
  python scripts/run_benchmark_suite.py --family hashlock --ids bench_hashlock_001
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from benchmark.audit_eval.modes import EvaluationMode
from benchmark.audit_eval.runner import run_registry

DEFAULT_REGISTRY = ROOT / "docs" / "benchmark_registry_executable.json"
FALLBACK_REGISTRY = ROOT / "docs" / "benchmark_registry.json"


def main() -> int:
    parser = argparse.ArgumentParser(description="Run audit benchmarks (no LLM)")
    parser.add_argument(
        "--mode",
        choices=["fast", "standard", "full"],
        default="standard",
        help="fast=detectors only; standard=+invariants+policy fixtures; full=reserved (no LLM)",
    )
    parser.add_argument("--registry", type=Path, default=None)
    parser.add_argument("--dry-run", action="store_true", help="Check contract resolvability only")
    parser.add_argument("--family", type=str, default=None)
    parser.add_argument("--ids", nargs="*", default=None)
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument("--output", type=Path, default=None, help="Write JSON results to file")
    parser.add_argument(
        "--include-coverage-probes",
        action="store_true",
        help="Count coverage_probe failures as expected gaps, not suite failure",
    )
    args = parser.parse_args()

    if args.mode == "full":
        print("WARNING: full mode does not invoke LLM in this runner; treated as standard.", file=sys.stderr)
        mode = EvaluationMode.STANDARD
    else:
        mode = EvaluationMode(args.mode)

    reg_path = args.registry or (DEFAULT_REGISTRY if DEFAULT_REGISTRY.is_file() else FALLBACK_REGISTRY)
    registry = json.loads(reg_path.read_text(encoding="utf-8"))

    results = run_registry(
        registry,
        mode=mode,
        dry_run=args.dry_run,
        family=args.family,
        ids=args.ids,
        limit=args.limit,
    )

    # Mark coverage probes
    probe_by_id = {b["id"]: b.get("coverage_probe") for b in registry.get("benchmarks", [])}
    out = []
    for r in results:
        d = r.to_dict()
        if probe_by_id.get(r.benchmark_id) and r.status == "fail":
            d["status"] = "gap"
            d["coverage_probe"] = True
        out.append(d)

    summary = {
        "registry": str(reg_path),
        "mode": mode.value,
        "dry_run": args.dry_run,
        "total": len(out),
        "pass": sum(1 for x in out if x["status"] == "pass"),
        "fail": sum(1 for x in out if x["status"] == "fail"),
        "gap": sum(1 for x in out if x["status"] == "gap"),
        "skip": sum(1 for x in out if x["status"] in ("skip", "dry_run")),
        "results": out,
    }

    text = json.dumps(summary, indent=2)
    if args.output:
        args.output.write_text(text, encoding="utf-8")
        print(f"Wrote {args.output}")
    else:
        print(text)

    fails = summary["fail"]
    if args.include_coverage_probes:
        return 0 if fails == 0 else 1
    return 0 if fails == 0 and summary["gap"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
