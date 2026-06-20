#!/usr/bin/env python3
"""
Run audit replay corpus — NO OpenRouter / LLM calls.

Uses fixture judgments (V2.1 compliant) and deterministic layers only.

Usage:
  python scripts/run_replay_suite.py
  python scripts/run_replay_suite.py --focus payroll_fp
  python scripts/run_replay_suite.py --focus trust_confusion
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from benchmark.audit_eval.replay_runner import run_replay_index

DEFAULT_INDEX = ROOT / "audit_replay_corpus" / "index.json"

FOCUS_GROUPS = {
    "payroll_fp": ["payroll_fp", "deterministic_intent"],
    "trust_confusion": ["trust_confusion", "deployment_confusion"],
    "auth_hallucination": ["adversarial_fail", "bundle_contradiction"],
    "contradiction": ["bundle_contradiction"],
}


def main() -> int:
    parser = argparse.ArgumentParser(description="Run audit replay suite (no LLM)")
    parser.add_argument("--index", type=Path, default=DEFAULT_INDEX)
    parser.add_argument("--focus", type=str, default=None, help="replay_trigger or group name")
    parser.add_argument("--ids", nargs="*", default=None)
    parser.add_argument("--adversarial-only", action="store_true")
    parser.add_argument("--critical-only", action="store_true")
    parser.add_argument("--output", type=Path, default=None)
    args = parser.parse_args()

    focus = args.focus
    if focus in FOCUS_GROUPS:
        all_results = []
        for trig in FOCUS_GROUPS[focus]:
            all_results.extend(
                run_replay_index(
                    args.index,
                    focus=trig,
                    ids=args.ids,
                    adversarial_only=args.adversarial_only,
                    critical_only=args.critical_only,
                )
            )
    else:
        all_results = run_replay_index(
            args.index,
            focus=focus,
            ids=args.ids,
            adversarial_only=args.adversarial_only,
            critical_only=args.critical_only,
        )

    out = [r.to_dict() for r in all_results]
    summary = {
        "index": str(args.index),
        "total": len(out),
        "pass": sum(1 for x in out if x["status"] == "pass"),
        "fail": sum(1 for x in out if x["status"] == "fail"),
        "skip": sum(1 for x in out if x["status"] == "skip"),
        "results": out,
    }
    text = json.dumps(summary, indent=2)
    if args.output:
        args.output.write_text(text, encoding="utf-8")
    else:
        print(text)
    return 0 if summary["fail"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
