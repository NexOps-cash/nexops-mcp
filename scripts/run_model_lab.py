#!/usr/bin/env python3
"""
NexOps Model Lab — run the same Phase 2 prompt against multiple models.

Usage:
  python scripts/run_model_lab.py --models configs/models.json --prompts configs/prompts.json
  python scripts/run_model_lab.py --models configs/models.json --prompts configs/prompts.json --compile
  python scripts/run_model_lab.py --models configs/models.json --prompts configs/prompts.json --dry-run
  python scripts/run_model_lab.py --models configs/models.json --prompts configs/prompts.json --filter-tags nft,minting

Requires OPENROUTER_API_KEY in .env or environment.
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from dotenv import load_dotenv

load_dotenv(ROOT / ".env")

from evaluation.model_lab.runner import ModelLabRunner
from evaluation.model_lab.schemas import RunOptions
from evaluation.model_lab.writer import allocate_run_dir


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="NexOps Model Lab: compare CashScript generation across models.",
    )
    parser.add_argument("--models", type=Path, required=True, help="Path to models.json")
    parser.add_argument("--prompts", type=Path, required=True, help="Path to prompts.json")
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=None,
        help="Output directory (default: model_lab_runs/run_YYYY_MM_DD)",
    )
    parser.add_argument(
        "--phase1-model",
        default="",
        help="OpenRouter slug for Phase 1 intent parsing (default: OPENROUTER_PHASE1_MODEL)",
    )
    parser.add_argument(
        "--compile",
        action="store_true",
        help="Compile each extracted .cash file",
    )
    parser.add_argument(
        "--audit",
        action="store_true",
        help="Run full NexOps audit per model (expensive — includes semantic judge LLM)",
    )
    parser.add_argument(
        "--concurrency",
        type=int,
        default=3,
        help="Max parallel model calls per prompt (default: 3)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Validate configs and print plan without API calls",
    )
    parser.add_argument(
        "--max-tokens",
        type=int,
        default=2500,
        help="Max completion tokens per model call (default: 2500)",
    )
    parser.add_argument(
        "--filter-tags",
        default="",
        help="Comma-separated tags; run only prompts matching any tag",
    )
    return parser.parse_args()


def main() -> int:
    args = _parse_args()

    models_path = args.models if args.models.is_absolute() else ROOT / args.models
    prompts_path = args.prompts if args.prompts.is_absolute() else ROOT / args.prompts

    if not models_path.exists():
        print(f"Error: models config not found: {models_path}", file=sys.stderr)
        return 1
    if not prompts_path.exists():
        print(f"Error: prompts config not found: {prompts_path}", file=sys.stderr)
        return 1

    output_dir = args.output_dir
    if output_dir is not None and not output_dir.is_absolute():
        output_dir = ROOT / output_dir
    elif output_dir is None and not args.dry_run:
        output_dir = allocate_run_dir(ROOT / "model_lab_runs")

    filter_tags = [t.strip() for t in args.filter_tags.split(",") if t.strip()]

    options = RunOptions(
        models_path=models_path,
        prompts_path=prompts_path,
        output_dir=output_dir or ROOT / "model_lab_runs" / "dry_run_placeholder",
        phase1_model=args.phase1_model,
        compile=args.compile,
        audit=args.audit,
        max_tokens=max(256, args.max_tokens),
        concurrency=max(1, args.concurrency),
        dry_run=args.dry_run,
        filter_tags=filter_tags,
    )

    try:
        runner = ModelLabRunner(options, ROOT)
        run_dir = asyncio.run(runner.run())
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    if args.dry_run:
        print("Dry run complete.")
        return 0

    print(f"Model lab run complete: {run_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
