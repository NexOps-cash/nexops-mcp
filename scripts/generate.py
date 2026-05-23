"""
Generate a CashScript contract from a natural-language prompt (CLI).

Usage:
  python scripts/generate.py "PFP drop: minting authority 0x02 stays in contract"
  python scripts/generate.py -p "loyalty points fungible token transfer"
  echo "mutable NFT update commitment" | python scripts/generate.py
  python scripts/generate.py -p "..." --out MyContract.cash
  python scripts/generate.py -p "..." --code-only

Requires OPENROUTER_API_KEY in .env or environment.
"""

from __future__ import annotations

import argparse
import asyncio
import os
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


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="NexOps: generate CashScript from a natural-language prompt.",
    )
    parser.add_argument(
        "prompt",
        nargs="?",
        default="",
        help="Contract intent (quote the whole string).",
    )
    parser.add_argument(
        "-p", "--prompt",
        dest="prompt_flag",
        default="",
        help="Intent text (alternative to positional prompt).",
    )
    parser.add_argument(
        "-o", "--out",
        default="",
        help="Write generated .cash to this file.",
    )
    parser.add_argument(
        "--code-only",
        action="store_true",
        help="Print only the generated source (no metadata).",
    )
    parser.add_argument(
        "--golden",
        action="store_true",
        help="Use golden template adaptation (default: free synthesis).",
    )
    parser.add_argument(
        "--allow-fallback",
        action="store_true",
        help="Allow secure fallback contract on exhaustion (default: benchmark parity, no fallback).",
    )
    parser.add_argument(
        "--security-level",
        choices=("low", "medium", "high"),
        default="high",
        help="Pipeline security level (default: high).",
    )
    return parser.parse_args()


async def _run(
    intent: str,
    *,
    disable_golden: bool,
    security_level: str,
    code_only: bool,
    out_path: str,
) -> int:
    if not os.getenv("OPENROUTER_API_KEY"):
        print(
            "Error: set OPENROUTER_API_KEY in .env or the environment.",
            file=sys.stderr,
        )
        return 1

    from src.services.pipeline_engine import get_guarded_pipeline_engine

    engine = get_guarded_pipeline_engine()

    async def on_update(msg: dict) -> None:
        if not isinstance(msg, dict):
            return
        stage = msg.get("stage", "")
        status = msg.get("status", "")
        message = msg.get("message", "")
        attempt = msg.get("attempt", "")
        if stage and not code_only:
            line = f"[{stage}] {message}"
            if attempt:
                line += f" (attempt {attempt})"
            print(line, file=sys.stderr)

    result = await engine.generate_guarded(
        intent,
        security_level=security_level,
        on_update=on_update,
        disable_golden=disable_golden,
        disable_fallbacks=not getattr(args, "allow_fallback", False),
    )

    if result.get("type") != "success":
        err = result.get("error", {})
        print(f"Generation failed: {err.get('code', 'error')}", file=sys.stderr)
        print(err.get("message", result), file=sys.stderr)
        violations = err.get("violations") or []
        for v in violations[:10]:
            if isinstance(v, dict):
                print(f"  - {v.get('rule', v)}", file=sys.stderr)
        return 1

    data = result["data"]
    code = data.get("code", "")
    contract_type = (
        data.get("intent_model", {}) or {}
    ).get("contract_type") or data.get("contract_type", "?")

    if out_path:
        path = Path(out_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(code, encoding="utf-8")
        if not code_only:
            print(f"Wrote {path}", file=sys.stderr)

    if code_only:
        print(code, end="" if code.endswith("\n") else "\n")
    else:
        print(file=sys.stderr)
        print(f"contract_type: {contract_type}", file=sys.stderr)
        if data.get("toll_gate"):
            print(
                f"structural_score: {data['toll_gate'].get('structural_score', 0):.2f}",
                file=sys.stderr,
            )
        print("--- generated .cash ---", file=sys.stderr)
        print(code)
        print("--- end ---", file=sys.stderr)

    return 0


if __name__ == "__main__":
    args = _parse_args()
    intent = (args.prompt or args.prompt_flag or "").strip()
    if not intent:
        if sys.stdin.isatty():
            print("Enter contract intent (end with Ctrl+Z then Enter on Windows, Ctrl+D on Unix):")
        intent = sys.stdin.read().strip()
    if not intent:
        print("Error: no prompt provided.", file=sys.stderr)
        sys.exit(1)

    disable_golden = not args.golden
    exit_code = asyncio.run(
        _run(
            intent,
            disable_golden=disable_golden,
            security_level=args.security_level,
            code_only=args.code_only,
            out_path=args.out,
        )
    )
    sys.exit(exit_code)
