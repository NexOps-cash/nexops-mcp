#!/usr/bin/env python3
"""
Interactive specification-first contract generation in the terminal.

Conversation → review → confirm (Y) or modify (M) → generate CashScript.

Usage:
  python scripts/interactive_generate.py
  python scripts/interactive_generate.py "Make an auction app for NFTs"

Requires OPENROUTER_API_KEY in .env for AI-assisted clarification and generation.
Without the key, missing fields are collected via registry prompts (no LLM chat).
"""

from __future__ import annotations

import argparse
import asyncio
import os
import sys
import uuid
from typing import Any, Optional

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from dotenv import load_dotenv

load_dotenv(ROOT / ".env")

from src.models import ContractSpecification, SpecStatus, SpecificationReview
from src.services.pipeline_engine import get_guarded_pipeline_engine
from src.services.session import get_session_manager
from src.services.spec.assistant import SpecificationAssistant
from src.services.spec.capabilities import CAPABILITY_REGISTRY
from src.services.spec.clarification import build_clarification_plan
from src.services.spec.orchestrator import run_spec_pipeline
from src.services.spec.review import confirm_specification, modify_specification, render_specification
from src.services.spec.validator import SpecValidator


BANNER = """
╔══════════════════════════════════════════════════════════════╗
║  NexOps — Interactive Contract Architect                     ║
║  Describe your contract → answer questions → confirm → code  ║
╚══════════════════════════════════════════════════════════════╝
"""


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Interactive NexOps spec + generate CLI")
    p.add_argument("intent", nargs="?", default="", help="Initial contract description")
    p.add_argument("-o", "--out", default="", help="Write generated .cash to file")
    p.add_argument(
        "--security-level",
        choices=("low", "medium", "high"),
        default="high",
    )
    return p.parse_args()


def _prompt(line: str = "> ") -> str:
    try:
        return input(line).strip()
    except (EOFError, KeyboardInterrupt):
        print("\nCancelled.")
        sys.exit(130)


def _question_for_field(field_name: str) -> str:
    for cap in CAPABILITY_REGISTRY.values():
        for fs in cap.required_fields:
            if fs.name == field_name:
                return fs.question or f"Please provide {field_name}:"
    return f"Please provide {field_name}:"


def _coerce_answer(field_name: str, raw: str) -> Any:
    text = raw.strip()
    if not text:
        return None
    if field_name in ("holders", "threshold", "timeout_days", "duration_days", "max_supply"):
        try:
            return int(text.split()[0].replace(",", ""))
        except ValueError:
            return text
    if field_name in ("start_price", "min_price", "initial_threshold", "final_threshold"):
        try:
            return int(text.replace(",", "").replace(" satoshis", "").split()[0])
        except ValueError:
            return text
    if field_name in ("weights", "shares", "signers", "recipients"):
        if text.startswith("["):
            import json
            try:
                return json.loads(text)
            except json.JSONDecodeError:
                pass
        parts = [p.strip() for p in text.replace(";", ",").split(",") if p.strip()]
        if field_name == "weights" or field_name == "shares":
            nums = []
            for p in parts:
                try:
                    nums.append(int(p) if "." not in p else float(p))
                except ValueError:
                    nums.append(p)
            return nums if nums else parts
        return parts
    return text


def _print_review(review: SpecificationReview) -> None:
    print("\n" + "═" * 62)
    print("  CONTRACT SPECIFICATION REVIEW")
    print("═" * 62)
    for section, items in review.sections.items():
        if not items:
            continue
        print(f"\n  {section}")
        print("  " + "─" * 40)
        for item in items:
            print(f"    • {item}")
    if review.utxo_architecture and review.utxo_architecture.contracts:
        print("\n  UTXO Architecture")
        print("  " + "─" * 40)
        for c in review.utxo_architecture.contracts:
            print(f"    • Contract {c.id}: {c.type}")
        for tx in review.utxo_architecture.transactions:
            ins = ", ".join(tx.inputs)
            outs = ", ".join(tx.outputs)
            print(f"    • {tx.name}: [{ins}] → [{outs}]")
        for st in review.utxo_architecture.state_objects:
            print(f"    • State {st.name}: {st.storage}")
    print("\n" + "═" * 62)


async def _assistant_turn(
    spec: ContractSpecification,
    user_message: str,
    api_key: Optional[str],
    openrouter_key: Optional[str],
) -> ContractSpecification:
    validation = SpecValidator.validate(spec)
    turn = await SpecificationAssistant.respond(
        spec,
        validation,
        user_message,
        api_key=api_key,
        openrouter_key=openrouter_key or api_key,
        provider="openrouter",
    )
    print(f"\n  NexOps: {turn.message}\n")
    if turn.still_missing:
        print(f"  Still needed: {', '.join(turn.still_missing)}\n")
    return turn.updated_spec


async def _fill_via_registry(spec: ContractSpecification) -> ContractSpecification:
    """Field-by-field prompts when no LLM key (or as fallback)."""
    while True:
        validation = SpecValidator.validate(spec)
        if validation.is_complete:
            spec.status = SpecStatus.IN_REVIEW
            return spec
        print("\n  I need a few more details:\n")
        for field in validation.missing_fields:
            q = _question_for_field(field)
            ans = _prompt(f"  {q}\n  > ")
            val = _coerce_answer(field, ans)
            if val is not None:
                spec.parameters[field] = val
        spec.status = SpecStatus.NEEDS_INPUT


async def _conversation_loop(
    spec: ContractSpecification,
    original_intent: str,
    use_llm: bool,
    api_key: Optional[str],
) -> ContractSpecification:
    validation = SpecValidator.validate(spec)
    clarification = build_clarification_plan(validation)

    if validation.is_complete:
        spec.status = SpecStatus.IN_REVIEW
        return spec

    print("\n  NexOps is drafting your specification...\n")
    if clarification.questions:
        print("  To build this safely, I need to know:\n")
        for q in clarification.questions:
            print(f"    • {q}")
        print()

    if use_llm:
        print("  Answer in plain language (or type 'fields' for one-by-one prompts).\n")
        while True:
            validation = SpecValidator.validate(spec)
            if validation.is_complete:
                spec.status = SpecStatus.IN_REVIEW
                break
            msg = _prompt("  You: ")
            if not msg:
                continue
            if msg.lower() in ("fields", "manual", "registry"):
                spec = await _fill_via_registry(spec)
                break
            spec = await _assistant_turn(spec, msg, api_key, api_key)
    else:
        print("  (No OPENROUTER_API_KEY — using registry prompts.)\n")
        spec = await _fill_via_registry(spec)

    return spec


async def _modify_loop(
    spec: ContractSpecification,
    use_llm: bool,
    api_key: Optional[str],
) -> ContractSpecification:
    spec = modify_specification(spec)
    print("\n  What would you like to change?\n")
    msg = _prompt("  You: ")
    if use_llm and msg:
        spec = await _assistant_turn(spec, msg, api_key, api_key)
        validation = SpecValidator.validate(spec)
        if not validation.is_complete:
            spec = await _conversation_loop(spec, spec.intent, use_llm, api_key)
    elif msg:
        spec = await _assistant_turn(spec, msg, api_key, api_key) if use_llm else spec
        if not SpecValidator.validate(spec).is_complete:
            spec = await _fill_via_registry(spec)
    return spec


async def _generate(
    intent: str,
    spec: ContractSpecification,
    security_level: str,
    api_key: Optional[str],
    out_path: str,
) -> int:
    engine = get_guarded_pipeline_engine()

    async def on_update(msg: dict) -> None:
        if not isinstance(msg, dict):
            return
        stage = msg.get("stage", "")
        message = msg.get("message", "")
        attempt = msg.get("attempt", "")
        if stage:
            line = f"  [{stage}] {message}"
            if attempt:
                line += f" (attempt {attempt})"
            print(line, file=sys.stderr)

    print("\n  Generating CashScript contract...\n", file=sys.stderr)

    result = await engine.generate_guarded(
        intent,
        security_level=security_level,
        on_update=on_update,
        openrouter_key=api_key,
        api_key=api_key,
        provider="openrouter",
        disable_golden=True,
        disable_fallbacks=True,
        resolution_mode="interactive",
        existing_spec=spec,
    )

    if result.get("type") != "success":
        err = result.get("error", {})
        print(f"\n  Generation failed: {err.get('code', 'error')}", file=sys.stderr)
        print(f"  {err.get('message', result)}", file=sys.stderr)
        return 1

    data = result["data"]
    code = data.get("code", "")
    contract_type = (data.get("intent_model") or {}).get("contract_type", "?")

    if out_path:
        path = Path(out_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(code, encoding="utf-8")
        print(f"\n  Wrote {path}", file=sys.stderr)

    print("\n" + "═" * 62)
    print("  GENERATED CONTRACT")
    print(f"  contract_type: {contract_type}")
    if data.get("toll_gate"):
        print(f"  structural_score: {data['toll_gate'].get('structural_score', 0):.2f}")
    print("═" * 62 + "\n")
    print(code)
    print("\n" + "═" * 62)
    return 0


async def run(initial_intent: str, security_level: str, out_path: str) -> int:
    print(BANNER)
    api_key = os.getenv("OPENROUTER_API_KEY")
    use_llm = bool(api_key)

    if not use_llm:
        print("  Warning: OPENROUTER_API_KEY not set — chat uses registry prompts only.")
        print("  Generation still requires the key.\n")

    intent = initial_intent.strip()
    if not intent:
        intent = _prompt("  What contract do you want to build?\n  > ")

    if not intent:
        print("  No intent provided.", file=sys.stderr)
        return 1

    session = get_session_manager().get_or_create(str(uuid.uuid4()))
    session.current_specification = None

    spec, clarification, _, _, report, _ = await run_spec_pipeline(
        intent,
        security_level=security_level,
        resolution_mode="interactive",
        api_key=api_key,
        openrouter_key=api_key,
        provider="openrouter" if use_llm else None,
    )
    session.current_specification = spec

    if clarification or not SpecValidator.validate(spec).is_complete:
        print(f"\n  Detected capabilities: {', '.join(c.name for c in spec.capabilities)}")
        spec = await _conversation_loop(spec, intent, use_llm, api_key)
        session.current_specification = spec

    # Review / confirm loop
    while True:
        validation = SpecValidator.validate(spec)
        if not validation.is_complete:
            spec = await _conversation_loop(spec, intent, use_llm, api_key)
            continue

        spec.status = SpecStatus.IN_REVIEW
        review = render_specification(spec)
        _print_review(review)

        choice = _prompt("\n  Confirm specification?  [Y]es  [M]odify  [Q]uit: ").upper()
        if choice in ("Y", "YES"):
            spec = confirm_specification(spec)
            session.current_specification = spec
            break
        if choice in ("M", "MODIFY"):
            spec = await _modify_loop(spec, use_llm, api_key)
            session.current_specification = spec
            continue
        if choice in ("Q", "QUIT", "N", "NO"):
            print("  Aborted.")
            return 0
        print("  Please enter Y, M, or Q.")

    if not api_key:
        print("\n  Error: set OPENROUTER_API_KEY to generate code.", file=sys.stderr)
        return 1

    return await _generate(intent, spec, security_level, api_key, out_path)


def main() -> None:
    args = _parse_args()
    code = asyncio.run(run(args.intent, args.security_level, args.out))
    sys.exit(code)


if __name__ == "__main__":
    main()
