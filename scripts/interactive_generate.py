#!/usr/bin/env python3
"""
Interactive specification-first contract generation in the terminal.

Conversation → review → confirm (Y) or modify (M) → generate CashScript.

Usage:
  python scripts/interactive_generate.py
  python scripts/interactive_generate.py "Make an auction app for NFTs"

Requires OPENROUTER_API_KEY in .env for AI-assisted clarification and generation.
Without the key, missing fields are collected via registry prompts (no LLM chat).

Graph v2 (default): ConstraintGraph SSOT — same path as spec_turn API.
Use --legacy to force the old wizard/regex pipeline.
"""

from __future__ import annotations

import argparse
import asyncio
import os
import re
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

from src.models import (
    CompositionSupportAssessment,
    ContractSpecification,
    ExecutionPlan,
    PlanningReport,
    SpecStatus,
    SpecificationReview,
)
from src.services.pipeline_engine import get_guarded_pipeline_engine
from src.services.session import get_session_manager
from src.services.spec.assistant import SpecificationAssistant
from src.services.spec.architecture import ArchitectureBuilder
from src.services.spec.capabilities import CAPABILITY_REGISTRY
from src.services.spec.orchestrator import run_spec_pipeline
from src.services.spec.phase2_adapter import resolve_effective_mode
from src.services.spec.planner import ModulePlanner
from src.services.spec.review import confirm_specification, modify_specification, render_specification
from src.services.spec.support_assessment import assess_composition_support, personalize_suggestion_prompt
from src.services.spec.discovery import is_in_discovery_phase
from src.services.spec.parameter_extraction import confirm_fields
from src.services.spec.validator import SpecValidator
from src.services.spec.graph_config import use_spec_graph_v2
from src.services.spec.graph_cli import (
    cli_apply_message,
    cli_bootstrap,
    confirm_graph_session,
    modify_graph_session,
    persist_graph_session,
)
from src.services.spec.graph_pipeline import build_planning_report
from src.services.spec.review import render_graph_specification
from src.services.spec.validator_v2 import ValidatorV2
from src.services.spec.constraint_graph import ConstraintGraph


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
    p.add_argument(
        "--legacy",
        action="store_true",
        help="Use legacy wizard/regex spec pipeline instead of Constraint Graph v2",
    )
    p.add_argument(
        "--spec-debug",
        action="store_true",
        help="Print ContractSpecification parameters before/after each assistant turn",
    )
    return p.parse_args()


def _prompt(line: str = "> ") -> str:
    try:
        return input(line).strip()
    except (EOFError, KeyboardInterrupt):
        print("\nCancelled.")
        sys.exit(130)


def _looks_like_modification_input(text: str) -> bool:
    """Requirement bullets or long notes at the confirm prompt — not Y/M/Q."""
    stripped = text.strip()
    if not stripped:
        return False
    upper = stripped.upper()
    if upper in ("Y", "YES", "M", "MODIFY", "Q", "QUIT", "N", "NO"):
        return False
    if len(stripped) > 25:
        return True
    if stripped.startswith(("-", "•", "*")):
        return True
    if re.match(r"^\d+[\).\]]\s", stripped):
        return True
    if "\n" in stripped:
        return True
    if stripped.lower().rstrip(":") == "requirements":
        return True
    if "requirements" in stripped.lower() and len(stripped) > 12:
        return True
    return False


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


def _assess_graph(graph: ConstraintGraph) -> CompositionSupportAssessment:
    spec = graph.to_specification()
    _, _, report = build_planning_report(graph)
    return assess_composition_support(spec, report)


def _assess_spec(spec: ContractSpecification) -> CompositionSupportAssessment:
    modules, _ = ModulePlanner.select_modules(spec)
    plan = ExecutionPlan(
        modules=modules,
        order=[m.name for m in modules],
        dependencies={m.name: list(m.depends_on) for m in modules},
        shared_parameters=dict(spec.parameters),
    )
    utxo = ArchitectureBuilder.build(plan, spec)
    report = PlanningReport(
        detected_capabilities=[c.name for c in spec.capabilities],
        selected_modules=[m.name for m in modules],
        effective_mode=resolve_effective_mode(utxo, plan),
    )
    return assess_composition_support(spec, report)


def _print_composition_guidance(support: CompositionSupportAssessment, spec: ContractSpecification) -> None:
    print("\n" + "═" * 62)
    print("  COMPOSITION NOT SUPPORTED YET")
    print("═" * 62 + "\n")
    if support.guidance:
        for line in support.guidance.splitlines():
            print(f"  {line}" if line else "")
    else:
        print(f"  {support.reason}")
        if support.detail:
            print(f"\n  {support.detail}")
    if support.suggestions:
        print("\n  Supported alternatives:")
        for i, alt in enumerate(support.suggestions[:4], start=1):
            example = personalize_suggestion_prompt(alt, spec) if spec else alt.prompt_example
            print(f"    [{i}] {alt.label}")
            if example:
                print(f"        \"{example}\"")
    print("\n" + "═" * 62)


def _composition_menu(
    support: CompositionSupportAssessment,
    spec: ContractSpecification,
) -> str | tuple[str, str]:
    """Returns 'modify', 'quit', a prompt to generate, or ('apply', text) for pasted requirements."""
    options = support.suggestions[:4]
    n = len(options)
    while True:
        raw = _prompt(
            f"\n  [1-{n}] Generate a supported alternative  [M]odify spec  [Q]uit: "
        )
        if _looks_like_modification_input(raw):
            return ("apply", raw.strip())
        choice = raw.upper()
        if choice in ("Q", "QUIT"):
            return "quit"
        if choice in ("M", "MODIFY"):
            return "modify"
        if choice in ("Y", "YES"):
            print(f"  Y confirms a different step — pick 1-{n}, M, or Q here.")
            continue
        if choice.isdigit():
            idx = int(choice) - 1
            if 0 <= idx < n:
                alt = options[idx]
                return personalize_suggestion_prompt(alt, spec)
        print(f"  Please enter 1-{n}, M, or Q — or paste requirement bullets to update the spec.")


def _print_spec_snapshot(label: str, spec: ContractSpecification) -> None:
    print(
        f"\n  [spec:{label}] parameters={spec.parameters} "
        f"confirmed={spec.confirmed_fields} pending={spec.pending_parameters}\n"
    )


async def _assistant_turn(
    spec: ContractSpecification,
    user_message: str,
    api_key: Optional[str],
    openrouter_key: Optional[str],
    *,
    spec_debug: bool = False,
    last_assistant_message: str = "",
    session=None,
) -> tuple[ContractSpecification, str]:
    if spec_debug:
        _print_spec_snapshot("before", spec)

    validation = SpecValidator.validate(spec)
    chat_history = list(session.spec_chat_history) if session else []
    turn = await SpecificationAssistant.respond(
        spec,
        validation,
        user_message,
        api_key=api_key,
        openrouter_key=openrouter_key or api_key,
        provider="openrouter",
        last_assistant_message=last_assistant_message,
        chat_history=chat_history,
    )

    if session is not None:
        mgr = get_session_manager()
        mgr.append_spec_chat(session.session_id, "user", user_message)
        mgr.append_spec_chat(session.session_id, "assistant", turn.message)

    if spec_debug:
        _print_spec_snapshot("after", turn.updated_spec)

    print(f"\n  NexOps: {turn.message}\n")
    if turn.progress and turn.progress not in turn.message:
        print(f"  ({turn.progress})\n")
    return turn.updated_spec, turn.message


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
                confirm_fields(spec, {field})
        spec.status = SpecStatus.NEEDS_INPUT


def _print_graph_debug(graph: ConstraintGraph, spec: ContractSpecification) -> None:
    from src.services.spec.graph_pattern_detection import GraphPatternDetection

    patterns = GraphPatternDetection.detect_patterns(graph)
    print(
        f"\n  [graph] nodes={len(graph.nodes)} patterns={patterns} "
        f"parameters={spec.parameters} confirmed={spec.confirmed_fields}\n"
    )


async def _graph_conversation_loop(
    session,
    graph: ConstraintGraph,
    spec: ContractSpecification,
    use_llm: bool,
    api_key: Optional[str],
    *,
    spec_debug: bool = False,
) -> tuple[ConstraintGraph, ContractSpecification]:
    last_clarification = None
    while True:
        validation = ValidatorV2.validate(graph)
        if validation.is_complete:
            spec.status = SpecStatus.IN_REVIEW
            return graph, spec
        msg = _prompt("  You: ")
        if not msg:
            continue
        if msg.lower() in ("fields", "manual", "registry"):
            if not use_llm:
                spec = await _fill_via_registry(spec)
            else:
                print("  Registry fill is only available without graph v2 or use --legacy.\n")
                continue
            graph = ConstraintGraph.from_specification(spec)
            persist_graph_session(session, graph, spec)
            continue
        graph, spec, validation, last_clarification, assistant_msg = await cli_apply_message(
            session,
            graph,
            msg,
            api_key=api_key,
            openrouter_key=api_key,
            last_clarification=last_clarification,
        )
        print(f"\n  NexOps: {assistant_msg}\n")
        if spec_debug:
            _print_graph_debug(graph, spec)


async def _graph_modify_loop(
    session,
    graph: ConstraintGraph,
    spec: ContractSpecification,
    use_llm: bool,
    api_key: Optional[str],
    *,
    spec_debug: bool = False,
    change_message: str = "",
) -> tuple[ConstraintGraph, ContractSpecification]:
    spec = modify_graph_session(session, graph, spec)
    msg = change_message.strip()
    if not msg:
        print("\n  What would you like to change?\n")
        msg = _prompt("  You: ")
    if use_llm and msg:
        graph, spec, validation, _, assistant_msg = await cli_apply_message(
            session,
            graph,
            msg,
            api_key=api_key,
            openrouter_key=api_key,
        )
        print(f"\n  NexOps: {assistant_msg}\n")
        if spec_debug:
            _print_graph_debug(graph, spec)
        if not validation.is_complete:
            graph, spec = await _graph_conversation_loop(
                session, graph, spec, use_llm, api_key, spec_debug=spec_debug
            )
    elif msg and not use_llm:
        spec = await _fill_via_registry(spec)
        graph = ConstraintGraph.from_specification(spec)
        persist_graph_session(session, graph, spec)
    return graph, spec


async def _conversation_loop(
    spec: ContractSpecification,
    original_intent: str,
    use_llm: bool,
    api_key: Optional[str],
    session,
    *,
    spec_debug: bool = False,
) -> ContractSpecification:
    validation = SpecValidator.validate(spec)

    if validation.is_complete:
        spec.status = SpecStatus.IN_REVIEW
        return spec

    if use_llm:
        last_assistant_message = ""
        if is_in_discovery_phase(spec):
            if session is None or not session.spec_chat_history:
                spec, last_assistant_message = await _assistant_turn(
                    spec,
                    original_intent,
                    api_key,
                    api_key,
                    spec_debug=spec_debug,
                    last_assistant_message="",
                    session=session,
                )
        else:
            print("\n  NexOps is drafting your specification...\n")
            caps = ", ".join(c.name.replace("_", " ") for c in spec.capabilities)
            if caps:
                print(f"  Detected: {caps}\n")
            opening = SpecificationAssistant.opening_message(spec)
            print(f"  NexOps: {opening}\n")
            if session is not None:
                get_session_manager().append_spec_chat(session.session_id, "assistant", opening)
            last_assistant_message = opening

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
            spec, last_assistant_message = await _assistant_turn(
                spec,
                msg,
                api_key,
                api_key,
                spec_debug=spec_debug,
                last_assistant_message=last_assistant_message,
                session=session,
            )
    else:
        print("  (No OPENROUTER_API_KEY — using registry prompts.)\n")
        spec = await _fill_via_registry(spec)

    return spec


async def _modify_loop(
    spec: ContractSpecification,
    use_llm: bool,
    api_key: Optional[str],
    session,
    *,
    spec_debug: bool = False,
    change_message: str = "",
) -> ContractSpecification:
    spec = modify_specification(spec)
    msg = change_message.strip()
    if not msg:
        print("\n  What would you like to change?\n")
        msg = _prompt("  You: ")
    if use_llm and msg:
        spec, _ = await _assistant_turn(
            spec, msg, api_key, api_key, spec_debug=spec_debug, session=session
        )
        validation = SpecValidator.validate(spec)
        if not validation.is_complete:
            spec = await _conversation_loop(
                spec, spec.intent, use_llm, api_key, session, spec_debug=spec_debug
            )
    elif msg:
        if use_llm:
            spec, _ = await _assistant_turn(
                spec, msg, api_key, api_key, spec_debug=spec_debug, session=session
            )
        if not SpecValidator.validate(spec).is_complete:
            spec = await _fill_via_registry(spec)
    return spec


async def _finish_generate_result(result: dict, out_path: str) -> int:
    rtype = result.get("type")
    if rtype == "unsupported_composition":
        data = result.get("data", {})
        support = CompositionSupportAssessment(**data.get("composition_support", {}))
        spec_data = data.get("specification")
        spec_obj = ContractSpecification(**spec_data) if spec_data else ContractSpecification()
        _print_composition_guidance(support, spec_obj)
        action = _composition_menu(support, spec_obj)
        if action == "quit":
            print("  Specification saved. You can return to generate a supported pattern later.")
            return 0
        if action == "modify":
            return 2
        if action:
            return await _generate_simple(action, os.getenv("OPENROUTER_API_KEY"), out_path)
        return 0
    if rtype == "experimental_composition":
        data = result.get("data", {})
        support = CompositionSupportAssessment(**data.get("composition_support", {}))
        spec_data = data.get("specification")
        spec_obj = ContractSpecification(**spec_data) if spec_data else ContractSpecification()
        _print_composition_guidance(support, spec_obj)
        print("\n  This composition is experimental.")
        choice = _prompt("  [Y] Generate anyway  [Q] Quit: ").upper()
        if choice not in ("Y", "YES"):
            return 0
        return 1
    if rtype != "success":
        err = result.get("error", {})
        print(f"\n  Generation failed: {err.get('code', rtype or 'error')}", file=sys.stderr)
        if err.get("message"):
            print(f"  {err['message']}", file=sys.stderr)
        elif rtype:
            print(f"  {result}", file=sys.stderr)
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


async def _generate_simple(
    intent: str,
    api_key: Optional[str],
    out_path: str,
    security_level: str = "high",
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

    print(f"\n  Generating: {intent}\n", file=sys.stderr)

    result = await engine.generate_guarded(
        intent,
        security_level=security_level,
        on_update=on_update,
        openrouter_key=api_key,
        api_key=api_key,
        provider="openrouter",
        disable_golden=True,
        disable_fallbacks=True,
        resolution_mode="non_interactive",
        existing_spec=None,
    )
    return await _finish_generate_result(result, out_path)


async def _generate(
    intent: str,
    spec: ContractSpecification,
    security_level: str,
    api_key: Optional[str],
    out_path: str,
    *,
    existing_graph: Optional[dict] = None,
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
        existing_graph=existing_graph,
    )

    code = await _finish_generate_result(result, out_path)
    if code == 2:
        return 2
    if code == 1 and result.get("type") == "experimental_composition":
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
            existing_graph=existing_graph,
            allow_experimental=True,
        )
        return await _finish_generate_result(result, out_path)
    return code


async def run_legacy(
    initial_intent: str,
    security_level: str,
    out_path: str,
    spec_debug: bool = False,
) -> int:
    api_key = os.getenv("OPENROUTER_API_KEY")
    use_llm = bool(api_key)

    intent = initial_intent.strip()
    if not intent:
        intent = _prompt("  What contract do you want to build?\n  > ").strip()

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
        spec = await _conversation_loop(spec, intent, use_llm, api_key, session, spec_debug=spec_debug)
        session.current_specification = spec

    # Review / confirm loop
    while True:
        validation = SpecValidator.validate(spec)
        if not validation.is_complete:
            spec = await _conversation_loop(spec, intent, use_llm, api_key, session, spec_debug=spec_debug)
            continue

        spec.status = SpecStatus.IN_REVIEW
        support = _assess_spec(spec)

        if support.status == "unsupported":
            print("\n  Your specification is complete, but this combination cannot be generated yet.\n")
            _print_composition_guidance(support, spec)
            action = _composition_menu(support, spec)
            if isinstance(action, tuple) and action[0] == "apply":
                print("\n  I'll fold those details into your specification.\n")
                spec = await _modify_loop(
                    spec,
                    use_llm,
                    api_key,
                    session,
                    spec_debug=spec_debug,
                    change_message=action[1],
                )
                session.current_specification = spec
                continue
            if action == "quit":
                print("  Specification saved. You can return to generate a supported pattern later.")
                return 0
            if action == "modify":
                spec = await _modify_loop(spec, use_llm, api_key, session, spec_debug=spec_debug)
                session.current_specification = spec
                continue
            if action and api_key:
                return await _generate_simple(action, api_key, out_path, security_level)
            if not api_key:
                print("\n  Error: set OPENROUTER_API_KEY to generate code.", file=sys.stderr)
                return 1
            continue

        review = render_specification(spec)
        _print_review(review)

        if support.status == "experimental":
            print("\n  Note: This composition is experimental and may not reflect all planned behavior.")

        raw_choice = _prompt("\n  Confirm specification?  [Y]es  [M]odify  [Q]uit: ")
        if _looks_like_modification_input(raw_choice):
            print("\n  I'll fold those details into your specification.\n")
            spec = await _modify_loop(
                spec,
                use_llm,
                api_key,
                session,
                spec_debug=spec_debug,
                change_message=raw_choice,
            )
            session.current_specification = spec
            continue

        choice = raw_choice.strip().upper()
        if choice in ("Y", "YES"):
            spec = confirm_specification(spec)
            session.current_specification = spec
            break
        if choice in ("M", "MODIFY"):
            spec = await _modify_loop(spec, use_llm, api_key, session, spec_debug=spec_debug)
            session.current_specification = spec
            continue
        if choice in ("Q", "QUIT", "N", "NO"):
            print("  Aborted.")
            return 0
        print("  Please enter Y, M, or Q — or paste requirement bullets to update the spec.")

    if not api_key:
        print("\n  Error: set OPENROUTER_API_KEY to generate code.", file=sys.stderr)
        return 1

    while True:
        code = await _generate(intent, spec, security_level, api_key, out_path)
        if code != 2:
            return code
        spec = await _modify_loop(spec, use_llm, api_key, session, spec_debug=spec_debug)
        session.current_specification = spec
        spec = confirm_specification(spec)


async def run_graph(
    initial_intent: str,
    security_level: str,
    out_path: str,
    spec_debug: bool = False,
) -> int:
    api_key = os.getenv("OPENROUTER_API_KEY")
    use_llm = bool(api_key)

    intent = initial_intent.strip()
    if not intent:
        intent = _prompt("  What contract do you want to build?\n  > ").strip()

    if not intent:
        print("  No intent provided.", file=sys.stderr)
        return 1

    session = get_session_manager().get_or_create(str(uuid.uuid4()))
    session.current_specification = None
    session.current_constraint_graph = None

    graph, spec, validation, opening = await cli_bootstrap(
        intent,
        session,
        api_key=api_key if use_llm else None,
        openrouter_key=api_key,
    )
    print(f"\n  NexOps: {opening}\n")
    if spec_debug:
        _print_graph_debug(graph, spec)

    if not validation.is_complete:
        graph, spec = await _graph_conversation_loop(
            session, graph, spec, use_llm, api_key, spec_debug=spec_debug
        )

    while True:
        validation = ValidatorV2.validate(graph)
        if not validation.is_complete:
            graph, spec = await _graph_conversation_loop(
                session, graph, spec, use_llm, api_key, spec_debug=spec_debug
            )
            continue

        spec.status = SpecStatus.IN_REVIEW
        support = _assess_graph(graph)

        if support.status == "unsupported":
            print("\n  Your specification is complete, but this combination cannot be generated yet.\n")
            _print_composition_guidance(support, spec)
            action = _composition_menu(support, spec)
            if isinstance(action, tuple) and action[0] == "apply":
                print("\n  I'll fold those details into your specification.\n")
                graph, spec = await _graph_modify_loop(
                    session,
                    graph,
                    spec,
                    use_llm,
                    api_key,
                    spec_debug=spec_debug,
                    change_message=action[1],
                )
                continue
            if action == "quit":
                print("  Specification saved. You can return to generate a supported pattern later.")
                return 0
            if action == "modify":
                graph, spec = await _graph_modify_loop(
                    session, graph, spec, use_llm, api_key, spec_debug=spec_debug
                )
                continue
            if action and api_key:
                return await _generate_simple(action, api_key, out_path, security_level)
            if not api_key:
                print("\n  Error: set OPENROUTER_API_KEY to generate code.", file=sys.stderr)
                return 1
            continue

        review = render_graph_specification(graph)
        _print_review(review)

        if support.status == "experimental":
            print("\n  Note: This composition is experimental and may not reflect all planned behavior.")

        raw_choice = _prompt("\n  Confirm specification?  [Y]es  [M]odify  [Q]uit: ")
        if _looks_like_modification_input(raw_choice):
            print("\n  I'll fold those details into your specification.\n")
            graph, spec = await _graph_modify_loop(
                session,
                graph,
                spec,
                use_llm,
                api_key,
                spec_debug=spec_debug,
                change_message=raw_choice,
            )
            continue

        choice = raw_choice.strip().upper()
        if choice in ("Y", "YES"):
            spec = confirm_graph_session(session, graph, spec)
            break
        if choice in ("M", "MODIFY"):
            graph, spec = await _graph_modify_loop(
                session, graph, spec, use_llm, api_key, spec_debug=spec_debug
            )
            continue
        if choice in ("Q", "QUIT", "N", "NO"):
            print("  Aborted.")
            return 0
        print("  Please enter Y, M, or Q — or paste requirement bullets to update the spec.")

    if not api_key:
        print("\n  Error: set OPENROUTER_API_KEY to generate code.", file=sys.stderr)
        return 1

    confirmed_graph = session.current_constraint_graph
    while True:
        code = await _generate(
            intent,
            spec,
            security_level,
            api_key,
            out_path,
            existing_graph=confirmed_graph,
        )
        if code != 2:
            return code
        graph, spec = await _graph_modify_loop(
            session, graph, spec, use_llm, api_key, spec_debug=spec_debug
        )
        spec = confirm_graph_session(session, graph, spec)
        confirmed_graph = session.current_constraint_graph


async def run(
    initial_intent: str,
    security_level: str,
    out_path: str,
    spec_debug: bool = False,
    *,
    legacy: bool = False,
) -> int:
    print(BANNER)
    api_key = os.getenv("OPENROUTER_API_KEY")
    use_llm = bool(api_key)

    if not use_llm:
        print("  Warning: OPENROUTER_API_KEY not set — chat uses registry prompts only.")
        print("  Generation still requires the key.\n")

    if use_spec_graph_v2() and not legacy:
        print("  Mode: Constraint Graph v2 (use --legacy for wizard pipeline)\n")
        return await run_graph(initial_intent, security_level, out_path, spec_debug)

    if legacy:
        print("  Mode: legacy wizard pipeline\n")
    return await run_legacy(initial_intent, security_level, out_path, spec_debug)


def main() -> None:
    args = _parse_args()
    spec_debug = args.spec_debug or os.getenv("NEXOPS_SPEC_DEBUG", "").lower() in ("1", "true", "yes")
    code = asyncio.run(
        run(
            args.intent,
            args.security_level,
            args.out,
            spec_debug=spec_debug,
            legacy=args.legacy,
        )
    )
    sys.exit(code)


if __name__ == "__main__":
    main()
