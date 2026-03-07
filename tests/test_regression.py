"""
NexOps — Regression & Performance Comparison Test
Diagnostic only. Does NOT modify pipeline code.

Metrics captured per run:
  - Phase 2 prompt length (sys + user chars)
  - Model used (logged by providers)
  - Generation attempt count
  - Fix loop attempt count
  - Language guard triggers
  - Toll Gate violation count
  - Compile loop exhaustion
  - Final structural score
  - Total runtime
  - Output contract length (chars)
"""

import asyncio
import logging
import time
import re
import sys
import json
from io import StringIO
from typing import Dict, Any

# ── Set up logging capture ────────────────────────────────────────────────────

class MetricsLogCapture(logging.Handler):
    """Captures log records for metric extraction."""
    def __init__(self):
        super().__init__()
        self.records: list[logging.LogRecord] = []

    def emit(self, record):
        self.records.append(record)

    def messages(self):
        return [self.format(r) for r in self.records]

    def clear(self):
        self.records.clear()


# ── Bootstrap environment ─────────────────────────────────────────────────────

from dotenv import load_dotenv
load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)

capture = MetricsLogCapture()
capture.setFormatter(logging.Formatter("%(message)s"))
logging.getLogger("nexops").addHandler(capture)

# ── Import pipeline ───────────────────────────────────────────────────────────

from src.services.pipeline_engine import get_guarded_pipeline_engine


# ── Test intents ──────────────────────────────────────────────────────────────

TEST_CASES = [
    ("1_multisig",   "simple multisig 2 of 2"),
    ("2_escrow",     "2-of-3 multisig escrow with 30 day timeout reclaim"),
    ("3_vesting",    "token vesting contract with 90 day cliff"),
]

# ── Metric extraction helpers ────────────────────────────────────────────────

def _extract_metrics(logs: list[str], result: Dict[str, Any], elapsed: float) -> Dict[str, Any]:
    full_log = "\n".join(logs)

    # Prompt length
    prompt_match = re.search(r"\[Phase2\] Prompt length: (\d+) chars \(sys=(\d+), user=(\d+)\)", full_log)
    total_chars  = int(prompt_match.group(1)) if prompt_match else "N/A"
    sys_chars    = int(prompt_match.group(2)) if prompt_match else "N/A"
    user_chars   = int(prompt_match.group(3)) if prompt_match else "N/A"

    # Generation attempts
    gen_attempts = len(re.findall(r"--- Generation Attempt", full_log))
    # Fix attempts
    fix_attempts = len(re.findall(r"Compile Attempt \d+\.\.\.", full_log))
    # Deterministic fixes
    det_fixes    = len(re.findall(r"\[Fix\] Deterministic:", full_log))
    # Language guard
    lg_triggers  = len(re.findall(r"Language Guard failed", full_log))
    # Compile exhaustion
    compile_exhausted = "yes" if "Compile loop exhausted" in full_log else "no"
    # Toll gate violations
    tg_match     = re.search(r"Phase 3 complete:.*violations=(\d+)", full_log)
    tg_violations = int(tg_match.group(1)) if tg_match else 0
    # Structural score
    score_match  = re.search(r"score=([0-9.]+)", full_log)
    struct_score = float(score_match.group(1)) if score_match else "N/A"

    # -- Targeted Phase 2 Model Extraction --
    # Find the block in logs after "[Phase2] Prompt length..."
    phase2_start = full_log.find("[Phase2] Prompt length:")
    p2_logs = full_log[phase2_start:] if phase2_start != -1 else full_log

    # Model actually used (from provider response log in Phase 2)
    model_match  = re.search(r"\[(?:OpenRouter|Groq|OpenAI)\] Response from ([^\s]+)", p2_logs)
    actual_model = model_match.group(1) if model_match else "unknown"

    # Success label (Phase 2 primary label)
    success_match = re.search(r"\[LLM\] Success: (.+?) responded", p2_logs)
    success_label = success_match.group(1) if success_match else "unknown"

    # Contract quality
    if result.get("type") == "success":
        code = result["data"]["code"]
        output_chars = len(code)
        status = "SUCCESS"
    else:
        code = ""
        output_chars = 0
        status = "FAILED: " + result.get("error", {}).get("message", "?")

    return {
        "status": status,
        "actual_model": actual_model,
        "success_label": success_label,
        "prompt_total_chars": total_chars,
        "prompt_sys_chars": sys_chars,
        "prompt_user_chars": user_chars,
        "gen_attempts": gen_attempts,
        "fix_attempts_llm": fix_attempts - det_fixes,
        "fix_attempts_det": det_fixes,
        "language_guard_triggers": lg_triggers,
        "compile_exhausted": compile_exhausted,
        "toll_gate_violations": tg_violations,
        "structural_score": struct_score,
        "output_chars": output_chars,
        "elapsed_sec": round(elapsed, 2),
        "code": code,
    }


# ── Print helpers ────────────────────────────────────────────────────────────

def _print_divider(title=""):
    line = "─" * 72
    if title:
        pad = (70 - len(title)) // 2
        print(f"\n╔{line}╗")
        print(f"║{' ' * pad}{title}{' ' * (70 - pad - len(title))}║")
        print(f"╚{line}╝")
    else:
        print(f"\n{line}")

def _print_metrics(label: str, m: Dict[str, Any]):
    _print_divider(label)
    print(f"  Status         : {m['status']}")
    print(f"  P2 Model Label : {m['success_label']}")
    print(f"  P2 Actual Model: {m['actual_model']}")
    print(f"  Prompt Chars   : {m['prompt_total_chars']} (sys={m['prompt_sys_chars']}, user={m['prompt_user_chars']})")
    print(f"  Gen Attempts   : {m['gen_attempts']}")
    print(f"  Fix Attempts   : {m['fix_attempts_llm']} LLM + {m['fix_attempts_det']} deterministic")
    print(f"  Lang Guard Hit : {m['language_guard_triggers']}")
    print(f"  Compile Exhaust: {m['compile_exhausted']}")
    print(f"  TollGate Viol. : {m['toll_gate_violations']}")
    print(f"  Struct. Score  : {m['structural_score']}")
    print(f"  Output Chars   : {m['output_chars']}")
    print(f"  Elapsed        : {m['elapsed_sec']}s")
    if m["code"]:
        print(f"\n  ── Generated Contract ──────────────────────────────────────────")
        for line in m["code"].split("\n"):
            print(f"  {line}")


# ── Main runner ───────────────────────────────────────────────────────────────

async def run_all():
    # Load Run 1 Results if they exist
    prev_path = "regression_results.json"
    run1_results = {}
    if os.path.exists(prev_path):
        try:
            with open(prev_path, "r", encoding="utf-8") as f:
                run1_results = json.load(f)
            print(f"  [Init] Loaded Run 1 results from {prev_path}")
        except:
             print(f"  [Init] Failed to load {prev_path}, assuming fresh run.")

    import os as _os
    engine = get_guarded_pipeline_engine()
    results_by_label = {}

    for (label, intent) in TEST_CASES:
        _print_divider(f"TEST: {label}")
        print(f"  Intent: \"{intent}\"")
        capture.clear()

        t0 = time.monotonic()
        try:
            result = await engine.generate_guarded(intent, security_level="high")
        except Exception as e:
            result = {"type": "error", "error": {"message": str(e)}}
        elapsed = time.monotonic() - t0

        logs = capture.messages()
        m = _extract_metrics(logs, result, elapsed)
        _print_metrics(label, m)
        results_by_label[label] = m

    # ── Comparison Summary ────────────────────────────────────────────────────
    _print_divider("COMPARISON: RUN 1 (Old) vs RUN 2 (DSL Fixes)")
    
    headers = ["Test", "Metric", "Run 1 (Old)", "Run 2 (New)", "Δ"]
    print(f"\n  {'Test':<14} {'Metric':<28} {'Run 1':>12} {'Run 2':>12} {'Δ':>8}")
    print(f"  {'─'*14} {'─'*28} {'─'*12} {'─'*12} {'─'*8}")

    for (label, _) in TEST_CASES:
        r1 = run1_results.get(label, {})
        r2 = results_by_label.get(label, {})
        
        metrics_to_compare = [
            ("Prompt Chars", "prompt_total_chars"),
            ("Gen Attempts", "gen_attempts"),
            ("Fix Attempts (LLM)", "fix_attempts_llm"),
            ("TollGate Viol.", "toll_gate_violations"),
            ("Struct. Score", "structural_score")
        ]
        
        for i, (metric_name, key) in enumerate(metrics_to_compare):
            lbl = label if i == 0 else ""
            val1 = r1.get(key, "?")
            val2 = r2.get(key, "?")
            
            try:
                if isinstance(val1, (int, float)) and isinstance(val2, (int, float)):
                    if metric_name == "Struct. Score":
                        delta = f"{val2 - val1:+.2f}"
                    else:
                        delta = f"{val2 - val1:+d}"
                else:
                    delta = "─"
            except:
                delta = "─"
            
            # Format comparison values
            v1_str = f"{val1:.2f}" if isinstance(val1, float) else str(val1)
            v2_str = f"{val2:.2f}" if isinstance(val2, float) else str(val2)
            
            print(f"  {lbl:<14} {metric_name:<28} {v1_str:>12} {v2_str:>12} {delta:>8}")
        print()

    # ── Cost Estimate ─────────────────────────────────────────────────────────
    _print_divider("COST ESTIMATE (Claude Sonnet 4.6 @ $3/$12 per 1M tok)")
    input_rate  = 3.0 / 1_000_000   # $ per input token
    output_rate = 12.0 / 1_000_000  # $ per output token

    for label, m in results_by_label.items():
        # rough token estimate: ~3.5 chars per token (optimistic)
        in_tokens  = int(m.get("prompt_total_chars", 0) / 3.5) * m.get("gen_attempts", 1)
        out_tokens = int(m.get("output_chars", 0) / 3.5) * m.get("gen_attempts", 1)
        cost = in_tokens * input_rate + out_tokens * output_rate
        print(f"  {label:<14}: ~{in_tokens} in / ~{out_tokens} out → ${cost:.5f} per run")

    # ── Save results JSON ─────────────────────────────────────────────────────
    out_path = "regression_results_run2.json"
    serialisable = {k: {sk: sv for sk, sv in v.items() if sk != "code"} for k, v in results_by_label.items()}
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(serialisable, f, indent=2)
    print(f"\n  Results saved → {out_path}")


if __name__ == "__main__":
    import os
    asyncio.run(run_all())
