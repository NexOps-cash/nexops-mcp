"""
test_coverage_stability.py — Pattern Coverage Stability Diagnostic

Three new intents:
  A. split-multisig:   2-of-2 multisig with 50/50 fund split
  B. timelock:         single beneficiary unlockable after timestamp
  C. token-burn:       owner-only token burn contract

Captures per-run:
  - Phase 2 prompt chars (sys / user)
  - Gen attempts
  - DSL lint violations (rule_id + line)
  - Compile errors (exact last message)
  - TollGate violations
  - Final struct score
  - Output chars
  - Cost estimate

DO NOT modify rules.
DO NOT increase retries.
"""

import asyncio
import logging
import time
import re
import sys
import json
import os

# ── Logging setup ─────────────────────────────────────────────────────────────

# ANSI Colors
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
CYAN = "\033[96m"
MAGENTA = "\033[95m"
RESET = "\033[0m"

class ColoredFormatter(logging.Formatter):
    COLORS = {
        logging.DEBUG: CYAN,
        logging.INFO: GREEN,
        logging.WARNING: YELLOW,
        logging.ERROR: RED,
        logging.CRITICAL: MAGENTA,
    }

    def format(self, record):
        color = self.COLORS.get(record.levelno, RESET)
        record.msg = f"{color}{record.msg}{RESET}"
        return super().format(record)

class CapturingHandler(logging.Handler):
    def __init__(self):
        super().__init__()
        self.records: list[logging.LogRecord] = []

    def emit(self, record):
        self.records.append(record)

    def messages(self) -> list[str]:
        return [self.format(r) for r in self.records]

    def clear(self):
        self.records.clear()


from dotenv import load_dotenv
load_dotenv()

# Setup primary handler
sh = logging.StreamHandler(sys.stdout)
sh.setFormatter(ColoredFormatter("%(asctime)s [%(name)s] %(levelname)s: %(message)s"))

logging.basicConfig(
    level=logging.INFO,
    handlers=[sh],
)

cap = CapturingHandler()
cap.setFormatter(logging.Formatter("%(message)s"))
logging.getLogger("nexops").addHandler(cap)

# ── Test suite ────────────────────────────────────────────────────────────────

TEST_CASES = [
    (
        "A_split_multisig",
        "2-of-2 multisig that splits funds 50/50 to two fixed pubkeys",
    ),
    (
        "B_timelock",
        "single beneficiary timelock contract unlockable after timestamp",
    ),
    (
        "C_token_burn",
        "token contract that allows only owner to burn tokens",
    ),
]

# ── Metric extraction ─────────────────────────────────────────────────────────

def _extract(logs: list[str], result: dict, elapsed: float) -> dict:
    log = "\n".join(logs)

    # Prompt chars
    pm = re.search(r"\[Phase2\] Prompt length: (\d+) chars \(sys=(\d+), user=(\d+)\)", log)
    total_chars = int(pm.group(1)) if pm else "N/A"
    sys_chars   = int(pm.group(2)) if pm else "N/A"
    user_chars  = int(pm.group(3)) if pm else "N/A"

    # Gen attempts
    gen_attempts  = len(re.findall(r"--- Generation Attempt", log))

    # DSL lint violations — collect ALL [DSLLint] lines
    lint_lines = re.findall(r"\[DSLLint\] (LNC-\S+ L\d+: .+)", log)
    lint_passed = bool(re.search(r"\[DSLLint\] PASSED", log))

    # Compile errors — extract the last compile error seen
    compile_errors = re.findall(r"Compile failed: (.+?)\. Attempting", log)
    last_compile_error = compile_errors[-1] if compile_errors else "none"

    # Fix attempts (LLM)
    fix_attempts = len(re.findall(r"Compile Attempt \d+\.\.\.", log))

    # Compile exhausted
    compile_exhausted = "yes" if "Compile loop exhausted" in log else "no"

    # TollGate violations
    tg_match      = re.search(r"Phase 3 complete:.*violations=(\d+)", log)
    tg_violations = int(tg_match.group(1)) if tg_match else 0

    # Structural score
    sm    = re.search(r"score=([0-9.]+)", log)
    score = float(sm.group(1)) if sm else "N/A"

    # contract_mode
    mode_m = re.search(r"Generation Attempt \d+ \(mode=([^)]*)\)", log)
    contract_mode = mode_m.group(1) if mode_m else "unknown"

    # Actual model
    model_m  = re.search(r"\[(?:OpenRouter|Groq|OpenAI)\] Response from ([^\s]+)", log)
    actual_model = model_m.group(1) if model_m else "unknown"

    # Output
    if result.get("type") == "success":
        code         = result["data"]["code"]
        output_chars = len(code)
        status       = "SUCCESS"
    else:
        code         = ""
        output_chars = 0
        msg          = result.get("error", {}).get("message", "?")
        status       = f"FAILED: {msg}"

    return {
        "status":             status,
        "contract_mode":      contract_mode,
        "actual_model":       actual_model,
        "prompt_total":       total_chars,
        "prompt_sys":         sys_chars,
        "prompt_user":        user_chars,
        "gen_attempts":       gen_attempts,
        "fix_attempts_llm":   fix_attempts,
        "compile_exhausted":  compile_exhausted,
        "lint_passed":        lint_passed,
        "lint_violations":    lint_lines,          # list of "LNC-XXX L<n>: message"
        "last_compile_error": last_compile_error,
        "tg_violations":      tg_violations,
        "struct_score":       score,
        "output_chars":       output_chars,
        "elapsed_sec":        round(elapsed, 2),
        "code":               code,
    }


# ── Print helpers ─────────────────────────────────────────────────────────────

_LINE = "─" * 72

def _header(title: str):
    pad = (70 - len(title)) // 2
    print(f"\n╔{_LINE}╗")
    print(f"║{' ' * pad}{title}{' ' * (70 - pad - len(title))}║")
    print(f"╚{_LINE}╝")


def _print_run(label: str, intent: str, m: dict):
    _header(f"TEST: {label}")
    print(f"  Intent        : \"{intent}\"")
    print(f"  Status        : {m['status']}")
    print(f"  Contract Mode : {m['contract_mode']}")
    print(f"  Model Used    : {m['actual_model']}")
    print(f"  Prompt Chars  : {m['prompt_total']} (sys={m['prompt_sys']}, user={m['prompt_user']})")
    print(f"  Gen Attempts  : {m['gen_attempts']}")
    print(f"  Fix Attempts  : {m['fix_attempts_llm']} LLM")
    print(f"  Compile Exh.  : {m['compile_exhausted']}")
    print()
    # DSL lint
    if m["lint_violations"]:
        print(f"  DSL Lint      : FAIL ({len(m['lint_violations'])} violations)")
        for v in m["lint_violations"]:
            print(f"    ✗ {v}")
    else:
        print(f"  DSL Lint      : {'PASS' if m['lint_passed'] else 'no lint run'}")
    # Compile error
    if m["last_compile_error"] != "none":
        print(f"  Compile Error : {m['last_compile_error'][:120]}")
    else:
        print(f"  Compile Error : none")
    print(f"  TollGate Viol.: {m['tg_violations']}")
    print(f"  Struct. Score : {m['struct_score']}")
    print(f"  Output Chars  : {m['output_chars']}")
    print(f"  Elapsed       : {m['elapsed_sec']}s")
    if m["code"]:
        print(f"\n  ── Generated Contract {'─' * 50}")
        for ln in m["code"].splitlines():
            print(f"  {ln}")


# ── Summary table ─────────────────────────────────────────────────────────────

def _print_summary(results: dict):
    _header("PATTERN COVERAGE STABILITY — SUMMARY TABLE")

    col_w = [24, 20, 10, 10, 10, 8, 10, 8]
    hdr = f"  {'Test':<24} {'Intent snippet':<20} {'Mode':<10} {'Score':<10} {'TG Viol':<10} {'Fixes':<8} {'Output':<10} {'Status':<8}"
    print(f"\n{hdr}")
    print(f"  {'─'*24} {'─'*20} {'─'*10} {'─'*10} {'─'*10} {'─'*8} {'─'*10} {'─'*8}")

    for label, intent in TEST_CASES:
        m = results.get(label, {})
        score   = f"{m.get('struct_score', 'N/A')}"
        tg      = str(m.get("tg_violations", "?"))
        fixes   = str(m.get("fix_attempts_llm", "?"))
        out     = str(m.get("output_chars", "?"))
        mode    = m.get("contract_mode", "?")
        st      = "OK" if m.get("status", "").startswith("SUCCESS") else "FAIL"
        snip    = intent[:18] + ".." if len(intent) > 18 else intent

        print(f"  {label:<24} {snip:<20} {mode:<10} {score:<10} {tg:<10} {fixes:<8} {out:<10} {st:<8}")

    print()

    # Verbose lint + compile column
    _header("DSL LINT & COMPILE DETAILS PER TEST")
    for label, intent in TEST_CASES:
        m = results.get(label, {})
        print(f"\n  [{label}]")
        lv = m.get("lint_violations", [])
        if lv:
            for v in lv:
                print(f"    Lint  ✗  {v}")
        else:
            print(f"    Lint  ✓  PASSED")
        ce = m.get("last_compile_error", "none")
        if ce != "none":
            print(f"    Compile ✗  {ce[:110]}")
        else:
            print(f"    Compile ✓  none")


# ── Cost estimate ─────────────────────────────────────────────────────────────

def _print_cost(results: dict):
    _header("COST ESTIMATE (Sonnet 4.6 @ $3/$12 per 1M tok)")
    input_rate  = 3.0  / 1_000_000
    output_rate = 12.0 / 1_000_000
    for label, _ in TEST_CASES:
        m = results.get(label, {})
        pts = m.get("prompt_total", 0) or 0
        ocs = m.get("output_chars", 0) or 0
        ga  = m.get("gen_attempts", 1) or 1
        in_tok  = int(pts / 3.5) * ga
        out_tok = int(ocs / 3.5) * ga
        cost    = in_tok * input_rate + out_tok * output_rate
        print(f"  {label:<24}: ~{in_tok} in / ~{out_tok} out → ${cost:.5f}")


# ── Runner ────────────────────────────────────────────────────────────────────

async def run():
    from src.services.pipeline_engine import get_guarded_pipeline_engine
    engine = get_guarded_pipeline_engine()
    results = {}

    for label, intent in TEST_CASES:
        cap.clear()
        t0 = time.monotonic()
        try:
            result = await engine.generate_guarded(intent, security_level="high")
        except Exception as e:
            result = {"type": "error", "error": {"message": str(e)}}
        elapsed = time.monotonic() - t0

        m = _extract(cap.messages(), result, elapsed)
        _print_run(label, intent, m)
        results[label] = m

    _print_summary(results)
    _print_cost(results)

    # Save
    out_path = "coverage_stability_results.json"
    serialisable = {k: {sk: sv for sk, sv in v.items() if sk != "code"} for k, v in results.items()}
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(serialisable, f, indent=2)
    print(f"\n  Results saved → {out_path}")


if __name__ == "__main__":
    asyncio.run(run())
