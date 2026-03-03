"""
test_golden_escrow.py
=====================
Standalone test for the Golden Template pipeline.
Sends the escrow intent directly through the pipeline engine (no WebSocket).
Logs every LLM raw response at each attempt, before guards run.

Run:
    python test_golden_escrow.py
"""

import asyncio
import logging
import time
import sys
from typing import Dict, Any

from src.services.pipeline_engine import get_guarded_pipeline_engine

# ── ANSI Colors ────────────────────────────────────────────────────────────────
GREEN   = "\033[92m"
RED     = "\033[91m"
YELLOW  = "\033[93m"
BLUE    = "\033[94m"
CYAN    = "\033[96m"
MAGENTA = "\033[95m"
RESET   = "\033[0m"

SEP  = "-" * 65
SEP2 = "=" * 65

# ── Colored Logging ────────────────────────────────────────────────────────────
class ColoredFormatter(logging.Formatter):
    COLORS = {
        logging.DEBUG:    CYAN,
        logging.INFO:     GREEN,
        logging.WARNING:  YELLOW,
        logging.ERROR:    RED,
        logging.CRITICAL: MAGENTA,
    }

    def format(self, record):
        color = self.COLORS.get(record.levelno, RESET)
        msg = str(record.msg)
        record.msg = f"{color}{msg}{RESET}" if RESET not in msg else f"{color}{msg}"
        return super().format(record)

sh = logging.StreamHandler(sys.stdout)
sh.setFormatter(ColoredFormatter("%(asctime)s [%(name)s] %(levelname)s: %(message)s"))
logging.basicConfig(level=logging.INFO, handlers=[sh])
logger = logging.getLogger("nexops.golden_test")

# ── Test Target ────────────────────────────────────────────────────────────────
TEST = {
    "id":     "G-01",
    "name":   "2-of-3 Escrow with NFT Custody + 1% Fee",
    "intent": "Create a 2-of-3 escrow with NFT custody, refund after 800000, and add 1% platform fee to feeRecipient",
}

# ── LLM Response Interceptor ──────────────────────────────────────────────────
# Monkey-patch parse_golden_llm_response so we print every raw LLM output
# before the guards inspect it (attempt N of 3 is visible even on retry).
import knowledge.golden.golden_prompt as _gp

_original_parse = _gp.parse_golden_llm_response
_attempt_counter = [0]

def _logging_parse(raw: str, required_parameters, template_param_count):
    _attempt_counter[0] += 1
    attempt = _attempt_counter[0]
    print(f"\n{MAGENTA}{SEP}{RESET}")
    print(f"{MAGENTA}  [LLM RAW OUTPUT] Attempt {attempt}{RESET}")
    print(f"{MAGENTA}{SEP}{RESET}")
    print(f"{CYAN}{raw}{RESET}")
    print(f"{MAGENTA}{SEP}{RESET}\n")
    return _original_parse(raw, required_parameters, template_param_count)

_gp.parse_golden_llm_response = _logging_parse

# Also patch pipeline.py's reference since it imported the name directly
import src.services.pipeline as _pipe
_pipe.parse_golden_llm_response = _logging_parse

# ── Runner ────────────────────────────────────────────────────────────────────
async def run_golden_test(engine) -> Dict[str, Any]:
    _attempt_counter[0] = 0  # reset per test run

    print(f"\n{BLUE}{SEP2}{RESET}")
    print(f"{BLUE}  GOLDEN TEMPLATE TEST: {TEST['name']}{RESET}")
    print(f"{BLUE}{SEP2}{RESET}")
    print(f"{CYAN}  Intent: {TEST['intent']}{RESET}\n")

    start = time.time()
    try:
        result = await engine.generate_guarded(TEST["intent"], security_level="high")
    except RuntimeError as e:
        elapsed = time.time() - start
        print(f"\n{RED}{SEP}{RESET}")
        print(f"{RED}  [HARD FAIL] Pipeline raised RuntimeError:{RESET}")
        print(f"{RED}  {e}{RESET}")
        print(f"{RED}  Elapsed: {elapsed:.1f}s{RESET}")
        print(f"{RED}{SEP}{RESET}\n")
        return {"routed_golden": False, "score": 0, "violations": -1}

    elapsed = time.time() - start

    print(f"\n{BLUE}{SEP}{RESET}")

    if result["type"] == "success":
        data = result["data"]
        contract_type = data["intent_model"].get("contract_type", "unknown")
        tg            = data["toll_gate"]
        violations    = tg.get("violations", [])
        score         = tg.get("structural_score", 0.0)
        code          = data["code"]
        fallback_used = data.get("fallback_used", False)

        routed_golden = contract_type in (
            "escrow_2of3_nft", "refundable_crowdfund", "dutch_auction", "linear_vesting"
        )
        route_label = f"{GREEN}GOLDEN ({contract_type}){RESET}" if routed_golden else \
                      f"{YELLOW}FREE SYNTHESIS ({contract_type}){RESET}"
        fallback_label = f" {RED}[FALLBACK USED]{RESET}" if fallback_used else ""

        print(f"  Route:       {route_label}{fallback_label}")
        print(f"  TG Score:    {GREEN}{score:.2f}{RESET}")
        print(f"  Violations:  {len(violations)}")
        print(f"  Elapsed:     {elapsed:.1f}s")
        print(f"  LLM Calls:   {_attempt_counter[0]}")

        if violations:
            for v in violations[:5]:
                print(f"    {YELLOW}!  {v}{RESET}")

        print(f"\n{GREEN}{SEP}{RESET}")
        print(f"{GREEN}  Generated Contract:{RESET}\n")
        try:
            print(CYAN + code + RESET)
        except UnicodeEncodeError:
            sys.stdout.buffer.write((CYAN + code + RESET).encode("utf-8", errors="replace"))
            sys.stdout.buffer.write(b"\n")
        print(f"{GREEN}{SEP}{RESET}")

        if fallback_used:
            print(f"\n{YELLOW}[FALLBACK] Fallback template used -- pipeline did not converge{RESET}\n")
        elif routed_golden and len(violations) == 0:
            print(f"\n{GREEN}[PASS] GOLDEN PATH -- PERFECT CONVERGENCE{RESET}\n")
        elif routed_golden:
            print(f"\n{YELLOW}[PARTIAL] GOLDEN PATH -- violations present{RESET}\n")
        else:
            print(f"\n{YELLOW}[WARN] FREE SYNTHESIS -- check Phase 1 normalization{RESET}\n")

        return {
            "routed_golden": routed_golden,
            "contract_type": contract_type,
            "score": score,
            "violations": len(violations),
            "code_len": len(code),
        }

    else:
        error = result.get("error", {})
        print(f"\n{RED}[FAIL] {error.get('message', 'Unknown error')}{RESET}")
        last_err = error.get("last_compiler_error", "")
        if last_err:
            print(f"{RED}  Compiler: {last_err[:120]}{RESET}")
        print()
        return {"routed_golden": False, "score": 0, "violations": -1}


# ── Entry Point ────────────────────────────────────────────────────────────────
async def main():
    print(f"\n{MAGENTA}Initializing Guarded Pipeline Engine...{RESET}")
    engine = get_guarded_pipeline_engine()
    await run_golden_test(engine)


if __name__ == "__main__":
    asyncio.run(main())
