"""
test_distribution.py — Phase A Regression
Tests: distribution payout, no-self-anchor guard, convergence.
"""
import asyncio
import logging
import sys

from src.services.pipeline_engine import get_guarded_pipeline_engine

GREEN   = "\033[92m"
RED     = "\033[91m"
YELLOW  = "\033[93m"
CYAN    = "\033[96m"
MAGENTA = "\033[95m"
BOLD    = "\033[1m"
RESET   = "\033[0m"


class ColoredFormatter(logging.Formatter):
    COLORS = {logging.DEBUG: CYAN, logging.INFO: GREEN,
              logging.WARNING: YELLOW, logging.ERROR: RED, logging.CRITICAL: MAGENTA}
    def format(self, record):
        color = self.COLORS.get(record.levelno, RESET)
        record.msg = f"{color}{record.msg}{RESET}"
        return super().format(record)


sh = logging.StreamHandler(sys.stdout)
sh.setFormatter(ColoredFormatter("%(asctime)s [%(name)s] %(levelname)s: %(message)s"))
logging.basicConfig(level=logging.WARNING, handlers=[sh])
for lg in ["nexops.dsl_lint", "nexops.pipeline_engine", "nexops.resilient_llm"]:
    logging.getLogger(lg).setLevel(logging.INFO)


TESTS = [
    {
        "id": "D-01",
        "name": "Simple Bounty Payout",
        "intent": "release funds to a single recipient, authorized by the owner signature",
        "expect_mode": "distribution",
        "expect_no_self_anchor": True,
    },
    {
        "id": "D-02",
        "name": "Multi-sig Release to Recipient",
        "intent": "pay out contract funds to a recipient address after both alice and bob sign",
        "expect_mode": "distribution",
        "expect_no_self_anchor": True,
    },
    {
        "id": "D-03",
        "name": "Timelock Transfer",
        "intent": "transfer all funds to a fixed recipient wallet after a 30-day timeout",
        "expect_mode": "distribution",
        "expect_no_self_anchor": True,
    },
]


def check_self_anchor(code: str) -> bool:
    """Returns True if code contains this.activeBytecode (bad for distribution)."""
    import re
    return bool(re.search(r"this\.activeBytecode", code))


async def run_test(tc: dict, engine) -> bool:
    import time
    print(f"\n{CYAN}{BOLD}▶ [{tc['id']}] {tc['name']}{RESET}")
    t0 = time.time()

    r = await engine.generate_guarded(tc["intent"], security_level="high")
    elapsed = time.time() - t0

    if r["type"] == "success":
        d    = r["data"]
        code = d["code"]
        tg   = d["toll_gate"]
        mode = d["intent_model"].get("contract_type", "?")
        score = tg.get("structural_score", 0.0)
        viol  = len(tg["violations"])

        has_bad_anchor = check_self_anchor(code)
        anchor_ok = not has_bad_anchor

        mode_ok = mode == tc.get("expect_mode", mode)  # warn if wrong mode

        status = "✅ PASS" if (score == 1.0 and anchor_ok) else "⚠ PARTIAL"
        color  = GREEN if score == 1.0 and anchor_ok else YELLOW

        print(f"{color}  {status}  score={score:.2f}  viol={viol}  mode={mode}  anchor_clean={anchor_ok}  ({elapsed:.1f}s){RESET}")

        if not mode_ok:
            print(f"{YELLOW}  ⚠ Expected mode={tc['expect_mode']} but got mode={mode}{RESET}")
        if has_bad_anchor:
            print(f"{RED}  ❌ SELF-ANCHOR DETECTED: this.activeBytecode found in distribution contract!{RESET}")

        print(f"{CYAN}{code}{RESET}")
        return score == 1.0 and anchor_ok

    else:
        err = r.get("error", {})
        print(f"{RED}  ❌ FAIL ({elapsed:.1f}s): {err.get('message', '')}{RESET}")
        last = err.get("last_compiler_error", "")
        if last:
            print(f"{YELLOW}    {last[:120]}{RESET}")
        return False


async def main():
    print(f"\n{MAGENTA}{BOLD}{'='*60}{RESET}")
    print(f"{MAGENTA}{BOLD}  PHASE A — DISTRIBUTION MODE REGRESSION{RESET}")
    print(f"{MAGENTA}{BOLD}{'='*60}{RESET}\n")

    engine = get_guarded_pipeline_engine()
    results = [await run_test(tc, engine) for tc in TESTS]

    passed = sum(results)
    color  = GREEN if passed == len(TESTS) else (YELLOW if passed > 0 else RED)
    print(f"\n{color}{BOLD}  Result: {passed}/{len(TESTS)} passed{RESET}\n")


if __name__ == "__main__":
    asyncio.run(main())
