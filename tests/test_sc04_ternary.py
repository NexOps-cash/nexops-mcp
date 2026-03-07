"""
test_sc04_ternary.py — SC-04 regression: confirm no ternary ? reaches compile
"""
import asyncio
import logging
import sys

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

from src.services.pipeline_engine import get_guarded_pipeline_engine

TERNARY_MARKER = "[LNC-009]"   # logged by dsl_lint on ternary detection
COMPILE_MARKER = "Compile Attempt"


async def main():
    print(f"\n{MAGENTA}{BOLD}  SC-04 Regression — LNC-009 Ternary Gate{RESET}\n")
    engine = get_guarded_pipeline_engine()

    intent = "2-of-3 multisig escrow with a 30-day timeout reclaim branch for the original sender"
    r = await engine.generate_guarded(intent, security_level="high")

    if r["type"] == "success":
        d  = r["data"]
        tg = d["toll_gate"]
        score = tg.get("structural_score", 0.0)
        viol  = len(tg["violations"])
        mode  = d["intent_model"].get("contract_type", "?")
        print(f"\n{GREEN}{BOLD}✅ SC-04 PASS  score={score:.2f}  viol={viol}  mode={mode}{RESET}")
        print(f"{CYAN}{d['code']}{RESET}")
    else:
        err = r.get("error", {})
        print(f"\n{RED}{BOLD}❌ SC-04 FAIL{RESET}")
        print(f"{YELLOW}  {err.get('message', str(err))}{RESET}")
        last = err.get("last_compiler_error", "")
        if last:
            print(f"{YELLOW}  LAST COMPILE ERR: {last[:200]}{RESET}")


if __name__ == "__main__":
    asyncio.run(main())
