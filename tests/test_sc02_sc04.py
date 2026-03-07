"""
test_sc02_sc04.py — Targeted regression for SC-02 and SC-04
"""
import asyncio
import logging
import time
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
    COLORS = {
        logging.DEBUG:    CYAN,
        logging.INFO:     GREEN,
        logging.WARNING:  YELLOW,
        logging.ERROR:    RED,
        logging.CRITICAL: MAGENTA,
    }
    def format(self, record):
        color = self.COLORS.get(record.levelno, RESET)
        record.msg = f"{color}{record.msg}{RESET}"
        return super().format(record)

sh = logging.StreamHandler(sys.stdout)
sh.setFormatter(ColoredFormatter("%(asctime)s [%(name)s] %(levelname)s: %(message)s"))
logging.basicConfig(level=logging.INFO, handlers=[sh])

TESTS = [
    {"id": "SC-02", "name": "2-of-2 Split 50/50",
     "intent": "2-of-2 multisig that splits all funds 50/50 equally to two fixed pubkey recipients"},
    {"id": "SC-04", "name": "2-of-3 Escrow with Timeout",
     "intent": "2-of-3 multisig escrow with a 30-day timeout reclaim branch for the original sender"},
]

async def run(tc, engine):
    print(f"\n{CYAN}{BOLD}▶ [{tc['id']}] {tc['name']}{RESET}")
    t0 = time.time()
    try:
        raw = await engine.generate_guarded(tc["intent"], security_level="high")
        elapsed = time.time() - t0
        if raw["type"] == "success":
            d  = raw["data"]
            tg = d["toll_gate"]
            score = tg.get("structural_score", 0.0)
            viol  = len(tg["violations"])
            mode  = d["intent_model"].get("contract_type", "?")
            print(f"{GREEN}  ✅ PASS  score={score:.2f}  viol={viol}  mode={mode}  ({elapsed:.1f}s){RESET}")
            print(f"{CYAN}{d['code']}{RESET}")
            return True
        else:
            err = raw.get("error", {})
            print(f"{RED}  ❌ FAIL  ({elapsed:.1f}s){RESET}")
            print(f"{YELLOW}     {err.get('message', err)}{RESET}")
            return False
    except Exception as e:
        print(f"{MAGENTA}  💥 CRASH: {e}{RESET}")
        return False

async def main():
    print(f"\n{MAGENTA}{BOLD}  SC-02 + SC-04 REGRESSION — after structural fixes{RESET}\n")
    engine = get_guarded_pipeline_engine()
    results = [await run(tc, engine) for tc in TESTS]
    passed = sum(results)
    color = GREEN if passed == 2 else (YELLOW if passed == 1 else RED)
    print(f"\n{color}{BOLD}  Result: {passed}/2 passed{RESET}\n")

if __name__ == "__main__":
    asyncio.run(main())
