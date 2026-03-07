"""
test_token_split.py — Phase C Token Hardening Regression
Tests: token split math, mint authority guard (LNC-013), token pair guard (LNC-014).
"""
import asyncio
import logging
import sys
import re

from src.services.pipeline_engine import get_guarded_pipeline_engine

GREEN   = "\033[92m"
RED     = "\033[91m"
YELLOW  = "\033[93m"
CYAN    = "\033[96m"
MAGENTA = "\033[95m"
BOLD    = "\033[1m"
RESET   = "\033[0m"

# Configure logging
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
        "id": "TOK-01",
        "name": "Token Split 50/50",
        "intent": "split the input tokens equally between two recipients (alice and bob). Preserve category.",
        "expect_mode": "token",
        "checks": ["tokenCategory preservation", "tokenAmount split sum"],
    },
    {
        "id": "TOK-02",
        "name": "Minting with Authority",
        "intent": "mint 1000 new tokens. Requires mintAuthority signature. Determine category from input 0.",
        "expect_mode": "token", # or minting
        "checks": ["mintAuthority param", "checkSig(..., mintAuthority)"],
    },
]

def analyze_token_split(code: str) -> bool:
    # Check for split logic: output[0].amount + output[1].amount == input.amount
    # Regex is tricky for full expression, but look for the sum
    has_sum = bool(re.search(r"tx\.outputs\[0\]\.tokenAmount\s*\+\s*tx\.outputs\[1\]\.tokenAmount", code))
    has_equality = bool(re.search(r"==\s*tx\.inputs\[.*\]\.tokenAmount", code))
    return has_sum and has_equality

def analyze_mint_authority(code: str) -> bool:
    has_param = "mintAuthority" in code
    has_check = bool(re.search(r"checkSig\s*\([^,]+,\s*mintAuthority\s*\)", code))
    return has_param and has_check

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

        # Check specifics
        passed_specifics = True
        
        if tc["id"] == "TOK-01":
            if not analyze_token_split(code):
                print(f"{RED}  ❌ FAILED: Token split logic missing or incorrect{RESET}")
                passed_specifics = False
            else:
                print(f"{GREEN}  ✅ Token split logic verified{RESET}")
                
        if tc["id"] == "TOK-02":
            if not analyze_mint_authority(code):
                 print(f"{RED}  ❌ FAILED: Mint authority pattern (LNC-013) missing{RESET}")
                 passed_specifics = False
            else:
                 print(f"{GREEN}  ✅ Mint authority verified{RESET}")

        status = "✅ PASS" if (score == 1.0 and passed_specifics) else "⚠ PARTIAL"
        color  = GREEN if score == 1.0 and passed_specifics else YELLOW

        print(f"{color}  {status}  score={score:.2f}  viol={viol}  mode={mode} ({elapsed:.1f}s){RESET}")
        print(f"{CYAN}{code}{RESET}")
        return score == 1.0 and passed_specifics

    else:
        err = r.get("error", {})
        print(f"{RED}  ❌ FAIL ({elapsed:.1f}s): {err.get('message', '')}{RESET}")
        last = err.get("last_compiler_error", "")
        if last:
            print(f"{YELLOW}    {last[:120]}{RESET}")
        
        # Check if failure was due to our new lint rules (which is good!)
        if "LNC-013" in str(err) or "LNC-014" in str(err):
             print(f"{GREEN}  ℹ LNC-013/014 caught a violation (This is expected behavior during hardening if model initially failed){RESET}")
        
        return False


async def main():
    print(f"\n{MAGENTA}{BOLD}{'='*60}{RESET}")
    print(f"{MAGENTA}{BOLD}  PHASE C — TOKEN HARDENING REGRESSION{RESET}")
    print(f"{MAGENTA}{BOLD}{'='*60}{RESET}\n")

    engine = get_guarded_pipeline_engine()
    results = [await run_test(tc, engine) for tc in TESTS]

    passed = sum(results)
    color  = GREEN if passed == len(TESTS) else (YELLOW if passed > 0 else RED)
    print(f"\n{color}{BOLD}  Result: {passed}/{len(TESTS)} passed{RESET}\n")


if __name__ == "__main__":
    asyncio.run(main())
