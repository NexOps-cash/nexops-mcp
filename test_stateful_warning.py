"""
test_stateful_warning.py — Phase B-lite Verification
Tests: LNC-012 Frozen State Guard (warning only).
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
# Ensure we see warnings
logging.getLogger("nexops.dsl_lint").setLevel(logging.WARNING) 
logging.getLogger("nexops.pipeline_engine").setLevel(logging.INFO)


TEST_CASE = {
    "id": "ST-01",
    "name": "Frozen Counter (Stateful, No Mutation)",
    "intent": "create a stateful counter contract that increments an integer count on each spend. The contract should perpetuate itself.",
    "expect_mode": "stateful", # or covenant
    "expect_warning": "LNC-012",
}


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

        # Check for LNC-012 warning in TollGateResult violations
        # Note: Warnings might be filtered out if strictness is high, but let's check raw violations list
        # We need to access the raw violations from the linter result if possible.
        # But generate_guarded returns TollGateResult which usually filters for errors?
        # Actually Phase3.validate returns ALL violations, but score calculation might ignore warnings.
        
        # Let's inspect the violations returned in 'd["toll_gate"]["violations"]'
        
        warnings = [v for v in tg["violations"] if v.get("rule_id") == "LNC-012"]
        has_warning = len(warnings) > 0
        
        status = "✅ PASS" if (score == 1.0) else "⚠ PARTIAL" # Warning shouldn't punish score much if severity is low?
        # But actually, warnings are just logged, they don't lower the score if weights are 0?
        # Let's assume warning present = SUCCESS for this test.
        
        if has_warning:
             print(f"{GREEN}  ✅ LNC-012 Warning Detected: {warnings[0]['message'][:60]}...{RESET}")
        else:
             print(f"{YELLOW}  ⚠ LNC-012 Warning MISSING (Did the contract actually mutate steps?){RESET}")
             # Check code for mutation
             if "LockingBytecode" in code:
                  print(f"{CYAN}  (Code seems to have LockingBytecode construction - maybe it mutated?){RESET}")

        print(f"{GREEN}  {status}  score={score:.2f}  viol={viol}  mode={mode} ({elapsed:.1f}s){RESET}")
        print(f"{CYAN}{code}{RESET}")
        return has_warning # We WANT the warning

    else:
        err = r.get("error", {})
        print(f"{RED}  ❌ FAIL ({elapsed:.1f}s): {err.get('message', '')}{RESET}")
        return False


async def main():
    print(f"\n{MAGENTA}{BOLD}{'='*60}{RESET}")
    print(f"{MAGENTA}{BOLD}  PHASE B-lite — FROZEN STATE DETECTION{RESET}")
    print(f"{MAGENTA}{BOLD}{'='*60}{RESET}\n")

    engine = get_guarded_pipeline_engine()
    await run_test(TEST_CASE, engine)


if __name__ == "__main__":
    asyncio.run(main())
