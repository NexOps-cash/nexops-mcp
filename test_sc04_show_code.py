"""
test_sc04_show_code.py — Dump the Phase2A raw output to see what's hitting compile
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

# Patch: monkey-patch pipeline_engine to intercept generated code BEFORE lint
import src.services.pipeline_engine as pe_mod

_orig_generate = pe_mod.GuardedPipelineEngine.generate_guarded.__wrapped__ if hasattr(
    pe_mod.GuardedPipelineEngine.generate_guarded, '__wrapped__') else None

intercepted_codes = []

# Patch Phase2 to record generated code
import src.services.pipeline as pipeline_mod
_orig_phase2_run = pipeline_mod.Phase2.run

async def _patched_phase2_run(ir, **kwargs):
    code = await _orig_phase2_run(ir, **kwargs)
    intercepted_codes.append(("Phase2", code))
    return code

pipeline_mod.Phase2.run = _patched_phase2_run

# Also patch compiler to record what it receives
import src.services.compiler as compiler_mod
_orig_compile = compiler_mod.CompilerService.compile

@staticmethod
def _patched_compile(code):
    intercepted_codes.append(("Compile", code))
    return _orig_compile(code)

compiler_mod.CompilerService.compile = _patched_compile

class ColoredFormatter(logging.Formatter):
    COLORS = {logging.INFO: GREEN, logging.WARNING: YELLOW,
              logging.ERROR: RED, logging.CRITICAL: MAGENTA}
    def format(self, record):
        color = self.COLORS.get(record.levelno, "\033[0m")
        record.msg = f"{color}{record.msg}\033[0m"
        return super().format(record)

sh = logging.StreamHandler(sys.stdout)
sh.setFormatter(ColoredFormatter("%(asctime)s [%(name)s] %(levelname)s: %(message)s"))
logging.basicConfig(level=logging.WARNING, handlers=[sh])
logging.getLogger("nexops.dsl_lint").setLevel(logging.INFO)
logging.getLogger("nexops.pipeline_engine").setLevel(logging.INFO)

from src.services.pipeline_engine import get_guarded_pipeline_engine

async def main():
    print(f"\n{MAGENTA}{BOLD}SC-04 Code Dump — show all generated/compiled code{RESET}\n")
    engine = get_guarded_pipeline_engine()
    r = await engine.generate_guarded(
        "2-of-3 multisig escrow with a 30-day timeout reclaim branch for the original sender",
        security_level="high"
    )

    print(f"\n{BOLD}=== INTERCEPTED CODE EVENTS ==={RESET}")
    for i, (stage, code) in enumerate(intercepted_codes):
        lines = code.split("\n")
        # Look for ? in the code
        has_ternary = any("?" in l and "//" not in l.split("?")[0].rstrip() for l in lines)
        flag = f" {RED}⚠ TERNARY DETECTED{RESET}" if has_ternary else f" {GREEN}✓ clean{RESET}"
        print(f"\n{CYAN}[{i+1}] {stage}{flag}{RESET}")
        for ln, line in enumerate(lines, 1):
            marker = f"{RED}>>>{RESET}" if "?" in line else "   "
            print(f"{marker} {ln:3}: {line}")

    if r["type"] == "success":
        print(f"\n{GREEN}{BOLD}✅ PASS{RESET}")
    else:
        err = r.get("error", {})
        print(f"\n{RED}{BOLD}❌ FAIL: {err.get('message', '')}{RESET}")
        print(f"{YELLOW}LAST COMPILE ERR: {err.get('last_compiler_error', '')}{RESET}")

if __name__ == "__main__":
    asyncio.run(main())
