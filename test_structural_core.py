"""
test_structural_core.py — Structural Convergence Test
5 canonical contract patterns with colored logging.
"""

import asyncio
import logging
import time
import sys
from typing import Dict, Any

from src.services.pipeline_engine import get_guarded_pipeline_engine

# ─── ANSI Colors ──────────────────────────────────────────────────────────────
GREEN   = "\033[92m"
RED     = "\033[91m"
YELLOW  = "\033[93m"
BLUE    = "\033[94m"
CYAN    = "\033[96m"
MAGENTA = "\033[95m"
BOLD    = "\033[1m"
RESET   = "\033[0m"

# ─── Colored Logger ───────────────────────────────────────────────────────────
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
logger = logging.getLogger("nexops.structural_core")

# ─── Test Suite ───────────────────────────────────────────────────────────────
TESTS = [
    {
        "id": "SC-01",
        "name": "2-of-2 Simple Multisig",
        "intent": "simple 2-of-2 multisig wallet requiring both parties to sign",
    },
    {
        "id": "SC-02",
        "name": "2-of-2 Split 50/50",
        "intent": "2-of-2 multisig that splits all funds 50/50 equally to two fixed pubkey recipients",
    },
    {
        "id": "SC-03",
        "name": "Single Beneficiary Timelock",
        "intent": "timelock contract unlockable by a single beneficiary after a fixed timestamp",
    },
    {
        "id": "SC-04",
        "name": "2-of-3 Escrow with Timeout",
        "intent": "2-of-3 multisig escrow with a 30-day timeout reclaim branch for the original sender",
    },
    {
        "id": "SC-05",
        "name": "Dual Hashlock + Timelock HTLC",
        "intent": "HTLC contract with dual hashlock preimage and absolute timelock fallback for reclaim",
    },
]

# ─── Table Helper ─────────────────────────────────────────────────────────────
def print_table(headers: list, rows: list):
    col_w = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            col_w[i] = max(col_w[i], len(str(cell)))
    sep = "-+-".join("-" * w for w in col_w)
    fmt = " | ".join(f"{{:<{w}}}" for w in col_w)
    print(f"\n{BOLD}{fmt.format(*headers)}{RESET}")
    print(sep)
    for row in rows:
        cells = [str(c) for c in row]
        # Colorize the Conv column
        conv_idx = headers.index("Conv") if "Conv" in headers else -1
        if conv_idx >= 0:
            conv_val = cells[conv_idx]
            if conv_val == "YES":
                cells[conv_idx] = f"{GREEN}{conv_val}{RESET}"
            elif conv_val == "CRASH":
                cells[conv_idx] = f"{MAGENTA}{conv_val}{RESET}"
            else:
                cells[conv_idx] = f"{RED}{conv_val}{RESET}"
        print(fmt.format(*cells))
    print(sep + "\n")

# ─── Single Test Runner ───────────────────────────────────────────────────────
async def run_test(tc: Dict[str, str], engine) -> Dict[str, Any]:
    print(f"\n{BLUE}{BOLD}▶ [{tc['id']}] {tc['name']}{RESET}")
    start = time.time()

    result = {
        "id":           tc["id"],
        "name":         tc["name"],
        "mode":         "N/A",
        "dsl_lint":     "—",
        "compile_att":  "—",
        "tg_viol":      "—",
        "score":        "—",
        "conv":         "NO",
        "fail_layer":   "Unknown",
    }

    try:
        raw = await engine.generate_guarded(tc["intent"], security_level="high")
        elapsed = time.time() - start

        if raw["type"] == "success":
            data = raw["data"]
            im   = data["intent_model"]
            tg   = data["toll_gate"]
            viol_count = len(tg["violations"])
            score      = tg.get("structural_score", 0.0)
            converged  = "YES" if viol_count == 0 else "PARTIAL"

            result.update({
                "mode":        im.get("contract_type", "unknown"),
                "dsl_lint":    f"{GREEN}PASS{RESET}",
                "compile_att": str(data.get("compile_fix_count", 0) + 1),
                "tg_viol":     str(viol_count),
                "score":       f"{score:.2f}",
                "conv":        converged,
                "fail_layer":  "-",
            })

            print(f"{GREEN}  ✅ CONVERGED  |  score={score:.2f}  viol={viol_count}  mode={im.get('contract_type')}  ({elapsed:.1f}s){RESET}")
            print(f"{CYAN}{data['code']}{RESET}")

        else:
            err = raw.get("error", {})
            msg = err.get("message", "")
            last_err = err.get("last_compiler_error", "")

            if "intent_parse_failed" in str(err.get("code", "")):
                layer = "Phase1"
            elif "lint loop exhausted" in msg.lower():
                layer = "DSL Lint"
            elif "exhausted" in msg.lower():
                layer = "Compile/Fix"
            else:
                layer = "Unknown"

            result.update({
                "dsl_lint":   f"{RED}FAIL{RESET}",
                "fail_layer": layer,
                "conv":       "NO",
            })
            print(f"{RED}  ❌ FAILED  |  layer={layer}  ({elapsed:.1f}s){RESET}")
            if last_err:
                print(f"{YELLOW}     ↳ {last_err[:120]}{RESET}")

    except Exception as e:
        result.update({"conv": "CRASH", "fail_layer": f"Exception: {str(e)[:50]}"})
        print(f"{MAGENTA}  💥 CRASH: {e}{RESET}")

    return result

# ─── Main ─────────────────────────────────────────────────────────────────────
async def main():
    print(f"\n{MAGENTA}{BOLD}{'='*60}{RESET}")
    print(f"{MAGENTA}{BOLD}  NEXOPS STRUCTURAL CONVERGENCE — CORE 5 PATTERNS{RESET}")
    print(f"{MAGENTA}{BOLD}{'='*60}{RESET}\n")

    print(f"{CYAN}Initializing Guarded Pipeline Engine...{RESET}")
    engine = get_guarded_pipeline_engine()

    results = []
    for tc in TESTS:
        results.append(await run_test(tc, engine))

    # ── Summary Table ──────────────────────────────────────────────────────────
    print(f"\n{BOLD}{'='*60}{RESET}")
    print(f"{BOLD}  SUMMARY{RESET}")
    print(f"{BOLD}{'='*60}{RESET}")

    headers = ["ID", "Name", "Mode", "DSL", "Comp#", "TG Viol", "Score", "Conv", "Fail Layer"]
    rows = [[
        r["id"], r["name"], r["mode"],
        r["dsl_lint"], r["compile_att"],
        r["tg_viol"], r["score"],
        r["conv"], r["fail_layer"],
    ] for r in results]
    print_table(headers, rows)

    # ── Pass Rate ──────────────────────────────────────────────────────────────
    passed = sum(1 for r in results if "YES" in r["conv"] or "PARTIAL" in r["conv"])
    total  = len(results)
    color  = GREEN if passed == total else (YELLOW if passed > 0 else RED)
    print(f"{color}{BOLD}  Result: {passed}/{total} converged{RESET}\n")

if __name__ == "__main__":
    asyncio.run(main())
