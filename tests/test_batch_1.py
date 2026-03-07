
import asyncio
import logging
import json
import time
import sys
from typing import List, Dict, Any
from src.services.pipeline_engine import get_guarded_pipeline_engine

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
        # Avoid double resetting if message already contains ANSI
        msg = str(record.msg)
        if RESET not in msg:
            record.msg = f"{color}{msg}{RESET}"
        else:
            record.msg = f"{color}{msg}"
        return super().format(record)

# Setup colored logging to see internal pipeline steps
sh = logging.StreamHandler(sys.stdout)
sh.setFormatter(ColoredFormatter("%(asctime)s [%(name)s] %(levelname)s: %(message)s"))
logging.basicConfig(level=logging.INFO, handlers=[sh])
logger = logging.getLogger("nexops.batch_1")

# Test Data
BATCH_NAME = "BATCH 1 (Baseline Core)"
TESTS = [
    {"id": "1", "name": "Simple 2-of-2 Multisig", "intent": "simple 2-of-2 multisig wallet"},
    {"id": "2", "name": "2-of-2 Split 50/50", "intent": "2-of-2 multisig that splits funds 50/50 to two fixed pubkeys"},
    {"id": "3", "name": "Timelock Beneficiary", "intent": "single beneficiary timelock unlockable after timestamp"},
]

def print_table(headers, data):
    col_widths = [len(h) for h in headers]
    for row in data:
        for i, cell in enumerate(row):
            col_widths[i] = max(col_widths[i], len(str(cell)))
    fmt = " | ".join([f"{{:<{w}}}" for w in col_widths])
    print("\n" + "-" * (sum(col_widths) + 3 * (len(headers) - 1)))
    print(fmt.format(*headers))
    print("-" * (sum(col_widths) + 3 * (len(headers) - 1)))
    for row in data:
        print(fmt.format(*[str(c) for c in row]))
    print("-" * (sum(col_widths) + 3 * (len(headers) - 1)) + "\n")

async def run_test(test_case: Dict[str, str], engine) -> Dict[str, Any]:
    print(f"\n{BLUE}🚀 Running: {test_case['name']}{RESET}")
    start_time = time.time()
    
    metrics = {
        "id": test_case["id"],
        "name": test_case["name"],
        "mode": "N/A",
        "dsl_lint": "Unknown",
        "compile": "Fail",
        "tg_viol": "0",
        "score": "0.00",
        "converged": "NO",
        "failure_layer": "Unknown",
        "code": ""
    }

    try:
        result = await engine.generate_guarded(test_case["intent"], security_level="high")
        elapsed = time.time() - start_time
        
        if result["type"] == "success":
            data = result["data"]
            metrics.update({
                "mode": data["intent_model"].get("contract_type", "unknown"),
                "dsl_lint": "PASS",
                "compile": "PASS",
                "tg_viol": str(len(data["toll_gate"]["violations"])),
                "score": f"{data['toll_gate']['structural_score']:.2f}",
                "converged": "YES" if len(data["toll_gate"]["violations"]) == 0 else "PARTIAL",
                "failure_layer": "-",
                "code": data["code"]
            })
            print(f"\n{GREEN}✅ CONVERGED RESULT:{RESET}")
            print(f"{CYAN}{data['code']}{RESET}")
        else:
            error = result.get("error", {})
            msg = error.get("message", "")
            last_err = error.get("last_compiler_error", "")
            metrics["converged"] = "NO"
            if "intent_parse_failed" in str(error.get("code", "")):
                 metrics["failure_layer"] = "Phase1"
            elif "lint loop exhausted" in str(msg).lower():
                 metrics["failure_layer"] = "DSL Lint"
            elif "exhausted" in str(msg).lower():
                 metrics["failure_layer"] = "Compile/Fix"
            else:
                 metrics["failure_layer"] = "Unknown"
            metrics["compile"] = f"ERR: {last_err[:30]}..." if last_err else "Fail"
            print(f"\n{RED}❌ FAILED: {metrics['failure_layer']} - {metrics['compile']}{RESET}")
        
    except Exception as e:
        print(f"\n{RED}💥 CRASH: {str(e)}{RESET}")
        metrics["converged"] = "CRASH"
        metrics["failure_layer"] = f"Exception: {str(e)[:30]}"
    
    return metrics

async def main():
    print(f"{MAGENTA}Initializing Guarded Pipeline Engine...{RESET}")
    engine = get_guarded_pipeline_engine()
    all_results = []
    
    print("\n" + "="*60)
    print(f"{CYAN}{BATCH_NAME} - STRUCTURAL CONVERGENCE{RESET}")
    print("="*60)

    for test in TESTS:
        res = await run_test(test, engine)
        all_results.append(res)
    
    # Batch Summary Table
    headers = ["ID", "Name", "Mode", "Lint", "Comp", "TG Viol", "Score", "Conv", "Fail Layer"]
    table_data = [[
        r["id"], r["name"], r["mode"], r["dsl_lint"], r["compile"], 
        r["tg_viol"], r["score"], r["converged"], r["failure_layer"]
    ] for r in all_results]
    print_table(headers, table_data)

if __name__ == "__main__":
    asyncio.run(main())
