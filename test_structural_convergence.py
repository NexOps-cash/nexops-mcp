
import asyncio
import logging
import json
import time
from typing import List, Dict, Any
from src.services.pipeline_engine import get_guarded_pipeline_engine

# Configure logging
logging.basicConfig(level=logging.ERROR)  # Suppress internal logs for clean output
logger = logging.getLogger("nexops.test_structural_convergence")
logger.setLevel(logging.INFO)

# ANSI Colors
GREEN = "\033[92m"
RED = "\033[91m"
RESET = "\033[0m"
CYAN = "\033[96m"

# Test Batches
BATCHES = [
    {
        "name": "BATCH 1 (Baseline Core)",
        "tests": [
            {"id": "1", "name": "Simple 2-of-2 Multisig", "intent": "simple 2-of-2 multisig wallet"},
            {"id": "2", "name": "2-of-2 Split 50/50", "intent": "2-of-2 multisig that splits funds 50/50 to two fixed pubkeys"},
            {"id": "3", "name": "Timelock Beneficiary", "intent": "single beneficiary timelock unlockable after timestamp"},
        ]
    },
    {
        "name": "BATCH 2 (Covenant + Timeout)",
        "tests": [
            {"id": "4", "name": "Escrow Timeout Reclaim", "intent": "2-of-3 multisig escrow with 30 day timeout reclaim"},
            {"id": "5", "name": "Hashlock Preimage", "intent": "hashlock contract requiring secret preimage to spend"},
            {"id": "6", "name": "Multisig with Fallback", "intent": "multisig with fallback to single signer after timeout"},
        ]
    },
    {
        "name": "BATCH 3 (Token Stateful)",
        "tests": [
            {"id": "7", "name": "Token Burn", "intent": "token contract that allows only owner to burn tokens"},
            {"id": "8", "name": "Token Mint Fixed", "intent": "token minting contract with fixed max supply"},
            {"id": "9", "name": "Token Vault", "intent": "token vault that locks tokens until timestamp"},
        ]
    },
    {
        "name": "BATCH 4 (Advanced Stateful)",
        "tests": [
            {"id": "10", "name": "Vesting Cliff", "intent": "token vesting contract with 90 day cliff"},
            {"id": "11", "name": "Linear Vesting", "intent": "linear token vesting releasing proportionally over time"},
            {"id": "12", "name": "Stateful Counter", "intent": "stateful contract tracking internal counter and updating state each spend"},
        ]
    },
    {
        "name": "BATCH 5 (Edge & Composition)",
        "tests": [
            {"id": "13", "name": "Multi-Output Ratio", "intent": "multi-output covenant requiring exact 3 outputs with fixed ratios"},
            {"id": "14", "name": "Dual Hashlock+Timelock", "intent": "dual hashlock + timelock HTLC style contract"},
            {"id": "15", "name": "Escrow Dispute Mediator", "intent": "multisig escrow with dispute branch and mediator resolution"},
        ]
    }
]

def print_table(headers, data):
    # Calculate column widths
    col_widths = [len(h) for h in headers]
    for row in data:
        for i, cell in enumerate(row):
            col_widths[i] = max(col_widths[i], len(str(cell)))
    
    # Create format string
    fmt = " | ".join([f"{{:<{w}}}" for w in col_widths])
    
    # Print header
    print("-" * (sum(col_widths) + 3 * (len(headers) - 1)))
    print(fmt.format(*headers))
    print("-" * (sum(col_widths) + 3 * (len(headers) - 1)))
    
    # Print rows
    for row in data:
        print(fmt.format(*[str(c) for c in row]))
    print("-" * (sum(col_widths) + 3 * (len(headers) - 1)))

async def run_test(test_case: Dict[str, str], engine) -> Dict[str, Any]:
    print(f"  {CYAN}Running: {test_case['name']}...{RESET}")
    start_time = time.time()
    
    metrics = {
        "id": test_case["id"],
        "name": test_case["name"],
        "mode": "N/A",
        "dsl_lint": "Unknown",
        "compile": "Fail",
        "tg_viol": "N/A",
        "score": 0.0,
        "converged": "NO",
        "failure_layer": "Unknown",
        "elapsed": "0.0s",
        "code": "N/A"
    }

    try:
        result = await engine.generate_guarded(test_case["intent"], security_level="high")
        elapsed = time.time() - start_time
        metrics["elapsed"] = f"{elapsed:.1f}s"
        
        if result["type"] == "success":
            data = result["data"]
            metrics["mode"] = data["intent_model"].get("contract_type", "unknown")
            metrics["dsl_lint"] = "PASS" # If success, lint must have passed or been warnings
            metrics["compile"] = "PASS"
            metrics["tg_viol"] = len(data["toll_gate"]["violations"])
            metrics["score"] = data["toll_gate"]["structural_score"]
            metrics["converged"] = "YES" if metrics["tg_viol"] == 0 else "PARTIAL"
            metrics["failure_layer"] = "-"
            metrics["code"] = data["code"]
            print(f"{GREEN}{data['code']}{RESET}")
        else:
            # Analyze failure
            error = result.get("error", {})
            msg = error.get("message", "")
            last_err = error.get("last_compiler_error", "")
            
            metrics["converged"] = "NO"
            
            if "intent_parse_failed" in error.get("code", ""):
                 metrics["failure_layer"] = "Phase1"
            elif "lint loop exhausted" in str(msg).lower():
                 metrics["failure_layer"] = "DSL Lint"
                 metrics["dsl_lint"] = "FAIL"
            elif "exhausted" in str(msg).lower():
                 metrics["failure_layer"] = "Compile/Fix"
                 metrics["dsl_lint"] = "PASS" # Likely passed lint to get to compile exhaustion
            else:
                 metrics["failure_layer"] = "Unknown"

            if last_err:
                metrics["compile"] = f"ERR: {last_err[:20]}..."
            
            print(f"{RED}FAILED: {metrics['failure_layer']} - {metrics['compile']}{RESET}")
        
    except Exception as e:
        print(f"{RED}CRASH: {str(e)}{RESET}")
        metrics["converged"] = "CRASH"
        metrics["failure_layer"] = f"Exception: {str(e)[:30]}"
    
    return metrics

async def main():
    print(f"{CYAN}Initializing Guarded Pipeline Engine...{RESET}")
    engine = get_guarded_pipeline_engine()
    
    all_results = []
    
    print("\n" + "="*60)
    print(f"{CYAN}NEXOPS STRUCTURAL CONVERGENCE TEST SUITE - 15 PATTERNS{RESET}")
    print("="*60 + "\n")

    for batch in BATCHES:
        print(f"--- {batch['name']} ---")
        batch_results = []
        for test in batch["tests"]:
            res = await run_test(test, engine)
            batch_results.append(res)
            all_results.append(res)
        
        # Print Batch Summary
        headers = ["ID", "Name", "Mode", "Lint", "Comp", "TG Viol", "Score", "Conv", "Fail Layer"]
        table_data = [[
            r.get("id", ""), 
            r.get("name", ""), 
            r.get("mode", "-"), 
            r.get("dsl_lint", "-"), 
            r.get("compile", "-"), 
            r.get("tg_viol", "-"), 
            f"{r.get('score', 0):.2f}", 
            r.get("converged", ""), 
            r.get("failure_layer", "")
        ] for r in batch_results]
        
        print("\n")
        print_table(headers, table_data)
        print("\n")

    # Final Report
    print("\n" + "="*60)
    print("FINAL STRUCTURAL STABILITY REPORT")
    print("="*60)
    
    passed = len([r for r in all_results if r.get("converged") == "YES"])
    partial = len([r for r in all_results if r.get("converged") == "PARTIAL"])
    failed = len(all_results) - passed - partial
    
    print(f"\nConvergence Rate: {passed/len(all_results)*100:.1f}% ({passed}/{len(all_results)})")
    if partial > 0:
        print(f"Partial Convergence (TG Violations): {partial}")
    print(f"Failed: {failed}")
    
    # Identify failure clusters
    fail_layers = [r.get("failure_layer") for r in all_results if r.get("converged") == "NO"]
    if fail_layers:
        print("\nFailure Clusters:")
        from collections import Counter
        for layer, count in Counter(fail_layers).items():
            print(f"  - {layer}: {count}")
            
    # Recommendations
    print("\nRecommendation:")
    if passed >= 12:
         print(f"  -> {GREEN}READY for BCH Demo (High Stability){RESET}")
    elif passed >= 8:
         print(f"  -> {CYAN}USABLE but needs hand-holding (Medium Stability){RESET}")
    else:
         print(f"  -> {RED}NOT READY (Core instability detected){RESET}")

    # Detailed Code Report
    print("\n" + "="*60)
    print("DETAILED CONVERGENCE REPORT (CODE)")
    print("="*60)

    for res in all_results:
        print(f"\n{CYAN}Pattern {res['id']}: {res['name']}{RESET}")
        if res.get("converged") == "YES":
             print(f"{GREEN}")
             print(res.get("code", "Code missing"))
             print(f"{RESET}")
        else:
             print(f"{RED}NO - Failed at {res.get('failure_layer', 'Unknown')}{RESET}")
             if res.get("compile", "PASS") != "PASS":
                 print(f"Error: {res.get('compile')}")

if __name__ == "__main__":
    asyncio.run(main())
