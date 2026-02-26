import asyncio
import logging
import sys
import os

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("reproduce_convergence")

# Add project root to path
sys.path.append(os.getcwd())

from src.services.pipeline_engine import get_guarded_pipeline_engine

async def main():
    engine = get_guarded_pipeline_engine()
    
    intent = "Timelock Beneficiary"
    logger.info(f"Running convergence test for: {intent}")
    
    result = await engine.generate_guarded(intent, security_level="high")
    
    if result["type"] == "success":
        data = result["data"]
        print("\n[SUCCESS] CONVERGED RESULT:")
        print(data["code"])
        print("\nFallback used:", data.get("fallback_used", False))
        print("Toll Gate Passed:", data["toll_gate"]["passed"])
        if data["toll_gate"]["violations"]:
            print("Violations found (but tolerated):")
            for v in data["toll_gate"]["violations"]:
                print(f"  - {v['rule']}: {v['reason']} (Severity: {v.get('severity', 'unknown')})")
    else:
        print("\n❌ FAILED TO CONVERGE")
        print(result.get("error"))

if __name__ == "__main__":
    asyncio.run(main())
