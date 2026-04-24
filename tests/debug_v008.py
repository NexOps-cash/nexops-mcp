import asyncio
import json
import os
import sys

# Ensure project root is in path
sys.path.append(os.getcwd())

from src.services.pipeline_engine import get_guarded_pipeline_engine
from benchmark.schemas import BenchmarkCase

async def main():
    # v_008 intent: Vault with emergency recovery path and multi-sig distinctness
    intent = """
    Create a vault where funds can be withdrawn by owner after 24 hours, 
    OR by owner + backup with 2-of-2 multisig immediately.
    Ensure 'cancel' function exists to stop a pending withdrawal.
    """
    
    engine = get_guarded_pipeline_engine()
    
    print("\n--- Running v_008 individual test ---")
    result = await engine.generate_guarded(
        intent,
        security_level="high",
        disable_golden=True,
        disable_fallbacks=True
    )
    
    if result["type"] == "success":
        print("\n=== SUCCESS ===")
        print(result["data"]["code"])
    else:
        print("\n--- FAILURE ---")
        print(json.dumps(result["error"], indent=2))

if __name__ == "__main__":
    asyncio.run(main())
