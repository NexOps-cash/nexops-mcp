import asyncio
import sys
import os

# Add src to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.services.pipeline_engine import get_guarded_pipeline_engine

async def main():
    engine = get_guarded_pipeline_engine()
    
    intent_str = "Create a vault with 2-step withdrawal: announce withdrawal to staging, then claim after 24 hour delay."
    
    print(f"Running synthesis for intent: {intent_str}")
    # We pass the intent string directly to generate_guarded
    result = await engine.generate_guarded(intent_str)
    
    if result["type"] == "success":
        print("\n=== SUCCESS ===")
        print(result["data"]["code"])
    else:
        print("\n=== FAILURE ===")
        print(f"Error: {result.get('error', 'Unknown')}")
        if "data" in result:
             print(f"Stage: {result['data'].get('stage')}")
             print(f"Code: {result['data'].get('code')}")

if __name__ == "__main__":
    asyncio.run(main())
