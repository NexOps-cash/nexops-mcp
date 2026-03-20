import asyncio
import logging
import sys
import os

# Set up logging to see Phase 4 logs
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("verify_vesting")

# Fix Windows encoding issues
if sys.platform == 'win32':
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

# Add project root to path
sys.path.append(os.getcwd())

from src.services.pipeline_engine import get_guarded_pipeline_engine

async def main():
    engine = get_guarded_pipeline_engine()
    
    # Intent that was failing due to SanityChecker bug and lack of relaxation
    intent = "linear token vesting releasing proportionally over time"
    
    print("\n" + "="*60)
    print(f"VERIFYING RELAXED PIPELINE FOR INTENT:")
    print(f"   \"{intent}\"")
    print("="*60)
    
    # Run with security_level="standard" to use Phase 4 relaxation
    result = await engine.generate_guarded(
        intent, 
        security_level="standard",
        provider="openrouter" # Assuming openrouter is available since benchmarks use it
    )
    
    if result["type"] == "success":
        data = result["data"]
        print("\nCONVERGENCE SUCCESSFUL")
        print(f"Attempt: {data.get('attempt_number', 1)}")
        print(f"Perfect Match (Phase 4 Passed): {data.get('is_perfect_match', 'N/A')}")
        print(f"Fallback Used: {data.get('fallback_used', False)}")
        
        print("\n--- GENERATED CODE START ---")
        print(data["code"])
        print("--- GENERATED CODE END ---\n")
        
        sanity = data.get("sanity_check", {})
        if not sanity.get("success"):
            print("INTENT WARNINGS (Tolerated in Relaxed Mode):")
            for v in sanity.get("violations", []):
                print(f"  - {v}")
    else:
        print("\n❌ FAILED TO CONVERGE")
        print(result.get("error"))

if __name__ == "__main__":
    asyncio.run(main())
