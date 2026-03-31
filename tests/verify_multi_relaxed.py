import asyncio
import logging
import sys
import os
import json

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(levelname)s:%(name)s:%(message)s')

# Add project root to path
sys.path.append(os.getcwd())

# Fix Windows encoding issues for output
if sys.platform == 'win32':
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

from src.services.pipeline_engine import get_guarded_pipeline_engine

async def run_verification(engine, intent, name):
    print("\n" + "="*80)
    print(f"🔥 TESTING CONTRACT PATTERN: {name.upper()}")
    print(f"INTENT: \"{intent}\"")
    print("="*80)
    
    # Run with security_level="standard" to use Phase 4 relaxation
    result = await engine.generate_guarded(
        intent, 
        security_level="standard",
        provider="openrouter"
    )
    
    if result["type"] == "success":
        data = result["data"]
        
        # Phase 1 Output
        print("\n[PHASE 1] Intent Parsing (IR):")
        print(json.dumps(data.get("intent_model", {}), indent=2))
        
        # Phase 4 Result
        print(f"\n[PHASE 4] Sanity Check result: {'SUCCESS' if data.get('is_perfect_match') else 'RELAXED MATCH'}")
        sanity = data.get("sanity_check", {})
        if not sanity.get("success"):
            print("⚠️ Warnings (Tolerated):")
            for v in sanity.get("violations", []):
                print(f"  - {v}")
        
        # Final Code
        print("\n[FINAL CODE] Output Code:")
        print("-" * 40)
        print(data["code"])
        print("-" * 40)
        
        return True
    else:
        print(f"\n❌ FAILED TO CONVERGE: {name}")
        print(result.get("error"))
        return False

async def main():
    engine = get_guarded_pipeline_engine()
    
    intents = [
        {
            "name": "Vault",
            "intent": "Security vault with 24 hour withdrawal delay for owner and immediate rescue for backup key"
        },
        {
            "name": "Escrow",
            "intent": "2-of-3 escrow with buyer, seller, and arbitrator plus 30 day refund for buyer"
        }
    ]
    
    for item in intents:
        await run_verification(engine, item["intent"], item["name"])

if __name__ == "__main__":
    asyncio.run(main())
