
import asyncio
from src.services.pipeline import Phase1, Phase2, Phase3
from src.models import ContractIR

async def debug_gen():
    intent = "Create a 2-of-3 multisig escrow contract where funds can be released with any 2 signatures from alice, bob, and carol. After a 30-day timeout, alice can reclaim the funds alone."
    print(f"DEBUG: Generating for intent: {intent}")
    
    # Phase 1
    ir = await Phase1.run(intent)
    print(f"PHASE 1 SKELETON:\n{ir.contract_name}")
    
    # Phase 2
    code = await Phase2.run(ir)
    print("--- GENERATED CODE (Attempt 1) ---")
    print(code)
    print("----------------------------------")
    
    # Phase 3
    result = Phase3.validate(code)
    print(f"PHASE 3 RESULT: passed={result.passed}, score={result.structural_score}")
    for v in result.violations:
        print(f"  - [{v.severity}] {v.rule}: {v.reason}")
        print(f"    HINT: {v.fix_hint}")

if __name__ == "__main__":
    asyncio.run(debug_gen())
