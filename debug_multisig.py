import asyncio
import logging
import json
from src.services.pipeline import Phase1, Phase2, Phase3
from src.services.pipeline_engine import GuardedPipelineEngine

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("debug_multisig")

async def reproduce():
    intent = "create a simple multisig"
    security_level = "high"
    
    print(f"\n--- REPRODUCING INTENT: {intent} ---")
    
    # 1. Phase 1
    ir = await Phase1.run(intent, security_level)
    intent_model = ir.metadata.intent_model
    print(f"Intent Model: {intent_model.dict()}")
    
    # 2. Phase 2 (Attempt 1)
    code = await Phase2.run(ir, retry_count=0)
    print("\n--- GENERATED CODE (Attempt 1) ---")
    print(code)
    
    # 3. Phase 3 (Toll Gate)
    toll_gate = Phase3.validate(code)
    print(f"\n--- TOLL GATE RESULT (Attempt 1) ---")
    print(f"Passed: {toll_gate.passed}")
    for v in toll_gate.violations:
        print(f"Violation: {v.rule} | Reason: {v.reason}")
        if v.location:
             print(f"Location: {v.location}")

if __name__ == "__main__":
    asyncio.run(reproduce())
