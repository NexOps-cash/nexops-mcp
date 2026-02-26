import asyncio
import logging
from src.services.pipeline import Phase1, Phase2
from src.services.llm.factory import LLMFactory

async def reproduce():
    logging.basicConfig(level=logging.INFO)
    intent = "2-of-2 multisig that splits funds 50/50 to two fixed pubkeys"
    
    print("--- Phase 1 ---")
    ir = await Phase1.run(intent)
    print(f"Contract Type: {ir.metadata.intent_model.contract_type}")
    print(f"Features: {ir.metadata.intent_model.features}")
    
    print("\n--- Phase 2 (Forcing Groq) ---")
    # Patch LLMFactory to only return Groq for Phase 2
    with open("src/services/llm/factory.py", "r") as f:
        content = f.read()
    
    # We can just manually call Phase2.run and specify provider="groq" if get_provider supports it
    # Actually, Phase2.run calls get_provider("phase2", api_key=api_key, provider_type=provider)
    code = await Phase2.run(ir, provider="groq")
    
    print("\n--- Generated Code ---")
    print(code)
    
    print("\n--- Compiling ---")
    from src.services.compiler import get_compiler_service
    compiler = get_compiler_service()
    result = compiler.compile(code)
    print(f"Success: {result['success']}")
    if not result['success']:
        print(f"Error: {result['error']}")

if __name__ == "__main__":
    asyncio.run(reproduce())
