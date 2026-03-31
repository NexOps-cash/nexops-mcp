import asyncio
from src.services.llm.factory import LLMFactory
import time

async def test_endpoint(task_type: str, prompt: str = "Say exactly 'ping'"):
    try:
        print(f"\n[+] Testing endpoint for task: {task_type}")
        start = time.time()
        provider = LLMFactory.get_provider(task_type=task_type)
        response = await provider.complete(prompt)
        elapsed = time.time() - start
        print(f"    SUCCESS: {response.strip()}")
        print(f"    Latency: {elapsed:.2f}s")
    except Exception as e:
        print(f"    FAILED: {str(e)}")

async def run_tests():
    print("==================================================")
    print(" NexOps LLM Endpoint Connectivity Test")
    print("==================================================")
    
    # Simple prompt for standard generation
    tasks_to_test = [
        "phase1",
        "phase2",
        "golden",
        "fix",
        "repair",
        "edit",
        "audit",
        "general"
    ]
    
    for task in tasks_to_test:
        await test_endpoint(task)

if __name__ == "__main__":
    asyncio.run(run_tests())
