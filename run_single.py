import asyncio
from benchmark.runner import BenchmarkRunner

async def run_test():
    yaml_path = "benchmark/suites/test_linear.yaml"
    runner = BenchmarkRunner(yaml_path)
    runner.load_suite()
    await runner.run_all()

if __name__ == "__main__":
    asyncio.run(run_test())
