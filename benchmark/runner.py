import asyncio
import sys
import io
import yaml
import hashlib
import time
import argparse
import uuid
from pathlib import Path
from typing import List, Dict, Any
from datetime import datetime

# Fix Windows encoding issues for console output
if sys.platform == "win32":
    try:
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
        sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')
    except:
        pass

from benchmark.schemas import BenchmarkCase, CaseResult, BenchmarkReport
from src.services.pipeline_engine import get_guarded_pipeline_engine

class BenchmarkRunner:
    def __init__(self, yaml_path: str, tags: List[str] = None, case_ids: List[str] = None):
        self.yaml_path = Path(yaml_path)
        self.tags = tags or []
        self.case_ids = case_ids or []  # if non-empty, only run these case ids
        self.engine = get_guarded_pipeline_engine()
        self.cases: List[BenchmarkCase] = []
        self.dataset_hash = ""
        self.suite_version = "1.0"

    def load_suite(self):
        if not self.yaml_path.exists():
            print(f"Error: Suite file not found at {self.yaml_path}")
            sys.exit(1)

        with open(self.yaml_path, "r", encoding="utf-8") as f:
            content = f.read()
            self.dataset_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()
            data = yaml.safe_load(content)

        if not isinstance(data, list):
            print("Error: YAML suite must be a list of cases.")
            sys.exit(1)

        for case_data in data:
            case = BenchmarkCase(**case_data)
            if self.case_ids and case.id not in self.case_ids:
                continue
            # Filter by tags if provided
            if self.tags:
                if not any(tag in case.tags for tag in self.tags):
                    continue
            self.cases.append(case)
            self.suite_version = case.suite_version or self.suite_version

        print(f"Loaded {len(self.cases)} cases from {self.yaml_path.name}")
        print(f"Dataset Hash: {self.dataset_hash[:12]}...")

    async def run_all(self, model_override: str = None, on_progress: callable = None):
        from benchmark.evaluator import BenchmarkEvaluator
        from benchmark.reporter import BenchmarkReporter
        
        evaluator = BenchmarkEvaluator()
        reporter = BenchmarkReporter()
        
        run_id = f"bench_{datetime.now().strftime('%Y%m%d_%H%M')}_{uuid.uuid4().hex[:4]}"
        start_time = datetime.now()
        
        summary = f"[Runner] Starting benchmark run: {run_id}\n[Runner] Suite: {self.yaml_path.name} | Total Cases: {len(self.cases)}"
        print(f"\n{summary}")
        if on_progress:
            await on_progress({"type": "start", "run_id": run_id, "total": len(self.cases), "summary": summary})
            
        print("="*60)
        
        results = []
        for i, case in enumerate(self.cases):
            res = await evaluator.evaluate(case, model_override=model_override)
            results.append(res)
            
            # Immediate feedback per case (ASCII to avoid Windows console encoding issues)
            status_label = "PASS" if res.final_score > 0.7 else "WARN" if res.final_score > 0 else "FAIL"
            log_line = f"[{status_label}] {res.id:<20} | Score: {res.final_score:>6.3f} | Latency: {res.latency_seconds:>5.1f}s"
            print(log_line)
            
            if on_progress:
                await on_progress({
                    "type": "progress",
                    "current": i + 1,
                    "total": len(self.cases),
                    "case_id": res.id,
                    "result": res.model_dump(),
                    "log": log_line
                })
            
            if res.failure_layer:
                print(f"      Failure at: {res.failure_layer}")
            if res.missing_features:
                print(f"      Missing: {', '.join(res.missing_features)}")

        print("="*60)
        
        report = reporter.generate_report(
            results=results,
            run_id=run_id,
            dataset_hash=self.dataset_hash,
            suite_version=self.suite_version,
            start_time=start_time
        )
        
        reporter.print_summaries(report)
        
        if on_progress:
            await on_progress({"type": "complete", "report": report.model_dump()})
            
        return report

async def main():
    parser = argparse.ArgumentParser(description="NexOps MCP Pattern Benchmark Runner")
    parser.add_argument("suite", help="Path to the YAML suite file")
    parser.add_argument("--tags", help="Comma-separated tags to filter", default="")
    parser.add_argument("--ids", help="Comma-separated case ids to run (subset)", default="")
    parser.add_argument("--model", help="Model override", default=None)
    
    args = parser.parse_args()
    
    tags = [t.strip() for t in args.tags.split(",") if t.strip()]
    case_ids = [t.strip() for t in args.ids.split(",") if t.strip()]
    
    runner = BenchmarkRunner(args.suite, tags=tags, case_ids=case_ids)
    runner.load_suite()
    await runner.run_all(model_override=args.model)

if __name__ == "__main__":
    asyncio.run(main())
