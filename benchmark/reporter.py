import json
import yaml
from pathlib import Path
from typing import List, Dict, Any
from datetime import datetime
from collections import defaultdict

from benchmark.schemas import CaseResult, BenchmarkReport, PatternSummary, DifficultySummary

class BenchmarkReporter:
    def __init__(self, results_dir: str = "benchmark/results"):
        self.results_dir = Path(results_dir)
        self.results_dir.mkdir(parents=True, exist_ok=True)
        
        # Load cost config
        self.costs = {}
        with open("benchmark/config/scoring_weights.yaml", "r", encoding="utf-8") as f:
            weights = yaml.safe_load(f)
            self.costs = weights.get("costs", {})

    def generate_report(self, 
                        results: List[CaseResult], 
                        run_id: str, 
                        dataset_hash: str, 
                        suite_version: str,
                        start_time: datetime) -> BenchmarkReport:
        end_time = datetime.now()
        elapsed = (end_time - start_time).total_seconds()
        
        # Aggregates
        patterns = defaultdict(lambda: {"total": 0, "compile": 0, "conv": 0, "fallback": 0, "intent": 0.0, "score": 0.0, "retries": 0})
        difficulties = defaultdict(lambda: {"total": 0, "compile": 0, "intent": 0.0, "score": 0.0})
        
        total_latency = 0.0
        total_tokens_p = 0
        total_tokens_c = 0
        total_cost = 0.0
        total_score = 0.0
        
        for r in results:
            # Pattern aggregation
            p = patterns[r.pattern]
            p["total"] += 1
            if r.compile_pass: p["compile"] += 1
            if r.converged: p["conv"] += 1
            if getattr(r, "fallback_used", False): p["fallback"] += 1
            p["intent"] += r.intent_coverage
            p["score"] += r.final_score
            p["retries"] += r.retries_used
            
            # Difficulty aggregation
            d = difficulties[r.difficulty]
            d["total"] += 1
            if r.compile_pass: d["compile"] += 1
            d["intent"] += r.intent_coverage
            d["score"] += r.final_score
            
            total_latency += r.latency_seconds
            # Heuristic token estimation (4 chars ~ 1 token)
            t_p = int(len(r.id) * 20) # Rough estimate for prompt + context
            t_c = int(len(r.code or "") / 4)
            total_tokens_p += t_p
            total_tokens_c += t_c
            
            # Cost calc
            case_cost = (t_p / 1000 * self.costs.get("prompt_1k", 0)) + \
                        (t_c / 1000 * self.costs.get("completion_1k", 0))
            total_cost += case_cost
            total_score += r.final_score
            r.tokens_prompt = t_p
            r.tokens_completion = t_c
            r.cost_usd = case_cost

        pattern_summaries = []
        for name, stats in patterns.items():
            pattern_summaries.append(PatternSummary(
                pattern=name,
                count=stats["total"],
                compile_rate=stats["compile"] / stats["total"],
                convergence_rate=stats["conv"] / stats["total"],
                avg_intent_coverage=stats["intent"] / stats["total"],
                avg_final_score=stats["score"] / stats["total"],
                avg_retries=stats["retries"] / stats["total"]
            ))

        diff_summaries = []
        for name, stats in difficulties.items():
            diff_summaries.append(DifficultySummary(
                difficulty=name,
                count=stats["total"],
                compile_rate=stats["compile"] / stats["total"],
                avg_intent_coverage=stats["intent"] / stats["total"],
                avg_final_score=stats["score"] / stats["total"]
            ))

        report = BenchmarkReport(
            run_id=run_id,
            dataset_hash=dataset_hash,
            suite_version=suite_version,
            total_cases=len(results),
            start_time=start_time.isoformat(),
            end_time=end_time.isoformat(),
            elapsed_total_seconds=elapsed,
            results=results,
            pattern_summaries=pattern_summaries,
            difficulty_summaries=diff_summaries,
            avg_latency=total_latency / len(results) if results else 0,
            total_tokens_prompt=total_tokens_p,
            total_tokens_completion=total_tokens_c,
            total_cost_usd=total_cost,
            avg_final_score=total_score / len(results) if results else 0.0
        )
        
        self.save_report(report)
        return report

    def save_report(self, report: BenchmarkReport):
        path = self.results_dir / f"{report.run_id}.json"
        with open(path, "w", encoding="utf-8") as f:
            f.write(report.model_dump_json(indent=2))
        print(f"\n[Reporter] Result saved to {path}")

    def print_summaries(self, report: BenchmarkReport):
        print("\n" + "="*60)
        print(f"BCH PATTERN BENCHMARK - {report.run_id}")
        print("="*60)
        
        print("\nPATTERN QUALITY MATRIX")
        print(f"{'Pattern':<15} | {'Comp':<6} | {'Conv':<6} | {'Intent':<6} | {'Score':<6}")
        print("-" * 55)
        for p in report.pattern_summaries:
            print(f"{p.pattern:<15} | {p.compile_rate:>5.0%} | {p.convergence_rate:>5.0%} | {p.avg_intent_coverage:>5.0%} | {p.avg_final_score:>6.3f}")

        print("\nDIFFICULTY DISTRIBUTION")
        print(f"{'Difficulty':<15} | {'Comp':<6} | {'Intent':<6} | {'Score':<6}")
        print("-" * 45)
        for d in report.difficulty_summaries:
            print(f"{d.difficulty:<15} | {d.compile_rate:>5.0%} | {d.avg_intent_coverage:>5.0%} | {d.avg_final_score:>6.3f}")

        print("\nRESOURCE TRACKING")
        print(f"Avg Latency: {report.avg_latency:.1f}s")
        print(f"Total Tokens: {report.total_tokens_prompt + report.total_tokens_completion:,} ({report.total_tokens_prompt}p / {report.total_tokens_completion}c)")
        print(f"Est. Total Cost: ${report.total_cost_usd:.2f} USD")
        print("="*60 + "\n")
