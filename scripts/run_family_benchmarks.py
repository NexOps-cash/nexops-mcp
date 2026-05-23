"""
Run all five CashTokens family benchmark suites (free synthesis) and write a report.

Usage:
  python scripts/run_family_benchmarks.py
"""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from dotenv import load_dotenv

load_dotenv(ROOT / ".env")

FAMILIES = [
    ("token_ft", "benchmark/suites/cashtokens_ft.yaml", "cashtokens_ft_family.json"),
    ("nft_immutable", "benchmark/suites/cashtokens_nft_immutable.yaml", "cashtokens_nft_immutable_family.json"),
    ("nft_mutable", "benchmark/suites/cashtokens_nft_mutable.yaml", "cashtokens_nft_mutable_family.json"),
    ("nft_minting", "benchmark/suites/cashtokens_nft_minting.yaml", "cashtokens_nft_minting_family.json"),
    ("hybrid_token", "benchmark/suites/cashtokens_hybrid.yaml", "cashtokens_hybrid_family.json"),
]


async def run_family(pattern: str, suite_path: str, out_name: str) -> dict:
    from benchmark.runner import BenchmarkRunner

    runner = BenchmarkRunner(str(ROOT / suite_path))
    runner.load_suite()
    report = await runner.run_all(disable_golden=True)
    out = ROOT / "benchmark/results" / out_name
    shutil.copy2(ROOT / "benchmark/results" / f"{report.run_id}.json", out)
    return report.model_dump()


def _md_report(sections: list[dict]) -> str:
    ts = datetime.now(timezone.utc).isoformat()
    lines = [
        "# CashTokens family benchmark report",
        "",
        f"Generated: {ts}",
        "",
        "Configuration: **free synthesis** (`disable_golden=True`), `security_level=high` via benchmark evaluator.",
        "",
        "---",
        "",
    ]
    for sec in sections:
        lines.append(f"## {sec['family']}")
        lines.append("")
        lines.append(f"- Suite: `{sec['suite']}`")
        lines.append(f"- Run ID: `{sec['run_id']}`")
        lines.append(f"- Cases: {sec['total']}")
        lines.append(f"- Compile rate: **{sec['compile_rate']:.0%}**")
        lines.append(f"- Convergence rate: **{sec['convergence_rate']:.0%}**")
        lines.append(f"- Avg final score: **{sec['avg_score']:.3f}**")
        lines.append(f"- Artifact: `benchmark/results/{sec['artifact']}`")
        lines.append("")
        lines.append("| Case | Compile | Converged | Score | Latency (s) | Notes |")
        lines.append("|------|---------|-----------|-------|-------------|-------|")
        for r in sec["results"]:
            notes = ""
            if r.get("failure_layer"):
                notes = r["failure_layer"]
            elif r.get("missing_features"):
                notes = "missing: " + ", ".join(r["missing_features"][:3])
            lines.append(
                f"| {r['id']} | {'Y' if r['compile_pass'] else 'N'} | "
                f"{'Y' if r['converged'] else 'N'} | {r['final_score']:.2f} | "
                f"{r['latency_seconds']:.1f} | {notes} |"
            )
        lines.append("")
    lines.append("## Summary across families")
    lines.append("")
    lines.append("| Family | Compile | Converge | Avg score |")
    lines.append("|--------|---------|----------|-----------|")
    for sec in sections:
        lines.append(
            f"| {sec['family']} | {sec['compile_rate']:.0%} | "
            f"{sec['convergence_rate']:.0%} | {sec['avg_score']:.3f} |"
        )
    lines.append("")
    return "\n".join(lines)


async def main() -> int:
    if not os.getenv("OPENROUTER_API_KEY"):
        print("Error: OPENROUTER_API_KEY required.", file=sys.stderr)
        return 1

    sections = []
    for pattern, suite, artifact in FAMILIES:
        print(f"\n=== Running {pattern} ===", file=sys.stderr)
        data = await run_family(pattern, suite, artifact)
        results = data.get("results", [])
        n = len(results) or 1
        sections.append({
            "family": pattern,
            "suite": suite,
            "run_id": data.get("run_id", "?"),
            "artifact": artifact,
            "total": len(results),
            "compile_rate": sum(1 for r in results if r.get("compile_pass")) / n,
            "convergence_rate": sum(1 for r in results if r.get("converged")) / n,
            "avg_score": sum(r.get("final_score") or 0 for r in results) / n,
            "results": results,
        })

    md = _md_report(sections)
    report_path = ROOT / "docs" / "cashtokens_family_benchmark_report.md"
    report_path.write_text(md, encoding="utf-8")
    print(md)
    print(f"\nWrote {report_path}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
