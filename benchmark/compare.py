"""
Compare two benchmark report JSON files (before/after upgrade).

Usage:
    python -m benchmark.compare benchmark/results/cashtokens_baseline.json \\
        benchmark/results/cashtokens_postupgrade.json
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional


def _load_report(path: Path) -> Dict[str, Any]:
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def _by_id(report: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    return {r["id"]: r for r in report.get("results", [])}


def _verdict(b: Dict[str, Any], a: Dict[str, Any]) -> str:
    b_conv = bool(b.get("converged"))
    a_conv = bool(a.get("converged"))
    b_score = float(b.get("final_score") or 0)
    a_score = float(a.get("final_score") or 0)
    if not b_conv and a_conv:
        return "newly-passing"
    if b_conv and not a_conv:
        return "newly-failing"
    if a_score > b_score + 0.05:
        return "improved"
    if a_score < b_score - 0.05:
        return "regressed"
    return "unchanged"


def compare_reports(baseline: Dict[str, Any], post: Dict[str, Any]) -> str:
    if baseline.get("dataset_hash") != post.get("dataset_hash"):
        print(
            "WARNING: dataset_hash mismatch — suites may differ. "
            f"baseline={baseline.get('dataset_hash', '')[:12]} "
            f"post={post.get('dataset_hash', '')[:12]}",
            file=sys.stderr,
        )

    b_map = _by_id(baseline)
    p_map = _by_id(post)
    all_ids = sorted(set(b_map) | set(p_map))

    lines: List[str] = []
    lines.append("# CashTokens benchmark comparison")
    lines.append("")
    lines.append(f"- Baseline run: `{baseline.get('run_id', '?')}`")
    lines.append(f"- Post run: `{post.get('run_id', '?')}`")
    lines.append(f"- Generated: {datetime.utcnow().isoformat()}Z")
    lines.append("")

    improved = newly = regressed = unchanged = 0
    lines.append("| Case | Pattern | Baseline | Post | Delta score | Verdict |")
    lines.append("|------|---------|----------|------|-------------|---------|")

    for cid in all_ids:
        b = b_map.get(cid, {})
        p = p_map.get(cid, {})
        b_conv = "Y" if b.get("converged") else "N"
        p_conv = "Y" if p.get("converged") else "N"
        b_sc = float(b.get("final_score") or 0)
        p_sc = float(p.get("final_score") or 0)
        delta = p_sc - b_sc
        v = _verdict(b, p) if b and p else ("missing" if cid not in b_map else "new")
        if v == "improved":
            improved += 1
        elif v == "newly-passing":
            newly += 1
        elif v == "regressed" or v == "newly-failing":
            regressed += 1
        else:
            unchanged += 1
        lines.append(
            f"| {cid} | {p.get('pattern', b.get('pattern', ''))} | "
            f"conv={b_conv} score={b_sc:.2f} | conv={p_conv} score={p_sc:.2f} | "
            f"{delta:+.2f} | {v} |"
        )

    lines.append("")
    lines.append("## Summary")
    lines.append(f"- Improved: {improved}")
    lines.append(f"- Newly passing (convergence): {newly}")
    lines.append(f"- Regressed / newly failing: {regressed}")
    lines.append(f"- Unchanged: {unchanged}")
    lines.append("")

    b_avg = float(baseline.get("avg_final_score") or 0)
    p_avg = float(post.get("avg_final_score") or 0)
    lines.append(f"- Baseline avg score: {b_avg:.3f}")
    lines.append(f"- Post avg score: {p_avg:.3f}")
    lines.append(f"- Delta avg score: {p_avg - b_avg:+.3f}")

    b_pat = {s["pattern"]: s for s in baseline.get("pattern_summaries", [])}
    p_pat = {s["pattern"]: s for s in post.get("pattern_summaries", [])}
    lines.append("")
    lines.append("## Per-pattern convergence rate")
    lines.append("| Pattern | Baseline conv% | Post conv% | Delta |")
    lines.append("|---------|----------------|------------|-------|")
    for pat in sorted(set(b_pat) | set(p_pat)):
        br = b_pat.get(pat, {})
        pr = p_pat.get(pat, {})
        bc = float(br.get("convergence_rate") or 0) * 100
        pc = float(pr.get("convergence_rate") or 0) * 100
        lines.append(f"| {pat} | {bc:.0f}% | {pc:.0f}% | {pc - bc:+.0f}% |")

    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description="Compare two benchmark JSON reports")
    parser.add_argument("baseline", help="Path to baseline report JSON")
    parser.add_argument("post", help="Path to post-upgrade report JSON")
    parser.add_argument(
        "--out",
        help="Write markdown diff to this path (default: benchmark/results/cashtokens_diff_<ts>.md)",
        default="",
    )
    args = parser.parse_args()

    baseline_path = Path(args.baseline)
    post_path = Path(args.post)
    if not baseline_path.is_file():
        print(f"Error: baseline not found: {baseline_path}", file=sys.stderr)
        sys.exit(1)
    if not post_path.is_file():
        print(f"Error: post report not found: {post_path}", file=sys.stderr)
        sys.exit(1)

    md = compare_reports(_load_report(baseline_path), _load_report(post_path))
    print(md)

    out = args.out
    if not out:
        ts = datetime.now().strftime("%Y%m%d_%H%M")
        out = f"benchmark/results/cashtokens_diff_{ts}.md"
    out_path = Path(out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(md, encoding="utf-8")
    print(f"\nWrote diff report to {out_path}", file=sys.stderr)


if __name__ == "__main__":
    main()
