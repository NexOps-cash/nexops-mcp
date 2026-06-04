"""
Compute precision/recall for CashTokens invalid-logic detector corpus.

Usage:
  python scripts/cashtokens_detector_metrics.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.services.cashtokens_token_detectors import CASHTOKENS_INVALID_DETECTOR_REGISTRY
from src.utils.cashscript_ast import CashScriptAST

FIXTURES = ROOT / "tests" / "fixtures" / "cashtokens_invalid"
OUT = ROOT / "benchmark" / "results" / "cashtokens_detector_metrics.json"


def main() -> int:
    tp = fp = tn = fn = 0
    rows = []
    by_id = {d.id: d for d in CASHTOKENS_INVALID_DETECTOR_REGISTRY}

    for detector_id, detector in sorted(by_id.items()):
        for label, expect_hit in (("vulnerable", True), ("secure", False)):
            code = (FIXTURES / detector_id / f"{label}.cash").read_text(encoding="utf-8")
            hit = detector.detect(CashScriptAST(code, contract_mode=detector_id)) is not None
            if expect_hit and hit:
                tp += 1
            elif expect_hit and not hit:
                fn += 1
            elif not expect_hit and hit:
                fp += 1
            else:
                tn += 1
            rows.append(
                {"detector": detector_id, "fixture": label, "expected": expect_hit, "actual": hit}
            )

    precision = tp / (tp + fp) if (tp + fp) else 1.0
    recall = tp / (tp + fn) if (tp + fn) else 1.0
    payload = {
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "precision": precision,
        "recall": recall,
        "rows": rows,
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print(json.dumps({"precision": precision, "recall": recall, "out": str(OUT)}, indent=2))
    return 0 if fn == 0 and fp == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
