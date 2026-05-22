"""Print evaluator breakdown for one semantic benchmark case (no checkpoint write)."""

from __future__ import annotations

import argparse
import asyncio
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from dotenv import load_dotenv

load_dotenv(ROOT / ".env")

SUITE = ROOT / "benchmark/suites/cashtokens_semantic.yaml"


async def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("case_id", help="e.g. semantic_005 or semantic_008")
    args = parser.parse_args()

    from benchmark.evaluator import BenchmarkEvaluator, _semantic_alias_pool
    from benchmark.runner import BenchmarkRunner
    from benchmark.schemas import BenchmarkCase
    from benchmark.feature_extractor import FeatureExtractor

    runner = BenchmarkRunner(str(SUITE), case_ids=[args.case_id])
    runner.load_suite()
    case: BenchmarkCase = runner.cases[0]
    evaluator = BenchmarkEvaluator()
    result = await evaluator.evaluate(case, disable_golden=True)

    print(f"case={case.id} pattern={case.pattern}")
    print(f"compile_pass={result.compile_pass} converged={result.converged}")
    print(f"intent_coverage={result.intent_coverage:.0%} failure_layer={result.failure_layer}")
    print(f"required_features={case.required_features}")
    print(f"critical_features={case.critical_features}")
    print(f"missing_required={result.missing_features}")
    print(f"detected_features={sorted(result.detected_features or [])}")

    code = getattr(result, "code", None) or ""
    if not code and not result.compile_pass:
        err = await evaluator.engine.generate_guarded(
            case.intent, security_level="high", disable_golden=True, disable_fallbacks=True
        )
        code = (err.get("error") or {}).get("last_code") or ""
        print("\n(last_code from failed pipeline, truncated)")
    if code:
        print(f"\ncode_lines={len(code.splitlines())}")
        for pat in (
            r"new\s+LockingBytecodeP2PKH",
            r"(?<!\w)LockingBytecodeP2PKH\s*\(",
            r"function\s+\w+",
            r"checkSig",
            r"tokenCategory",
            r"burn|redeem",
        ):
            print(f"  {pat}: {len(re.findall(pat, code, re.I))} hits")

    if code and result.compile_pass:
        extracted = FeatureExtractor().extract(code)
        detected = set(extracted["features"])
        capabilities = {
            "signature_verification": any("_signature" in f or f == "multisig" for f in detected),
            "token_validation": (
                ("token_amount" in detected)
                or ("token_nft" in detected)
                or ("tokenCategory" in code and "tokenAmount" in code)
            ),
            "output_value_validation": ("output_value_validation" in detected) or ("value_check" in detected),
        }
        aliases = _semantic_alias_pool(case.pattern, capabilities, detected, code, extracted["functions"])

        def sat(req: str) -> bool:
            if capabilities.get(req) or req in detected:
                return True
            return bool(aliases.get(req, False))

        print("\n--- required_features satisfaction ---")
        for req in case.required_features or []:
            print(f"  {req}: {sat(req)}")
        print("\n--- critical_features satisfaction ---")
        critical_missing = []
        for req in case.critical_features or []:
            ok = sat(req)
            if not ok:
                critical_missing.append(req)
            print(f"  {req}: {ok}")
        print(f"\ncritical_missing={critical_missing}")
        print(f"converged_blockers: coverage<70%={result.intent_coverage < 0.7}, critical={bool(critical_missing)}")


if __name__ == "__main__":
    asyncio.run(main())
