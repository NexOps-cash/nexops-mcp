"""Offline generation RCA for vault hard cases (no LLM).

Mines historical benchmark JSON, replays lint/compile/toll/sanity gates on saved
code and representative synthesis drafts for v_005, v_008, vr_010, vr_020, vr_023, vr_024.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import yaml
from benchmark.evaluator import _cashtoken_alias_pool, _vault_covenant_continuation, _multisig_detected
from benchmark.feature_extractor import FeatureExtractor
from benchmark.semantic_requirements import satisfies_requirement
from src.models import IntentModel
from src.services.compiler import CompilerService
from src.services.dsl_lint import get_dsl_linter
from src.services.pattern_profiles import canonical_pattern
from src.services.pipeline import Phase3, resolve_effective_mode
from src.services.sanity_checker import get_sanity_checker
from src.services.semantic_capabilities import extract_semantic_capabilities
from src.services.structural_integrity import is_structurally_valid

TARGET_CASES = ("v_005", "v_008", "vr_010", "vr_020", "vr_023", "vr_024")

DRAFTS = {
    "v_005_tiered_historical": None,  # filled from benchmark JSON
    "v_005_tiered_broken_instant": """
pragma cashscript ^0.13.0;
contract MultiTierVault(pubkey owner, int smallDelay, int largeDelay, int smallLimit) {
    function instantWithdraw(sig ownerSig, int amount) {
        require(amount <= smallLimit);
        require(checkSig(ownerSig, owner));
        require(tx.outputs.length == 1);
        require(tx.outputs[0].value == amount);
    }
    function announceLarge(sig ownerSig, int withdrawAmount) {
        require(withdrawAmount > smallLimit);
        require(tx.outputs.length == 2);
        require(tx.outputs[0].lockingBytecode == this.activeBytecode);
        require(tx.outputs[0].value == tx.inputs[this.activeInputIndex].value - withdrawAmount);
        require(checkSig(ownerSig, owner));
    }
    function claimLarge(sig ownerSig) {
        require(this.age >= largeDelay);
        require(tx.outputs.length == 1);
        require(checkSig(ownerSig, owner));
    }
}
""",
    "v_008_vulnerable_announce": """
pragma cashscript ^0.13.0;
contract BadVault(pubkey owner) {
    function announce(sig ownerSig, int withdrawAmount) {
        require(checkSig(ownerSig, owner));
        require(tx.outputs.length == 2);
        require(tx.outputs[0].lockingBytecode == this.activeBytecode);
        require(tx.outputs[1].value == withdrawAmount);
    }
}
""",
    "v_008_safe_typical": """
pragma cashscript ^0.13.0;
contract SecureVault(pubkey owner, pubkey backupOwner, int delaySeconds) {
    function announce(sig ownerSig, int withdrawAmount) {
        require(tx.outputs.length == 2);
        require(tx.outputs[0].lockingBytecode == this.activeBytecode);
        require(tx.outputs[0].value == tx.inputs[this.activeInputIndex].value - withdrawAmount);
        require(tx.outputs[1].value == withdrawAmount);
        require(checkSig(ownerSig, owner));
    }
    function claim(sig ownerSig) {
        require(this.age >= delaySeconds);
        require(tx.outputs.length == 1);
        require(tx.outputs[0].value == tx.inputs[this.activeInputIndex].value);
        require(checkSig(ownerSig, owner));
    }
}
""",
    "vr_010_backup_cancel_success": """
pragma cashscript ^0.13.0;
contract TimeLockVault(pubkey owner, pubkey backupKey, int delaySeconds) {
    function announce(sig ownerSig) {
        require(owner != backupKey);
        require(checkSig(ownerSig, owner));
        require(tx.outputs.length == 1);
        require(tx.outputs[0].lockingBytecode == this.activeBytecode);
        require(tx.outputs[0].value == tx.inputs[this.activeInputIndex].value);
    }
    function claim(sig ownerSig) {
        require(this.age >= delaySeconds);
        require(checkSig(ownerSig, owner));
        require(tx.outputs.length == 1);
        require(tx.outputs[0].value == tx.inputs[this.activeInputIndex].value);
    }
    function cancel(sig backupSig) {
        require(checkSig(backupSig, backupKey));
        require(tx.outputs.length == 1);
        require(tx.outputs[0].lockingBytecode == this.activeBytecode);
        require(tx.outputs[0].value == tx.inputs[this.activeInputIndex].value);
    }
}
""",
    "vr_010_overcomplex_attempt": """
pragma cashscript ^0.13.0;
contract SafetyWallet(pubkey owner, pubkey backup, int delay) {
    function announceWithdrawal(sig ownerSig, bytes dest, int amount) {
        require(checkSig(ownerSig, owner));
        require(tx.outputs.length == 3);
        require(tx.outputs[0].lockingBytecode == this.activeBytecode);
        require(tx.outputs[0].value == tx.inputs[this.activeInputIndex].value - amount);
        require(tx.outputs[1].lockingBytecode == dest);
        require(tx.outputs[1].value == amount);
        require(tx.outputs[2].lockingBytecode == this.activeBytecode);
    }
    function claimAfterDelay(sig ownerSig) {
        require(this.age >= delay);
        require(checkSig(ownerSig, owner));
    }
    function backupCancel(sig backupSig) {
        require(checkSig(backupSig, backup));
    }
}
""",
    "vr_020_vulnerable": """
pragma cashscript ^0.13.0;
contract BadStagedVault(pubkey owner, int delaySeconds) {
    function announce(sig ownerSig, int withdrawAmount) {
        require(checkSig(ownerSig, owner));
        require(tx.outputs.length == 2);
        require(tx.outputs[0].lockingBytecode == this.activeBytecode);
        require(tx.outputs[1].value == withdrawAmount);
    }
    function finalize(sig ownerSig) {
        require(this.age >= delaySeconds);
        require(checkSig(ownerSig, owner));
        require(tx.outputs.length == 1);
    }
}
""",
    "vr_023_founder_success": None,
    "vr_024_comprehensive": None,
}


def load_suites() -> dict[str, dict]:
    out: dict[str, dict] = {}
    for path in (ROOT / "benchmark/suites/vaults.yaml", ROOT / "benchmark/suites/vaults_real"):
        for case in yaml.safe_load(path.read_text(encoding="utf-8")):
            out[case["id"]] = case
    return out


def mine_benchmark_history(case_id: str) -> list[dict]:
    rows = []
    for p in sorted((ROOT / "benchmark/results").glob("bench_*.json")):
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue
        for r in data.get("results", []):
            if r.get("id") == case_id:
                rows.append(
                    {
                        "run_id": p.stem,
                        "compile_pass": r.get("compile_pass"),
                        "intent_coverage": r.get("intent_coverage"),
                        "final_score": r.get("final_score"),
                        "converged": r.get("converged"),
                        "failure_layer": r.get("failure_layer"),
                        "latency_seconds": r.get("latency_seconds"),
                        "retries_used": r.get("retries_used"),
                        "code_saved": bool(r.get("code")),
                        "code_len": len(r.get("code") or ""),
                    }
                )
                break
    return rows


def best_code_for_case(case_id: str) -> tuple[str | None, str | None]:
    """Return (code, run_id) from newest successful compile with code."""
    for p in sorted((ROOT / "benchmark/results").glob("bench_*.json"), reverse=True):
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue
        for r in data.get("results", []):
            if r.get("id") == case_id and r.get("code"):
                return r["code"], p.stem
    return None, None


def trace_gates(code: str, case: dict) -> dict:
    im = IntentModel(contract_type="vault", features=["timelock", "spending"])
    contract_mode = (resolve_effective_mode(im) or "vault").lower()
    linter = get_dsl_linter()
    compiler = CompilerService()
    sanity = get_sanity_checker()
    ext = FeatureExtractor()

    out: dict = {
        "draft_exists": bool(code and code.strip()),
        "structurally_valid": is_structurally_valid(code) if code else False,
    }
    if not out["draft_exists"]:
        out["first_failure"] = "Phase2_empty_draft"
        return out

    lint = linter.lint(code, contract_mode=contract_mode)
    out["lint_passed"] = lint.get("passed")
    out["lint_violations"] = [
        {"rule_id": v.get("rule_id"), "message": (v.get("message") or "")[:120]}
        for v in lint.get("violations", [])
    ][:8]
    if not lint.get("passed"):
        out["first_failure"] = "DSLLint"
        out["first_failure_detail"] = out["lint_violations"][0] if out["lint_violations"] else None
        return out

    comp = compiler.compile(code)
    out["compile_passed"] = comp.get("success")
    if not comp.get("success"):
        err = comp.get("error") or {}
        out["compile_error"] = (err.get("raw") if isinstance(err, dict) else str(err))[:800]
        out["first_failure"] = "Compile"
        return out

    tg = Phase3.validate(code, contract_mode=contract_mode)
    out["toll_gate_passed"] = tg.passed
    out["toll_gate_violations"] = [{"rule": v.rule, "reason": v.reason[:80]} for v in tg.violations][:8]
    if not tg.passed:
        out["first_failure"] = "TollGate"
        out["first_failure_detail"] = out["toll_gate_violations"][0] if out["toll_gate_violations"] else None
        return out

    san = sanity.validate(code, im)
    out["sanity_passed"] = san.get("success")
    out["sanity_violations"] = san.get("violations", [])[:6]
    if not san.get("success"):
        out["first_failure"] = "Sanity"
        return out

    ex = ext.extract(code)
    detected = set(ex["features"])
    functions = ex["functions"]
    has_time = bool(re.search(r"tx\.time\s*>=|this\.age\s*>=", code))
    caps = {
        "signature_verification": any("_signature" in f or f == "multisig" for f in detected)
        or bool(re.search(r"checkSig|checkMultiSig", code, re.I)),
        "time_validation": has_time,
        "multisig": _multisig_detected(detected, code),
        "covenant_continuation": _vault_covenant_continuation(detected, code, functions),
        "output_value_validation": ("output_value_validation" in detected) or ("value_check" in detected),
        "multiple_paths": len(functions) >= 2,
    }
    sem = extract_semantic_capabilities(code, contract_mode="vault")
    pool = _cashtoken_alias_pool("vault", caps, detected, code, functions)
    miss_crit = [
        c
        for c in case.get("critical_features", [])
        if not satisfies_requirement(
            c, sem, legacy_alias_checks=pool, detected_features=detected, legacy_capabilities=caps
        )[0]
    ]
    out["missing_criticals"] = miss_crit
    if case.get("tags") and "failure" in case.get("tags", []):
        out["adversarial_case"] = True
        out["must_fail_satisfied"] = not miss_crit
        if miss_crit:
            out["first_failure"] = "AdversarialIntentNotMet"
            return out
    elif miss_crit:
        out["first_failure"] = "EvaluatorCritical"
        return out

    out["first_failure"] = None
    return out


def summarize_history(rows: list[dict]) -> dict:
    if not rows:
        return {}
    n = len(rows)
    compiles = sum(1 for r in rows if r.get("compile_pass"))
    converged = sum(1 for r in rows if r.get("converged"))
    scores = [r["intent_coverage"] for r in rows if r.get("intent_coverage") is not None]
    timeouts = sum(1 for r in rows if r.get("failure_layer") == "Timeout")
    compile_fails = sum(
        1
        for r in rows
        if not r.get("compile_pass") and r.get("failure_layer") not in (None, "Timeout")
    )
    return {
        "runs_observed": n,
        "compile_rate": round(compiles / n, 3),
        "convergence_rate": round(converged / n, 3),
        "timeout_rate": round(timeouts / n, 3),
        "compile_fail_rate": round(compile_fails / n, 3),
        "intent_coverage_when_scored": scores,
        "median_latency_success": sorted(
            [r["latency_seconds"] for r in rows if r.get("compile_pass") and r.get("latency_seconds")]
        ),
    }


def main() -> None:
    suites = load_suites()
    out_dir = ROOT / "benchmark/results/vault_generation"
    out_dir.mkdir(parents=True, exist_ok=True)

    report = []
    for case_id in TARGET_CASES:
        case = suites[case_id]
        history = mine_benchmark_history(case_id)
        hist_summary = summarize_history(history)

        best_code, best_run = best_code_for_case(case_id)
        historical_trace = trace_gates(best_code or "", case) if best_code else {"first_failure": "NoCode"}

        draft_plan = {
            "v_005": ("v_005_tiered_broken_instant", "tiered instant path missing re-anchor"),
            "v_008": ("v_008_vulnerable_announce", "v_008_safe_typical"),
            "vr_010": ("vr_010_backup_cancel_success", "vr_010_overcomplex_attempt"),
            "vr_020": ("vr_020_vulnerable", None),
            "vr_023": (None, None),
            "vr_024": (None, None),
        }
        primary_key, alt_key = draft_plan[case_id]
        primary_draft = best_code if case_id in ("v_005", "vr_023", "vr_024") and best_code else (
            DRAFTS.get(primary_key or "", "") if primary_key else ""
        )
        if primary_key == "v_005_tiered_historical" and best_code:
            primary_draft = best_code

        alt_draft = DRAFTS.get(alt_key, "") if alt_key else ""
        primary_trace = trace_gates(primary_draft or "", case)
        alternate_trace = trace_gates(alt_draft, case) if alt_draft else None

        entry = {
            "case_id": case_id,
            "suite": "vaults.yaml" if case_id.startswith("v_") else "vaults_real",
            "is_failure_case": "failure" in (case.get("tags") or []),
            "intent_preview": case["intent"].strip()[:220],
            "routing": {
                "contract_type": "vault",
                "canonical_pattern": canonical_pattern("vault"),
                "knowledge_files": ["vault_rules.yaml"],
                "routing_mismatch": False,
            },
            "historical_cross_run": hist_summary,
            "historical_runs": history[:15],
            "best_saved_code_run": best_run,
            "saved_code_gate_trace": historical_trace,
            "primary_draft_label": primary_key or f"best_code_from_{best_run}",
            "primary_gate_trace": primary_trace,
            "alternate_draft_label": alt_key,
            "alternate_gate_trace": alternate_trace,
        }

        if primary_draft:
            draft_path = out_dir / f"{case_id}_representative_draft.cash"
            draft_path.write_text(primary_draft, encoding="utf-8")
            entry["representative_draft_path"] = str(draft_path)

        report.append(entry)
        (out_dir / f"{case_id}_rca_offline.json").write_text(
            json.dumps(entry, indent=2) + "\n", encoding="utf-8"
        )
        print(json.dumps({k: entry[k] for k in ("case_id", "historical_cross_run", "saved_code_gate_trace", "primary_gate_trace", "alternate_gate_trace")}, indent=2))

    (out_dir / "rca_offline_summary.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

    # vaults_real convergence snapshot from canonical run
    canonical = ROOT / "benchmark/results/bench_20260401_2119_3456.json"
    if canonical.exists():
        data = json.loads(canonical.read_text(encoding="utf-8"))
        results = data.get("results", [])
        n = len(results)
        conv = sum(1 for r in results if r.get("converged"))
        comp = sum(1 for r in results if r.get("compile_pass"))
        positives = [r for r in results if "failure" not in (r.get("tags") or [])]
        pos_conv = sum(1 for r in positives if r.get("converged"))
        snapshot = {
            "canonical_run": canonical.stem,
            "total_cases": n,
            "compile_rate": round(comp / n, 3),
            "convergence_rate_all": round(conv / n, 3),
            "positive_cases": len(positives),
            "positive_convergence_rate": round(pos_conv / len(positives), 3),
            "target_95pct_all": f"{int(0.95 * n + 0.99)}/{n}",
            "target_95pct_positives": f"{int(0.95 * len(positives) + 0.99)}/{len(positives)}",
        }
        (out_dir / "vaults_real_convergence_snapshot.json").write_text(
            json.dumps(snapshot, indent=2) + "\n", encoding="utf-8"
        )
        print("\n=== vaults_real convergence snapshot ===")
        print(json.dumps(snapshot, indent=2))


if __name__ == "__main__":
    main()
