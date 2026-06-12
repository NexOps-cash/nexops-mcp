"""Offline generation RCA: deterministic routing + gate trace without LLM.

Infers Phase1 routing from pipeline keyword rules, then runs lint/compile/toll/sanity
on representative synthesis drafts for rp_003 / rp_004.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import yaml
from src.models import IntentModel
from src.services.compiler import CompilerService
from src.services.dsl_lint import get_dsl_linter
from src.services.pattern_profiles import canonical_pattern
from src.services.pipeline import Phase3, resolve_effective_mode
from src.services.sanity_checker import get_sanity_checker
from src.services.structural_integrity import is_structurally_valid


def infer_routing(intent: str, llm_contract_type: str = "generic") -> dict:
    """Apply pipeline.py keyword normalization (no LLM)."""
    intent_lower = intent.lower()
    current_type = llm_contract_type
    features: list[str] = ["timelock", "spending"]

    if any(w in intent_lower for w in ("crowdfund", "fundrais", "goal", "backers", "pledge")):
        current_type = "refundable_crowdfund"
    elif any(
        w in intent_lower
        for w in ("vest", "vesting", "cliff", "unlock over time", "linear release", "salary")
    ):
        current_type = "linear_vesting"
    elif any(
        w in intent_lower
        for w in ("stream", "streaming", "decay", "linear decay", "block-by-block")
    ):
        current_type = "streaming"
    elif any(w in intent_lower for w in ("escrow", "arbiter", "refund", "reclaim", "timeout")):
        current_type = "escrow"
    elif "payment" in intent_lower and ("seller" in intent_lower or "buyer" in intent_lower):
        current_type = "escrow"

    # rp_004: vesting schedule dominates over reclaim wording
    if any(
        w in intent_lower
        for w in ("gradual", "25%", "every 7 days", "linear release", "vesting")
    ):
        current_type = "linear_vesting"

    # rp_003: subscription + reclaim -> escrow (not crowdfund)
    elif "subscription" in intent_lower or (
        "reclaim" in intent_lower and "remainder" in intent_lower
    ):
        if current_type in ("generic", "distribution"):
            current_type = "escrow"

    im = IntentModel(contract_type=current_type, features=features)
    effective = resolve_effective_mode(im)
    canonical = canonical_pattern(effective)
    return {
        "assumed_llm_contract_type": llm_contract_type,
        "normalized_contract_type": current_type,
        "effective_mode": effective,
        "canonical_pattern": canonical,
        "features": features,
        "routing_mismatch": canonical != "refundable_payment",
    }


def trace_gates(code: str, intent_model: IntentModel) -> dict:
    contract_mode = (resolve_effective_mode(intent_model) or "").lower()
    linter = get_dsl_linter()
    compiler = CompilerService()
    sanity = get_sanity_checker()

    out = {
        "draft_exists": bool(code and code.strip()),
        "structurally_valid": is_structurally_valid(code) if code else False,
    }
    if not out["draft_exists"]:
        out["first_failure"] = "Phase2_empty_draft"
        return out

    lint = linter.lint(code, contract_mode=contract_mode)
    out["lint_passed"] = lint.get("passed")
    out["lint_violations"] = [
        {"rule_id": v.get("rule_id"), "message": v.get("message")}
        for v in lint.get("violations", [])
    ][:8]
    if not lint.get("passed"):
        out["first_failure"] = "DSLLint"
        return out

    comp = compiler.compile(code)
    out["compile_passed"] = comp.get("success")
    if not comp.get("success"):
        err = comp.get("error") or {}
        out["compile_error"] = (err.get("raw") if isinstance(err, dict) else str(err))[:1200]
        out["first_failure"] = "Compile"
        return out

    tg = Phase3.validate(code, contract_mode=contract_mode)
    out["toll_gate_passed"] = tg.passed
    out["toll_gate_violations"] = [
        {"rule": v.rule, "reason": v.reason} for v in tg.violations
    ][:8]
    if not tg.passed:
        out["first_failure"] = "TollGate"
        return out

    san = sanity.validate(code, intent_model)
    out["sanity_passed"] = san.get("success")
    out["sanity_violations"] = san.get("violations", [])[:8]
    if not san.get("success"):
        out["first_failure"] = "Sanity"
        return out

    out["first_failure"] = None
    return out


# Representative drafts mimicking FREE_SYNTHESIS outputs on inferred routes
DRAFTS = {
    "rp_003_escrow_simple": '''
pragma cashscript ^0.13.0;
contract SubscriptionEscrow(pubkey service, pubkey subscriber, int monthlyPeriod) {
    function claim(sig serviceSig) {
        require(checkSig(serviceSig, service));
        require(tx.time >= monthlyPeriod);
        require(tx.outputs.length == 1);
        require(tx.outputs[0].value == tx.inputs[this.activeInputIndex].value);
    }
    function cancel(sig subscriberSig) {
        require(checkSig(subscriberSig, subscriber));
        require(tx.outputs.length == 1);
        require(tx.outputs[0].value == tx.inputs[this.activeInputIndex].value);
    }
}
''',
    "rp_003_escrow_covenant_attempt": '''
pragma cashscript ^0.13.0;
contract SubscriptionVault(pubkey service, pubkey subscriber, int monthlyPeriod) {
    function claim(sig serviceSig, int payoutAmount) {
        require(checkSig(serviceSig, service));
        require(tx.time >= monthlyPeriod);
        require(tx.outputs.length == 2);
        require(tx.outputs[0].lockingBytecode == this.activeBytecode);
        require(tx.outputs[0].value == tx.inputs[this.activeInputIndex].value - payoutAmount);
        require(tx.outputs[1].value == payoutAmount);
    }
    function cancel(sig subscriberSig) {
        require(checkSig(subscriberSig, subscriber));
        require(tx.outputs.length == 1);
        require(tx.outputs[0].lockingBytecode == this.activeBytecode);
        require(tx.outputs[0].value == tx.inputs[this.activeInputIndex].value);
    }
}
''',
    "rp_004_vesting_golden_shape": '''
pragma cashscript ^0.13.0;
contract GradualRelease(pubkey recipient, pubkey sender, int periodSeconds, int totalPeriods, int inactiveTimeout) {
    function release(sig recipientSig, int releaseAmount) {
        require(checkSig(recipientSig, recipient));
        require(tx.time >= periodSeconds);
        require(tx.outputs.length == 3);
        require(tx.outputs[0].value <= releaseAmount);
        require(tx.outputs[2].lockingBytecode == this.activeBytecode);
    }
    function reclaim(sig senderSig) {
        require(checkSig(senderSig, sender));
        require(tx.time >= inactiveTimeout);
        require(tx.outputs.length == 1);
        require(tx.outputs[0].value == tx.inputs[this.activeInputIndex].value);
    }
}
''',
    "rp_004_decay_broken_formula": '''
pragma cashscript ^0.13.0;
contract VestingDecay(pubkey recipient, int startTime, int duration, int totalAmount) {
    function unlock(sig recipientSig) {
        int elapsed = tx.time - startTime;
        int payout = totalAmount * elapsed / duration;
        require(checkSig(recipientSig, recipient));
        require(tx.outputs.length == 1);
        require(tx.outputs[0].value == payout);
    }
    function reclaim(sig recipientSig) {
        require(checkSig(recipientSig, recipient));
        require(tx.time >= startTime + duration);
        require(tx.outputs.length == 1);
    }
}
''',
}


def main() -> None:
    suite = yaml.safe_load((ROOT / "benchmark/suites/refundable_payment.yaml").read_text())
    out_dir = ROOT / "benchmark/results/refundable_generation"
    out_dir.mkdir(parents=True, exist_ok=True)

    report = []
    for case in suite:
        if case["id"] not in ("rp_003", "rp_004"):
            continue
        intent = case["intent"].strip()
        routing = infer_routing(intent, llm_contract_type="generic")
        routing_llm_escrow = infer_routing(intent, llm_contract_type="escrow")
        routing_llm_vesting = infer_routing(intent, llm_contract_type="linear_vesting")

        im = IntentModel(
            contract_type=routing["normalized_contract_type"],
            features=routing["features"],
        )

        draft_key = "rp_003_escrow_simple" if case["id"] == "rp_003" else "rp_004_vesting_golden_shape"
        alt_key = (
            "rp_003_escrow_covenant_attempt"
            if case["id"] == "rp_003"
            else "rp_004_decay_broken_formula"
        )

        primary = trace_gates(DRAFTS[draft_key], im)
        alternate = trace_gates(DRAFTS[alt_key], im)

        entry = {
            "case_id": case["id"],
            "intent_preview": intent[:200],
            "routing_inference_generic_llm": routing,
            "routing_if_llm_escrow": routing_llm_escrow,
            "routing_if_llm_linear_vesting": routing_llm_vesting,
            "primary_draft": draft_key,
            "primary_gate_trace": primary,
            "alternate_draft": alt_key,
            "alternate_gate_trace": alternate,
            "historical_benchmark": {
                "run_id": "bench_20260331_2121_6f05",
                "failure_layer": "Compile",
                "compile_pass": False,
                "code_saved": False,
                "retries_used": 3,
                "latency_seconds": 79.2 if case["id"] == "rp_003" else 52.5,
            },
        }
        draft_path = out_dir / f"{case['id']}_representative_draft.cash"
        draft_path.write_text(DRAFTS[draft_key], encoding="utf-8")
        entry["representative_draft_path"] = str(draft_path)

        report.append(entry)
        out_path = out_dir / f"{case['id']}_rca_offline.json"
        out_path.write_text(json.dumps(entry, indent=2) + "\n", encoding="utf-8")
        print(json.dumps(entry, indent=2))

    (out_dir / "rca_offline_summary.json").write_text(
        json.dumps(report, indent=2) + "\n", encoding="utf-8"
    )


if __name__ == "__main__":
    main()
