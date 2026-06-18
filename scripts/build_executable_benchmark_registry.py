#!/usr/bin/env python3
"""Build executable benchmark registry + difficulty metadata."""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FULL = ROOT / "docs" / "benchmark_registry.json"
EXEC = ROOT / "docs" / "benchmark_registry_executable.json"

# difficulty: 1=simple bug, 2=single invariant, 3=cross-feature, 4=complex protocol, 5=adversarial
EXECUTABLE = [
    {
        "id": "bench_payroll_001",
        "family": "payroll",
        "difficulty": 2,
        "intent": "Payroll distributing fixed salary amounts to predetermined employee lockingBytecode destinations. Owner must authorize each payout.",
        "contract_ref": "tests/audit_classification_matrix/scenarios.py:PAYROLL_RECIPIENTS_ONLY",
        "mutation": "missing_fixed_salary",
        "expected_findings": ["intent_fixed_amount_per_recipient"],
        "expected_severity": ["MEDIUM"],
        "expected_invariants": ["fixed_amount_per_recipient:MISSING", "auth_gate:ENFORCED"],
        "expected_kind": ["invariant_gap"],
        "evaluation_mode": "detector_only",
        "source": "handcrafted",
        "tier": 1,
    },
    {
        "id": "bench_payroll_002",
        "family": "payroll",
        "difficulty": 1,
        "intent": "Owner-signed payroll with recipient binding and token conservation.",
        "contract_ref": "tests/audit_classification_matrix/scenarios.py:PAYROLL_RECIPIENTS_ONLY",
        "expected_findings": [],
        "expected_severity": [],
        "expected_invariants": ["recipient_binding:ENFORCED", "auth_gate:ENFORCED"],
        "expected_kind": [],
        "evaluation_mode": "detector_only",
        "source": "handcrafted",
        "tier": 1,
    },
    {
        "id": "bench_payroll_004",
        "family": "payroll",
        "difficulty": 1,
        "intent": "Payroll without owner signature on distribute path.",
        "contract_ref": "tests/audit_classification_matrix/scenarios.py:PAYROLL_NO_AUTH",
        "expected_findings": ["intent_auth_gate"],
        "expected_severity": ["HIGH"],
        "expected_invariants": ["auth_gate:MISSING"],
        "expected_kind": ["vulnerability"],
        "evaluation_mode": "detector_only",
        "source": "handcrafted",
        "tier": 1,
    },
    {
        "id": "bench_hashlock_001",
        "family": "hashlock",
        "difficulty": 1,
        "intent": "Spend only by revealing SHA256 preimage matching hash.",
        "contract_ref": "tests/fixtures/audit_benchmark/hashlock/secure.cash",
        "expected_findings": [],
        "expected_invariants": [],
        "expected_kind": [],
        "evaluation_mode": "detector_only",
        "source": "handcrafted",
        "tier": 1,
    },
    {
        "id": "bench_hashlock_002",
        "family": "hashlock",
        "difficulty": 1,
        "intent": "Spend only by revealing SHA256 preimage matching hash.",
        "contract_ref": "tests/fixtures/audit_benchmark/hashlock/vulnerable_no_hash.cash",
        "expected_findings": ["hash_preimage_binding"],
        "expected_invariants": [],
        "evaluation_mode": "detector_only",
        "source": "handcrafted",
        "tier": 1,
        "coverage_probe": True,
        "notes": "P0 gap — no detector today; probe documents missing coverage",
    },
    {
        "id": "bench_hashlock_003",
        "family": "hashlock",
        "difficulty": 3,
        "intent": "HTLC: claim with preimage or refund after timeout.",
        "contract_ref": "tests/fixtures/audit_benchmark/hashlock/htlc_secure.cash",
        "expected_findings": [],
        "expected_invariants": [],
        "evaluation_mode": "detector_only",
        "source": "handcrafted",
        "tier": 1,
    },
    {
        "id": "bench_p0_fake_auth_001",
        "family": "cross_family",
        "difficulty": 5,
        "intent": "Owner must authorize pay; checkSig required on spend path.",
        "contract_ref": "tests/fixtures/audit_benchmark/p0/fake_auth_dead_code.cash",
        "expected_findings": ["intent_auth_gate"],
        "expected_kind": ["vulnerability"],
        "evaluation_mode": "detector_only",
        "source": "adversarial_variant",
        "tier": 1,
        "coverage_probe": True,
        "notes": "Dead-code checkSig — intent layer may miss; adversarial FAKE_AUTH family",
    },
    {
        "id": "bench_p0_dual_path_001",
        "family": "multisig",
        "difficulty": 2,
        "intent": "Only admin may spend; public path must not move value without admin sig.",
        "contract_ref": "tests/fixtures/audit_benchmark/p0/dual_path_bypass.cash",
        "expected_findings": ["intent_auth_gate"],
        "expected_kind": ["vulnerability"],
        "evaluation_mode": "detector_only",
        "source": "adversarial_variant",
        "tier": 1,
        "coverage_probe": True,
        "notes": "Dual path — AUTH-1 style; deterministic auth_gate may not fire on publicSpend",
    },
    {
        "id": "bench_p0_oracle_001",
        "family": "oracle",
        "difficulty": 3,
        "intent": "Owner-signed swap; oracle UTXO on input[1] must match oracleLock.",
        "contract_ref": "tests/fixtures/audit_benchmark/p0/oracle_secure.cash",
        "expected_findings": [],
        "expected_invariants": [],
        "evaluation_mode": "policy_only",
        "source": "handcrafted",
        "tier": 2,
        "policy_judgment": {
            "judge_version": "2.1",
            "verdict": "finding",
            "intent_fidelity_score": 8,
            "finding": {
                "gap_id": "semantic.oracle_reliance",
                "attacker_gain": False,
                "authorization_impact": False,
                "value_impact": "none",
                "trust_assumption": "oracle",
                "summary": "Swap depends on honest oracle price feed.",
                "reasoning": "Trust assumption only.",
                "reasoning_steps": ["1", "2", "3", "4", "5", "6"],
            },
        },
        "expected_kind": ["deployment_requirement"],
    },
    {
        "id": "bench_adv_auth2_replay",
        "family": "payroll",
        "difficulty": 5,
        "intent": "Signed payroll with fixed salaries.",
        "contract_ref": "tests/audit_classification_matrix/scenarios.py:PAYROLL_FIXED_SALARY",
        "evaluation_mode": "policy_only",
        "source": "adversarial_variant",
        "tier": 2,
        "policy_judgment": {
            "judge_version": "2.1",
            "verdict": "no_issue",
            "intent_fidelity_score": 9,
            "intent_fidelity_notes": "Auth enforced; hallucination retracted.",
        },
        "expected_findings": [],
        "expected_kind": [],
        "notes": "AUTH-2 V2.1 — no vulnerability on auth hallucination",
    },
]


def add_difficulty_to_full(data: dict) -> None:
    mutation_diff = {
        "secure_baseline": 1,
        "missing_auth": 1,
        "remove_checksig": 1,
        "output_binding_missing": 2,
        "index_underflow": 2,
        "token_category_drift": 2,
        "composite": 3,
        "as_collected": 4,
    }
    for b in data.get("benchmarks", []):
        if "difficulty" in b:
            continue
        mut = b.get("mutation", "")
        b["difficulty"] = mutation_diff.get(mut, 2)
        if b.get("source") == "adversarial_variant":
            b["difficulty"] = 5
        if b.get("family") == "cross_family":
            b["difficulty"] = max(b.get("difficulty", 3), 3)


def main() -> None:
    exec_doc = {
        "schema_version": "1.0",
        "description": "Materialized audit benchmarks — zero LLM, CI-ready",
        "total_count": len(EXECUTABLE),
        "benchmarks": EXECUTABLE,
    }
    EXEC.write_text(json.dumps(exec_doc, indent=2), encoding="utf-8")
    print(f"Wrote {len(EXECUTABLE)} executable benchmarks to {EXEC}")

    if FULL.is_file():
        data = json.loads(FULL.read_text(encoding="utf-8"))
        add_difficulty_to_full(data)
        FULL.write_text(json.dumps(data, indent=2), encoding="utf-8")
        print(f"Added difficulty field to {data['total_count']} entries in {FULL}")


if __name__ == "__main__":
    main()
