#!/usr/bin/env python3
"""Generate audit benchmark registry JSON for research sprint Workstream A."""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "docs" / "benchmark_registry.json"

# Hand-crafted + classification matrix seeds
HANDCRAFTED = [
    {
        "id": "bench_payroll_001",
        "family": "payroll",
        "intent": "Payroll distributing fixed salary amounts to predetermined employee lockingBytecode destinations. Owner must authorize each payout.",
        "contract_ref": "tests/audit_classification_matrix/scenarios.py:PAYROLL_FIXED_SALARY",
        "mutation": "remove_per_output_salary_require",
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
        "intent": "Payroll with recipient binding only; amounts may vary.",
        "contract_ref": "tests/audit_classification_matrix/scenarios.py:PAYROLL_RECIPIENTS_ONLY",
        "mutation": "secure_baseline",
        "expected_findings": [],
        "expected_severity": [],
        "expected_invariants": ["recipient_binding:ENFORCED", "auth_gate:ENFORCED"],
        "expected_kind": [],
        "evaluation_mode": "detector_only",
        "source": "handcrafted",
        "tier": 1,
    },
    {
        "id": "bench_payroll_003",
        "family": "payroll",
        "intent": "Payroll with treasury pre-funding requirement.",
        "contract_ref": "tests/audit_classification_matrix/scenarios.py:PAYROLL_FIXED_SALARY",
        "mutation": "secure_baseline",
        "expected_findings": [],
        "expected_severity": [],
        "expected_invariants": ["treasury_prefunding:NOT_ENFORCEABLE_ONCHAIN"],
        "expected_kind": [],
        "evaluation_mode": "policy_only",
        "source": "handcrafted",
        "tier": 2,
        "notes": "Treasury prefunding must NOT become VULNERABILITY; see FP playbook",
    },
    {
        "id": "bench_payroll_004",
        "family": "payroll",
        "intent": "Payroll without owner signature on distribute path.",
        "contract_ref": "tests/audit_classification_matrix/scenarios.py:PAYROLL_NO_AUTH",
        "mutation": "remove_checksig",
        "expected_findings": ["intent_auth_gate"],
        "expected_severity": ["HIGH"],
        "expected_invariants": ["auth_gate:MISSING"],
        "expected_kind": ["vulnerability"],
        "evaluation_mode": "detector_only",
        "source": "handcrafted",
        "tier": 1,
    },
]

MIGRATION_MAP = {
    "escrow": ("escrow.yaml", ["esc_001", "esc_002", "esc_003", "esc_004", "esc_005", "esc_006"]),
    "escrow_suite": ("escrow_suite.yaml", ["escrow_basic_multisig", "escrow_timeout_refund", "escrow_2of3_release"]),
    "vaultd": ("split_payment.yaml", ["sp_001", "sp_002", "split_002_payroll", "split_003_multisig_distribution"]),
    "vault": ("vaults.yaml", ["v_001", "v_002", "v_003", "v_004", "v_005", "v_006"]),
    "timelock": ("timelock.yaml", ["tl_001", "tl_002", "tl_003", "tl_004", "tl_005"]),
    "hashlock": ("hashlock.yaml", ["hl_001", "hl_002", "hl_003", "hl_004", "hl_005"]),
    "multisig": ("multisig.yaml", ["ms_001", "ms_002", "ms_003", "ms_004", "ms_005", "ms_006"]),
    "refundable": ("refundable_payment.yaml", ["rp_001", "rp_002", "rp_003", "rp_004", "rp_005", "rp_006"]),
    "conditional_spend": ("conditional_spend.yaml", ["cs_001", "cs_002", "cs_003", "cs_004", "cs_005"]),
    "covenant": ("covenant.yaml", ["cov_001", "cov_002", "cov_003"]),
    "decay": ("decay.yaml", ["dec_001", "dec_002", "dec_003"]),
    "vesting": ("vesting.yaml", ["vesting_cliff_basic", "vesting_linear", "vesting_with_owner_cancel"]),
    "cashtokens_ft": ("cashtokens_ft.yaml", ["ct_ft_family_001", "ct_ft_family_002", "ct_ft_family_003"]),
    "cashtokens_nft_imm": ("cashtokens_nft_immutable.yaml", ["ct_imm_family_001", "ct_imm_family_002"]),
    "cashtokens_nft_mut": ("cashtokens_nft_mutable.yaml", ["ct_mut_family_001", "ct_mut_family_002"]),
    "cashtokens_nft_mint": ("cashtokens_nft_minting.yaml", ["ct_mint_family_001", "ct_mint_family_002"]),
    "cashtokens_hybrid": ("cashtokens_hybrid.yaml", ["ct_hybrid_family_001", "ct_hybrid_family_002"]),
    "cashtokens_invalid": (
        "cashtokens_invalid_negative.yaml",
        ["ct_invalid_auth_leak_001", "ct_invalid_cat_drift_001", "ct_invalid_inflation_001"],
    ),
}

FLAW_VARIANTS = [
    ("secure_baseline", [], [], "none"),
    ("missing_auth", ["intent_auth_gate"], ["HIGH"], "vulnerability"),
    ("output_binding_missing", ["output_binding_missing"], ["MEDIUM"], "invariant_gap"),
    ("index_underflow", ["index_underflow"], ["HIGH"], "vulnerability"),
    ("token_category_drift", ["token_category_drift"], ["CRITICAL"], "vulnerability"),
]

ORACLE_BENCH = [
    {
        "id": f"bench_oracle_{i:03d}",
        "family": "oracle",
        "intent": intent,
        "contract_ref": "tests/adversarial_semantic_judge/scenarios.py:ORACLE_PRICE",
        "mutation": mut,
        "expected_findings": findings,
        "expected_severity": sev,
        "expected_invariants": inv,
        "expected_kind": kinds,
        "evaluation_mode": mode,
        "source": "handcrafted",
        "tier": tier,
    }
    for i, (intent, mut, findings, sev, inv, kinds, mode, tier) in enumerate(
        [
            (
                "Oracle-gated swap; owner signs; oracle UTXO must match oracleLock.",
                "secure_baseline",
                [],
                [],
                ["auth_gate:ENFORCED"],
                [],
                "policy_only",
                2,
            ),
            (
                "Price feed from off-chain oracle operator; trust deployment.",
                "off_chain_trust",
                [],
                [],
                ["treasury_prefunding:NOT_ENFORCEABLE_ONCHAIN"],
                ["deployment_requirement"],
                "policy_only",
                2,
            ),
            (
                "Swap with unconstrained oracle input index.",
                "oracle_input_unvalidated",
                ["input_output_coupling"],
                ["MEDIUM"],
                ["auth_gate:ENFORCED"],
                ["invariant_gap"],
                "detector_only",
                1,
            ),
            (
                "Owner-signed swap; minPrice enforced but oracle bytecode not bound.",
                "missing_oracle_binding",
                ["output_binding_missing"],
                ["MEDIUM"],
                ["recipient_binding:MISSING"],
                ["invariant_gap"],
                "full_audit",
                3,
            ),
            (
                "Stale oracle price accepted without timelock.",
                "stale_oracle",
                [],
                [],
                [],
                ["operational_risk"],
                "policy_only",
                2,
            ),
            (
                "Multi-oracle median; partial oracle set accepted.",
                "partial_oracle_aggregation",
                ["partial_aggregation_risk"],
                ["HIGH"],
                [],
                ["vulnerability"],
                "detector_only",
                1,
            ),
        ],
        start=1,
    )
]

DAO_TREASURY = [
    {
        "id": f"bench_dao_treasury_{i:03d}",
        "family": "dao_treasury",
        "intent": intent,
        "contract_ref": ref,
        "mutation": "composite",
        "expected_findings": findings,
        "expected_severity": sev,
        "expected_invariants": inv,
        "expected_kind": kinds,
        "evaluation_mode": "full_audit",
        "source": "handcrafted",
        "tier": 2,
    }
    for i, (intent, ref, findings, sev, inv, kinds) in enumerate(
        [
            (
                "DAO treasury 2-of-3 multisig with timelock on large withdrawals.",
                "composite:multisig+timelock",
                [],
                [],
                ["auth_gate:ENFORCED"],
                [],
            ),
            (
                "Treasury spend requires council signatures; emergency path timelocked.",
                "composite:vault+multisig",
                [],
                [],
                ["auth_gate:ENFORCED"],
                [],
            ),
            (
                "DAO payroll from treasury UTXO; external prefunding assumed.",
                "composite:payroll+treasury",
                [],
                [],
                ["treasury_prefunding:NOT_ENFORCEABLE_ONCHAIN"],
                ["deployment_requirement"],
            ),
            (
                "Treasury migration to new covenant without category preservation.",
                "composite:hybrid_migration",
                ["hybrid_continuity_break"],
                ["CRITICAL"],
                ["token_category_preservation:MISSING"],
                ["vulnerability"],
            ),
        ],
        start=1,
    )
]

CROSS_FAMILY = [
    {
        "id": f"bench_cross_{i:03d}",
        "family": "cross_family",
        "intent": intent,
        "contract_ref": "synthetic",
        "mutation": mut,
        "expected_findings": findings,
        "expected_severity": sev,
        "expected_invariants": inv,
        "expected_kind": kinds,
        "evaluation_mode": "full_audit",
        "source": "handcrafted",
        "tier": 2,
    }
    for i, (intent, mut, findings, sev, inv, kinds) in enumerate(
        [
            ("Escrow with embedded timelock refund and hashlock release.", "escrow+hashlock", [], [], ["auth_gate:ENFORCED"], []),
            ("Vault holding NFT mint authority with covenant continuation.", "vault+nft_minting", ["authority_leak"], ["CRITICAL"], [], ["vulnerability"]),
            ("Payroll split with FT token category preservation.", "payroll+ft", [], [], ["token_category_preservation:ENFORCED"], []),
            ("Refundable crowdfund with decay schedule.", "refundable+decay", [], [], [], []),
            ("Multisig escrow with oracle arbiter.", "multisig+escrow+oracle", [], [], ["auth_gate:ENFORCED"], []),
            ("Conditional spend atomic swap with hashlock preimage.", "swap+hashlock", [], [], [], []),
            ("Subscription streaming with vault custody.", "decay+vault", [], [], [], []),
            ("Hybrid FT+NFT sidecar treasury.", "hybrid+treasury", ["capability_hybrid_migration_mismatch"], ["HIGH"], [], ["vulnerability"]),
        ],
        start=1,
    )
]

REALWORLD_SLOTS = [
    {
        "id": f"bench_realworld_{i:03d}",
        "family": family,
        "intent": f"Real-world {family} contract from audit_benchmark_realworld index entry rw_{i:03d}.",
        "contract_ref": f"audit_benchmark_realworld/contracts/rw_{i:03d}.cash",
        "mutation": "as_collected",
        "expected_findings": [],
        "expected_severity": [],
        "expected_invariants": [],
        "expected_kind": [],
        "evaluation_mode": "full_audit",
        "source": "realworld",
        "tier": 3,
        "notes": "Populate from A.5 index; expected findings set after classification",
    }
    for i, family in enumerate(
        [
            "escrow", "vault", "multisig", "payroll", "timelock", "hashlock",
            "refundable", "covenant", "cashtokens_ft", "cashtokens_nft",
            "hybrid", "escrow", "vault", "multisig", "payroll", "timelock",
            "covenant", "cashtokens_ft", "cashtokens_nft", "hybrid",
        ],
        start=1,
    )
]


def migrated_entries() -> list[dict]:
    entries = []
    seq = 1
    for _group, (suite_file, case_ids) in MIGRATION_MAP.items():
        family = case_ids[0].split("_")[0] if case_ids else "generic"
        if case_ids[0].startswith("ct_"):
            family = "cashtokens"
        for case_id in case_ids:
            for flaw_name, findings, sev, kind in FLAW_VARIANTS[:2]:  # secure + one flaw each
                entries.append(
                    {
                        "id": f"bench_mig_{seq:03d}",
                        "family": family,
                        "intent": f"Migrated from benchmark/suites/{suite_file} case {case_id}.",
                        "contract_ref": f"benchmark/suites/{suite_file}:{case_id}",
                        "migration_source_id": case_id,
                        "mutation": flaw_name,
                        "expected_findings": findings,
                        "expected_severity": sev,
                        "expected_invariants": ["auth_gate:ENFORCED"] if flaw_name == "secure_baseline" else [],
                        "expected_kind": [kind] if kind != "none" else [],
                        "evaluation_mode": "detector_only" if flaw_name != "secure_baseline" else "detector_only",
                        "source": "migrated_from_generation",
                        "tier": 1,
                    }
                )
                seq += 1
    return entries


def main() -> None:
    registry = {
        "schema_version": "1.0",
        "description": "NexOps audit benchmark registry — research sprint Workstream A",
        "total_count": 0,
        "benchmarks": [],
    }
    all_bench = (
        HANDCRAFTED
        + migrated_entries()
        + ORACLE_BENCH
        + DAO_TREASURY
        + CROSS_FAMILY
        + REALWORLD_SLOTS
    )
    registry["benchmarks"] = all_bench
    registry["total_count"] = len(all_bench)
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(registry, indent=2), encoding="utf-8")
    print(f"Wrote {registry['total_count']} benchmarks to {OUT}")


if __name__ == "__main__":
    main()
