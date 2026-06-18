#!/usr/bin/env python3
"""Generate security pattern knowledge base docs."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "docs" / "security_patterns"

PATTERNS = {
    "payroll": {
        "purpose": "Distribute fixed or bounded payments to predetermined recipients; owner or multisig authorizes each spend.",
        "security_model": "Only authorized parties can move funds; recipients and amounts match declared intent; token categories preserved on splits.",
        "invariants": ["auth_gate", "recipient_binding", "fixed_amount_per_recipient", "value_conservation", "token_category_preservation"],
        "vulnerabilities": ["Missing checkSig", "Unbound output lockingBytecode", "Salary sum mismatch", "Token category drift"],
        "checklist": ["verify checkSig on spend path", "require tx.outputs[N].lockingBytecode for each payee", "sum tokenAmounts == input", "tokenCategory tied to input"],
        "gaps": "Proportional splits without literal fixed amounts; treasury prefunding is deployment not on-chain",
        "refs": "bench_payroll_001-004, payroll_a-d classification",
    },
    "escrow": {
        "purpose": "Hold funds until release conditions (multi-party sig) or refund conditions (timeout) met.",
        "security_model": "Release requires all required signatures; refund only after timeout to original party; value conserved.",
        "invariants": ["auth_gate", "value_conservation"],
        "vulnerabilities": ["Missing refund branch", "Timeout operator inverted", "Arbiter over-power", "Unbound release outputs"],
        "checklist": ["release branch multisig", "refund branch timelock + sender auth", "output binding on all paths", "no third path drain"],
        "gaps": "EscrowRoleEnforcementDetector unregistered; external funding is deployment",
        "refs": "esc_001-006, escrow_a/b classification",
    },
    "vault": {
        "purpose": "Custody with delayed withdrawal, cancellation, or role-separated emergency paths.",
        "security_model": "Withdrawals require auth + timelock where declared; emergency paths cannot bypass stronger invariants.",
        "invariants": ["auth_gate"],
        "vulnerabilities": ["Missing timelock on intent", "Emergency path without delay", "Index OOB on staged inputs"],
        "checklist": ["tx.time guards on delayed paths", "checkSig on all spend functions", "output count bounds", "covenant continuation if stateful"],
        "gaps": "Intent timelock heuristic via SanityChecker only",
        "refs": "v_001-008, vault_a/b classification",
    },
    "timelock": {
        "purpose": "Enforce minimum block time before spend or refund.",
        "security_model": "tx.time >= deadline on delayed paths; early spend impossible.",
        "invariants": ["auth_gate"],
        "vulnerabilities": ["tx.time > instead of >=", "Wrong comparison operator", "Timelock on wrong branch"],
        "checklist": ["time_validation_error lint", "paired auth on spend after lock", "refund path timing"],
        "gaps": "No dedicated timelock invariant ID",
        "refs": "tl_001-005 migration",
    },
    "hashlock": {
        "purpose": "Spend requires SHA256 preimage reveal; enables atomic swaps.",
        "security_model": "Hashlock verified on spend path; preimage length checked; no spend without valid hash.",
        "invariants": ["auth_gate"],
        "vulnerabilities": ["Missing hash verify", "Preimage length not checked", "Hash on wrong path", "Replay across contracts"],
        "checklist": ["require(sha256(preimage) == hash)", "commitment_length_missing", "single-use enforcement via covenant"],
        "gaps": "**P0: zero audit coverage**; no hashlock detector",
        "refs": "hl_001-005 migration",
    },
    "multisig": {
        "purpose": "M-of-N signature threshold before spend.",
        "security_model": "checkMultiSig with correct threshold; distinct pubkeys; no single-signer bypass.",
        "invariants": ["auth_gate"],
        "vulnerabilities": ["Threshold too low", "Pubkey reuse", "Duplicate signatures", "Bypass path without multisig"],
        "checklist": ["checkMultiSig threshold", "multisig_distinctness_flaw", "multisig_signature_reuse", "no parallel unsigned path"],
        "gaps": "Intent sanity for declared M-of-N",
        "refs": "ms_001-006, multisig_a/b",
    },
    "split_payment": {
        "purpose": "Split single input across N outputs (revenue share, treasury distribution).",
        "security_model": "Recipients bound; sums conserved; optional fixed per-recipient amounts.",
        "invariants": ["recipient_binding", "value_conservation", "fixed_amount_per_recipient", "token_category_preservation"],
        "vulnerabilities": ["Unbound recipient", "Partial sum", "Category drift on token split"],
        "checklist": ["output_binding_missing", "split conservation helpers", "intent invariants"],
        "gaps": "Proportional vs fixed amount detection heuristic",
        "refs": "sp_001-010, split_a/b",
    },
    "subscription": {
        "purpose": "Streaming or decay schedules (vesting, Dutch auction, linear unlock).",
        "security_model": "Claimable amount monotonic with time; cancel/auth paths separated; no double-claim.",
        "invariants": ["auth_gate", "value_conservation"],
        "vulnerabilities": ["Time arithmetic overflow", "Claim without decay update", "Cancel bypasses vesting"],
        "checklist": ["tx.time progression", "state commitment update", "covenant continuation"],
        "gaps": "No decay-specific audit matrix",
        "refs": "dec_001-003, vesting_* migration",
    },
    "refundable_payment": {
        "purpose": "Crowdfund or subscription escrow with refund if conditions fail.",
        "security_model": "Refund path returns to funder; release path requires milestone auth; timeout refunds.",
        "invariants": ["auth_gate", "value_conservation"],
        "vulnerabilities": ["Refund to wrong party", "Release without quorum", "Missing timeout refund"],
        "checklist": ["dual branch structure", "timelock on refund", "recipient binding on release"],
        "gaps": "Zero audit classification coverage",
        "refs": "rp_001-006 migration",
    },
    "conditional_spend": {
        "purpose": "Atomic swap or conditional release (hashlock + timelock combos).",
        "security_model": "Both sides' conditions enforced in same tx or linked covenant chain.",
        "invariants": ["auth_gate", "value_conservation"],
        "vulnerabilities": ["One-sided enforcement", "Oracle/truth external to covenant", "Wrong input index for counterparty"],
        "checklist": ["input_output_coupling", "hash + timelock combo", "output binding"],
        "gaps": "Phase1 routing issues documented in conditional_spend_phase1b_rca",
        "refs": "cs_001-005 migration",
    },
    "covenant": {
        "purpose": "Stateful UTXO chain with lockingBytecode continuation and optional token state.",
        "security_model": "Every spend recreates covenant or allowed exit; token category/amount/commitment preserved per rules.",
        "invariants": ["value_conservation", "token_category_preservation"],
        "vulnerabilities": ["Continuation break", "State fork", "Premature exit", "Mint authority escape"],
        "checklist": ["vulnerable_covenant detector", "lockingBytecode == activeBytecode", "capability detectors"],
        "gaps": "Complex state machines weakly covered semantically",
        "refs": "cov_001-003, stateful_suite",
    },
    "oracle": {
        "purpose": "Spend gated on external price or data feed UTXO.",
        "security_model": "Oracle UTXO script hash bound; stale data is deployment risk not auth bypass.",
        "invariants": ["auth_gate"],
        "vulnerabilities": ["Unbound oracle input", "Stale price acceptance", "Single oracle without quorum"],
        "checklist": ["oracle input lockingBytecode", "trust_assumption judge check", "minPrice bounds"],
        "gaps": "**Detector coverage none**; reasoning partial",
        "refs": "bench_oracle_*, ORACLE_PRICE adversarial",
    },
    "dao_treasury": {
        "purpose": "Composite multisig + timelock treasury for DAO funds.",
        "security_model": "Large withdrawals need threshold + delay; emergency paths narrowly scoped.",
        "invariants": ["auth_gate"],
        "vulnerabilities": ["Timelock bypass on emergency", "Threshold downgrade", "Hybrid migration break"],
        "checklist": ["multisig + timelock composition", "separate roles per function", "token continuity on migration"],
        "gaps": "No composite detector; untested reasoning",
        "refs": "bench_dao_treasury_*",
    },
    "cashtokens_ft": {
        "purpose": "Fungible token transfer, mint, burn with category 0x00/FT rules.",
        "security_model": "Category preserved; amounts conserved; mint paths capped and auth-gated.",
        "invariants": ["token_category_preservation", "value_conservation", "auth_gate"],
        "vulnerabilities": ["category_drift", "amount_inflation", "unbounded_mint", "unintended burn"],
        "checklist": ["token_category_drift", "token_amount_inflation", "unbounded_mint", "token pair validation"],
        "gaps": "Mint vs transfer mode routing",
        "refs": "ct_ft_*, ct_invalid_* fixtures",
    },
    "cashtokens_nft": {
        "purpose": "Immutable (0x00+commitment), mutable (0x01), minting (0x02) NFT flows.",
        "security_model": "Capability category correct; mint authority covenant-bound; commitment preserved on immutable.",
        "invariants": ["token_category_preservation", "auth_gate"],
        "vulnerabilities": ["authority_leak", "commitment loss", "mutable without re-anchor", "unrestricted transfer"],
        "checklist": ["authority_leak", "nft_commitment_loss", "mutable_capability_leak", "capability_unrestricted_nft_transfer"],
        "gaps": "Soulbound intent vs detector",
        "refs": "ct_nft_*, ct_mint_*, detector fixtures",
    },
    "hybrid_contracts": {
        "purpose": "FT+NFT sidecar, stablecoin minter, hybrid migration between categories.",
        "security_model": "Migration preserves category rules; sidecar cannot drain main vault; hybrid continuity.",
        "invariants": ["token_category_preservation", "auth_gate"],
        "vulnerabilities": ["hybrid_continuity_break", "sidecar escape", "migration mismatch"],
        "checklist": ["hybrid_continuity_break", "capability_hybrid_migration_mismatch", "sidecar auth"],
        "gaps": "semantic_005/008 flaky in generation benchmarks",
        "refs": "ct_hybrid_*, stablecoin_minter_sidecar golden",
    },
}

TEMPLATE = """# {title}

## Pattern Purpose

{purpose}

## Security Model

{security_model}

## Required Invariants

| Invariant ID | Tier | Must hold |
|--------------|------|-----------|
{invariant_rows}

## Common Vulnerabilities

{vuln_bullets}

## Audit Checklist

{check_bullets}

## Known NexOps Gaps

{gaps}

See [`coverage_gap_analysis.md`](../coverage_gap_analysis.md).

## Reference Contracts

{refs}

## Related Knowledge

- Generation rules: `src/services/knowledge_structured/{yaml_hint}`
- Benchmark entries: [`benchmark_registry.json`](../benchmark_registry.json)
"""


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    yaml_map = {
        "payroll": "split_rules.yaml",
        "escrow": "escrow_rules.yaml",
        "vault": "vault_rules.yaml",
        "timelock": "timelock_rules.yaml",
        "hashlock": "hashlock_rules.yaml",
        "multisig": "multisig_rules.yaml",
        "split_payment": "split_rules.yaml",
        "subscription": "decay_rules.yaml",
        "refundable_payment": "refundable_payment_rules.yaml",
        "conditional_spend": "conditional_spend_rules.yaml",
        "covenant": "covenant_rules.yaml",
        "oracle": "(none — derive from adversarial fixtures)",
        "dao_treasury": "(composite — multisig + vault rules)",
        "cashtokens_ft": "ft_transfer_rules.yaml",
        "cashtokens_nft": "nft_rules.yaml",
        "hybrid_contracts": "hybrid_token_rules.yaml",
    }
    for key, data in PATTERNS.items():
        inv_rows = "\n".join(
            f"| `{i}` | security/business | ENFORCED on spend |" for i in data["invariants"]
        )
        content = TEMPLATE.format(
            title=key.replace("_", " ").title(),
            purpose=data["purpose"],
            security_model=data["security_model"],
            invariant_rows=inv_rows,
            vuln_bullets="\n".join(f"- {v}" for v in data["vulnerabilities"]),
            check_bullets="\n".join(f"- [ ] {c}" for c in data["checklist"]),
            gaps=data["gaps"],
            refs=data["refs"],
            yaml_hint=yaml_map.get(key, "core_language.yaml"),
        )
        (OUT / f"{key}.md").write_text(content, encoding="utf-8")
    readme = """# NexOps Security Pattern Knowledge Base

Canonical audit references per BCH contract family. Extends (does not replace) `src/services/knowledge_structured/` generation YAML.

| Document | Family |
|----------|--------|
"""
    readme += "\n".join(f"| [{k}.md]({k}.md) | {k} |" for k in PATTERNS)
    (OUT / "README.md").write_text(readme, encoding="utf-8")
    print(f"Wrote {len(PATTERNS)} pattern docs to {OUT}")


if __name__ == "__main__":
    main()
