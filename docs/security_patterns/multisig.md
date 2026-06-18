# Multisig

## Pattern Purpose

M-of-N signature threshold before spend.

## Security Model

checkMultiSig with correct threshold; distinct pubkeys; no single-signer bypass.

## Required Invariants

| Invariant ID | Tier | Must hold |
|--------------|------|-----------|
| `auth_gate` | security/business | ENFORCED on spend |

## Common Vulnerabilities

- Threshold too low
- Pubkey reuse
- Duplicate signatures
- Bypass path without multisig

## Audit Checklist

- [ ] checkMultiSig threshold
- [ ] multisig_distinctness_flaw
- [ ] multisig_signature_reuse
- [ ] no parallel unsigned path

## Known NexOps Gaps

Intent sanity for declared M-of-N

See [`coverage_gap_analysis.md`](../coverage_gap_analysis.md).

## Reference Contracts

ms_001-006, multisig_a/b

## Related Knowledge

- Generation rules: `src/services/knowledge_structured/multisig_rules.yaml`
- Benchmark entries: [`benchmark_registry.json`](../benchmark_registry.json)
