# Refundable Payment

## Pattern Purpose

Crowdfund or subscription escrow with refund if conditions fail.

## Security Model

Refund path returns to funder; release path requires milestone auth; timeout refunds.

## Required Invariants

| Invariant ID | Tier | Must hold |
|--------------|------|-----------|
| `auth_gate` | security/business | ENFORCED on spend |
| `value_conservation` | security/business | ENFORCED on spend |

## Common Vulnerabilities

- Refund to wrong party
- Release without quorum
- Missing timeout refund

## Audit Checklist

- [ ] dual branch structure
- [ ] timelock on refund
- [ ] recipient binding on release

## Known NexOps Gaps

Zero audit classification coverage

See [`coverage_gap_analysis.md`](../coverage_gap_analysis.md).

## Reference Contracts

rp_001-006 migration

## Related Knowledge

- Generation rules: `src/services/knowledge_structured/refundable_payment_rules.yaml`
- Benchmark entries: [`benchmark_registry.json`](../benchmark_registry.json)
