# Timelock

## Pattern Purpose

Enforce minimum block time before spend or refund.

## Security Model

tx.time >= deadline on delayed paths; early spend impossible.

## Required Invariants

| Invariant ID | Tier | Must hold |
|--------------|------|-----------|
| `auth_gate` | security/business | ENFORCED on spend |

## Common Vulnerabilities

- tx.time > instead of >=
- Wrong comparison operator
- Timelock on wrong branch

## Audit Checklist

- [ ] time_validation_error lint
- [ ] paired auth on spend after lock
- [ ] refund path timing

## Known NexOps Gaps

No dedicated timelock invariant ID

See [`coverage_gap_analysis.md`](../coverage_gap_analysis.md).

## Reference Contracts

tl_001-005 migration

## Related Knowledge

- Generation rules: `src/services/knowledge_structured/timelock_rules.yaml`
- Benchmark entries: [`benchmark_registry.json`](../benchmark_registry.json)
