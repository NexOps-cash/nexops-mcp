# Subscription

## Pattern Purpose

Streaming or decay schedules (vesting, Dutch auction, linear unlock).

## Security Model

Claimable amount monotonic with time; cancel/auth paths separated; no double-claim.

## Required Invariants

| Invariant ID | Tier | Must hold |
|--------------|------|-----------|
| `auth_gate` | security/business | ENFORCED on spend |
| `value_conservation` | security/business | ENFORCED on spend |

## Common Vulnerabilities

- Time arithmetic overflow
- Claim without decay update
- Cancel bypasses vesting

## Audit Checklist

- [ ] tx.time progression
- [ ] state commitment update
- [ ] covenant continuation

## Known NexOps Gaps

No decay-specific audit matrix

See [`coverage_gap_analysis.md`](../coverage_gap_analysis.md).

## Reference Contracts

dec_001-003, vesting_* migration

## Related Knowledge

- Generation rules: `src/services/knowledge_structured/decay_rules.yaml`
- Benchmark entries: [`benchmark_registry.json`](../benchmark_registry.json)
