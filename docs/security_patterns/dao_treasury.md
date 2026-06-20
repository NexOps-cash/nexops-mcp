# Dao Treasury

## Pattern Purpose

Composite multisig + timelock treasury for DAO funds.

## Security Model

Large withdrawals need threshold + delay; emergency paths narrowly scoped.

## Required Invariants

| Invariant ID | Tier | Must hold |
|--------------|------|-----------|
| `auth_gate` | security/business | ENFORCED on spend |

## Common Vulnerabilities

- Timelock bypass on emergency
- Threshold downgrade
- Hybrid migration break

## Audit Checklist

- [ ] multisig + timelock composition
- [ ] separate roles per function
- [ ] token continuity on migration

## Known NexOps Gaps

No composite detector; untested reasoning

See [`coverage_gap_analysis.md`](../coverage_gap_analysis.md).

## Reference Contracts

bench_dao_treasury_*

## Related Knowledge

- Generation rules: `src/services/knowledge_structured/(composite — multisig + vault rules)`
- Benchmark entries: [`benchmark_registry.json`](../benchmark_registry.json)
