# Conditional Spend

## Pattern Purpose

Atomic swap or conditional release (hashlock + timelock combos).

## Security Model

Both sides' conditions enforced in same tx or linked covenant chain.

## Required Invariants

| Invariant ID | Tier | Must hold |
|--------------|------|-----------|
| `auth_gate` | security/business | ENFORCED on spend |
| `value_conservation` | security/business | ENFORCED on spend |

## Common Vulnerabilities

- One-sided enforcement
- Oracle/truth external to covenant
- Wrong input index for counterparty

## Audit Checklist

- [ ] input_output_coupling
- [ ] hash + timelock combo
- [ ] output binding

## Known NexOps Gaps

Phase1 routing issues documented in conditional_spend_phase1b_rca

See [`coverage_gap_analysis.md`](../coverage_gap_analysis.md).

## Reference Contracts

cs_001-005 migration

## Related Knowledge

- Generation rules: `src/services/knowledge_structured/conditional_spend_rules.yaml`
- Benchmark entries: [`benchmark_registry.json`](../benchmark_registry.json)
