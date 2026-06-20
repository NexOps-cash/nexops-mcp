# Split Payment

## Pattern Purpose

Split single input across N outputs (revenue share, treasury distribution).

## Security Model

Recipients bound; sums conserved; optional fixed per-recipient amounts.

## Required Invariants

| Invariant ID | Tier | Must hold |
|--------------|------|-----------|
| `recipient_binding` | security/business | ENFORCED on spend |
| `value_conservation` | security/business | ENFORCED on spend |
| `fixed_amount_per_recipient` | security/business | ENFORCED on spend |
| `token_category_preservation` | security/business | ENFORCED on spend |

## Common Vulnerabilities

- Unbound recipient
- Partial sum
- Category drift on token split

## Audit Checklist

- [ ] output_binding_missing
- [ ] split conservation helpers
- [ ] intent invariants

## Known NexOps Gaps

Proportional vs fixed amount detection heuristic

See [`coverage_gap_analysis.md`](../coverage_gap_analysis.md).

## Reference Contracts

sp_001-010, split_a/b

## Related Knowledge

- Generation rules: `src/services/knowledge_structured/split_rules.yaml`
- Benchmark entries: [`benchmark_registry.json`](../benchmark_registry.json)
