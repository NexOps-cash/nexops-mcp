# Cashtokens Ft

## Pattern Purpose

Fungible token transfer, mint, burn with category 0x00/FT rules.

## Security Model

Category preserved; amounts conserved; mint paths capped and auth-gated.

## Required Invariants

| Invariant ID | Tier | Must hold |
|--------------|------|-----------|
| `token_category_preservation` | security/business | ENFORCED on spend |
| `value_conservation` | security/business | ENFORCED on spend |
| `auth_gate` | security/business | ENFORCED on spend |

## Common Vulnerabilities

- category_drift
- amount_inflation
- unbounded_mint
- unintended burn

## Audit Checklist

- [ ] token_category_drift
- [ ] token_amount_inflation
- [ ] unbounded_mint
- [ ] token pair validation

## Known NexOps Gaps

Mint vs transfer mode routing

See [`coverage_gap_analysis.md`](../coverage_gap_analysis.md).

## Reference Contracts

ct_ft_*, ct_invalid_* fixtures

## Related Knowledge

- Generation rules: `src/services/knowledge_structured/ft_transfer_rules.yaml`
- Benchmark entries: [`benchmark_registry.json`](../benchmark_registry.json)
