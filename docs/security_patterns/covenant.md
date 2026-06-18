# Covenant

## Pattern Purpose

Stateful UTXO chain with lockingBytecode continuation and optional token state.

## Security Model

Every spend recreates covenant or allowed exit; token category/amount/commitment preserved per rules.

## Required Invariants

| Invariant ID | Tier | Must hold |
|--------------|------|-----------|
| `value_conservation` | security/business | ENFORCED on spend |
| `token_category_preservation` | security/business | ENFORCED on spend |

## Common Vulnerabilities

- Continuation break
- State fork
- Premature exit
- Mint authority escape

## Audit Checklist

- [ ] vulnerable_covenant detector
- [ ] lockingBytecode == activeBytecode
- [ ] capability detectors

## Known NexOps Gaps

Complex state machines weakly covered semantically

See [`coverage_gap_analysis.md`](../coverage_gap_analysis.md).

## Reference Contracts

cov_001-003, stateful_suite

## Related Knowledge

- Generation rules: `src/services/knowledge_structured/covenant_rules.yaml`
- Benchmark entries: [`benchmark_registry.json`](../benchmark_registry.json)
