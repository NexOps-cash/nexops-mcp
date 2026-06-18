# Hybrid Contracts

## Pattern Purpose

FT+NFT sidecar, stablecoin minter, hybrid migration between categories.

## Security Model

Migration preserves category rules; sidecar cannot drain main vault; hybrid continuity.

## Required Invariants

| Invariant ID | Tier | Must hold |
|--------------|------|-----------|
| `token_category_preservation` | security/business | ENFORCED on spend |
| `auth_gate` | security/business | ENFORCED on spend |

## Common Vulnerabilities

- hybrid_continuity_break
- sidecar escape
- migration mismatch

## Audit Checklist

- [ ] hybrid_continuity_break
- [ ] capability_hybrid_migration_mismatch
- [ ] sidecar auth

## Known NexOps Gaps

semantic_005/008 flaky in generation benchmarks

See [`coverage_gap_analysis.md`](../coverage_gap_analysis.md).

## Reference Contracts

ct_hybrid_*, stablecoin_minter_sidecar golden

## Related Knowledge

- Generation rules: `src/services/knowledge_structured/hybrid_token_rules.yaml`
- Benchmark entries: [`benchmark_registry.json`](../benchmark_registry.json)
