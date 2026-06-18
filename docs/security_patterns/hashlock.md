# Hashlock

## Pattern Purpose

Spend requires SHA256 preimage reveal; enables atomic swaps.

## Security Model

Hashlock verified on spend path; preimage length checked; no spend without valid hash.

## Required Invariants

| Invariant ID | Tier | Must hold |
|--------------|------|-----------|
| `auth_gate` | security/business | ENFORCED on spend |

## Common Vulnerabilities

- Missing hash verify
- Preimage length not checked
- Hash on wrong path
- Replay across contracts

## Audit Checklist

- [ ] require(sha256(preimage) == hash)
- [ ] commitment_length_missing
- [ ] single-use enforcement via covenant

## Known NexOps Gaps

**P0: zero audit coverage**; no hashlock detector

See [`coverage_gap_analysis.md`](../coverage_gap_analysis.md).

## Reference Contracts

hl_001-005 migration

## Related Knowledge

- Generation rules: `src/services/knowledge_structured/hashlock_rules.yaml`
- Benchmark entries: [`benchmark_registry.json`](../benchmark_registry.json)
