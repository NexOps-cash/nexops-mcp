# Oracle

## Pattern Purpose

Spend gated on external price or data feed UTXO.

## Security Model

Oracle UTXO script hash bound; stale data is deployment risk not auth bypass.

## Required Invariants

| Invariant ID | Tier | Must hold |
|--------------|------|-----------|
| `auth_gate` | security/business | ENFORCED on spend |

## Common Vulnerabilities

- Unbound oracle input
- Stale price acceptance
- Single oracle without quorum

## Audit Checklist

- [ ] oracle input lockingBytecode
- [ ] trust_assumption judge check
- [ ] minPrice bounds

## Known NexOps Gaps

**Detector coverage none**; reasoning partial

See [`coverage_gap_analysis.md`](../coverage_gap_analysis.md).

## Reference Contracts

bench_oracle_*, ORACLE_PRICE adversarial

## Related Knowledge

- Generation rules: `src/services/knowledge_structured/(none — derive from adversarial fixtures)`
- Benchmark entries: [`benchmark_registry.json`](../benchmark_registry.json)
