# Vault

## Pattern Purpose

Custody with delayed withdrawal, cancellation, or role-separated emergency paths.

## Security Model

Withdrawals require auth + timelock where declared; emergency paths cannot bypass stronger invariants.

## Required Invariants

| Invariant ID | Tier | Must hold |
|--------------|------|-----------|
| `auth_gate` | security/business | ENFORCED on spend |

## Common Vulnerabilities

- Missing timelock on intent
- Emergency path without delay
- Index OOB on staged inputs

## Audit Checklist

- [ ] tx.time guards on delayed paths
- [ ] checkSig on all spend functions
- [ ] output count bounds
- [ ] covenant continuation if stateful

## Known NexOps Gaps

Intent timelock heuristic via SanityChecker only

See [`coverage_gap_analysis.md`](../coverage_gap_analysis.md).

## Reference Contracts

v_001-008, vault_a/b classification

## Related Knowledge

- Generation rules: `src/services/knowledge_structured/vault_rules.yaml`
- Benchmark entries: [`benchmark_registry.json`](../benchmark_registry.json)
