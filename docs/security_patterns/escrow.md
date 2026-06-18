# Escrow

## Pattern Purpose

Hold funds until release conditions (multi-party sig) or refund conditions (timeout) met.

## Security Model

Release requires all required signatures; refund only after timeout to original party; value conserved.

## Required Invariants

| Invariant ID | Tier | Must hold |
|--------------|------|-----------|
| `auth_gate` | security/business | ENFORCED on spend |
| `value_conservation` | security/business | ENFORCED on spend |

## Common Vulnerabilities

- Missing refund branch
- Timeout operator inverted
- Arbiter over-power
- Unbound release outputs

## Audit Checklist

- [ ] release branch multisig
- [ ] refund branch timelock + sender auth
- [ ] output binding on all paths
- [ ] no third path drain

## Known NexOps Gaps

EscrowRoleEnforcementDetector unregistered; external funding is deployment

See [`coverage_gap_analysis.md`](../coverage_gap_analysis.md).

## Reference Contracts

esc_001-006, escrow_a/b classification

## Related Knowledge

- Generation rules: `src/services/knowledge_structured/escrow_rules.yaml`
- Benchmark entries: [`benchmark_registry.json`](../benchmark_registry.json)
