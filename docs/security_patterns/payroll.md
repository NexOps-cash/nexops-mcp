# Payroll

## Pattern Purpose

Distribute fixed or bounded payments to predetermined recipients; owner or multisig authorizes each spend.

## Security Model

Only authorized parties can move funds; recipients and amounts match declared intent; token categories preserved on splits.

## Required Invariants

| Invariant ID | Tier | Must hold |
|--------------|------|-----------|
| `auth_gate` | security/business | ENFORCED on spend |
| `recipient_binding` | security/business | ENFORCED on spend |
| `fixed_amount_per_recipient` | security/business | ENFORCED on spend |
| `value_conservation` | security/business | ENFORCED on spend |
| `token_category_preservation` | security/business | ENFORCED on spend |

## Common Vulnerabilities

- Missing checkSig
- Unbound output lockingBytecode
- Salary sum mismatch
- Token category drift

## Audit Checklist

- [ ] verify checkSig on spend path
- [ ] require tx.outputs[N].lockingBytecode for each payee
- [ ] sum tokenAmounts == input
- [ ] tokenCategory tied to input

## Known NexOps Gaps

Proportional splits without literal fixed amounts; treasury prefunding is deployment not on-chain

See [`coverage_gap_analysis.md`](../coverage_gap_analysis.md).

## Reference Contracts

bench_payroll_001-004, payroll_a-d classification

## Related Knowledge

- Generation rules: `src/services/knowledge_structured/split_rules.yaml`
- Benchmark entries: [`benchmark_registry.json`](../benchmark_registry.json)
