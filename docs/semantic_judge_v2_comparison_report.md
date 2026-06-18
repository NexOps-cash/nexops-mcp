# Semantic Judge V2 Comparison Report

Generated: 2026-06-17 13:28 UTC

## Summary

| Metric | Value |
|--------|-------|
| Scenarios | 22 |
| False positive eliminations (VULNERABILITY removed) | 3 |
| V2 payloads with contradicts_fact_ids | 0 |
| V2 payloads with uncertainty fields | 4 |

## Per-scenario diff

| ID | Suite | Status | Legacy PASS | V2 PASS | Findings added | Findings removed | Kind/severity changes |
|----|-------|--------|-------------|---------|----------------|------------------|----------------------|
| payroll_a | Payroll | OK | True | True | 0 | 0 | — |
| payroll_b | Payroll | OK | True | True | 0 | 0 | — |
| payroll_c | Payroll | REVIEW | False | True | 1 | 1 | — |
| payroll_d | Payroll | OK | True | True | 0 | 0 | — |
| escrow_a | Escrow | OK | True | True | 0 | 0 | — |
| escrow_b | Escrow | OK | True | True | 0 | 0 | — |
| multisig_a | Multisig | OK | True | True | 0 | 0 | — |
| multisig_b | Multisig | OK | True | True | 0 | 0 | — |
| vault_a | Vault | OK | True | True | 0 | 0 | — |
| vault_b | Vault | OK | True | True | 0 | 0 | — |
| split_a | Split Payment | OK | True | True | 0 | 0 | — |
| split_b | Split Payment | OK | True | True | 0 | 0 | — |
| token_a | CashToken | OK | True | True | 0 | 0 | — |
| token_b | CashToken | OK | True | True | 0 | 0 | — |
| design_exact_equality | Design Trade-Off | OK | True | True | 0 | 0 | — |
| design_no_change | Design Trade-Off | OK | True | True | 0 | 0 | — |
| confidence_deterministic | Confidence | OK | True | True | 0 | 0 | — |
| confidence_llm_only | Confidence | OK | True | True | 1 | 1 | — |
| trigger_attacker_payout | Triggerability | OK | True | True | 0 | 0 | — |
| trigger_non_attacker_treasury | Triggerability | REVIEW | False | True | 1 | 1 | — |
| trigger_non_attacker_dust | Triggerability | OK | True | True | 0 | 0 | — |
| trigger_unknown_capped | Triggerability | OK | True | True | 0 | 0 | — |
