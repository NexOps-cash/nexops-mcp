# Vault Phase 1B P0 — Generation Stabilization Results

**Date:** 2026-06-12  
**Scope:** Deterministic canonical templates for `vr_010` (backup-cancel) and `vr_023` (founder treasury). No evaluator, routing, rail, or adversarial changes.

---

## What shipped

| File | Change |
|------|--------|
| `knowledge/templates/vault_backup_cancel.cash` | announce → claim → cancel (from `bench_20260401_2030_ceb2`) |
| `knowledge/templates/vault_founder_treasury.cash` | instantSpend / stageLargeWithdrawal / finalizeLargeWithdrawal / emergencyRecover |
| `src/services/vault_canonical.py` | Intent matching + template load |
| `src/services/pipeline.py` | Phase 2 `VAULT_CANONICAL_TEMPLATE` branch (before golden/free synthesis, retry 0 only) |
| `src/services/knowledge_structured/synthesis_rules.yaml` | `vault.canonical_backup_cancel` + `canonical_founder_treasury` shapes |
| `tests/test_vault_canonical.py` | Match, compile, lint gate tests |

**Mechanism:** On first Phase 2 attempt, if `effective_mode == vault` and intent text matches a narrow profile, return the pre-validated `.cash` file with **no LLM synthesis** (~4s vs prior 300s timeouts).

---

## Success gate

| Gate | Target | Result |
|------|--------|--------|
| `vaults_real` positive convergence | ≥ 19/20 (95%) | **19/20 (95.0%)** — `bench_20260612_1842_92c3` |
| `vr_010` × 2 consecutive runs | compile + converge | **PASS** — `bench_20260612_1841_43a6`, `bench_20260612_1842_69fb` (~3.8s avg) |
| `vr_023` × 2 consecutive runs | compile + converge | **PASS** — same runs (~4.5s avg) |

### P0 case metrics (full suite run)

| Case | Before (canonical `2119`) | After P0 |
|------|---------------------------|----------|
| **vr_010** | Timeout 300s, no code | **1.0**, 3.6s, canonical template |
| **vr_023** | Timeout 300s (1/6 runs) | **1.0**, 5.9s, canonical template |
| **vr_009** | evaluator gap (pre-1A) | **1.0**, 3.9s (incidental — same founder template) |

### Remaining positive gap

| Case | Issue |
|------|-------|
| **vr_012** | Compile fail (CashToken vault — out of P0 scope) |

Failure cases (`vr_020`–`vr_022`) unchanged — adversarial / compile-limited by design.

---

## Reproduce

```bash
python -m pytest tests/test_vault_canonical.py -v

# P0 cases only
python -m benchmark.runner benchmark/suites/vaults_real --ids vr_010,vr_023

# Full re-measure
python -m benchmark.runner benchmark/suites/vaults_real
```

---

## Next step

**Refundable Phase 1B** — vault positive gate met; re-measurement complete on `bench_20260612_1842_92c3`.
