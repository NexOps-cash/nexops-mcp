# Composition Readiness Scorecard

**Sprint:** Phase 2 Composition Research  
**Branch:** `research/composition-sprint-v2`  
**Date:** 2026-06-18  
**Purpose:** Per-pattern readiness summary that **feeds** [`composition_matrix.md`](composition_matrix.md).

---

## Scoring Methodology

| Column | Source | Label |
|--------|--------|-------|
| **Gen %** | Latest dedicated-suite convergence from [`statusjune.md`](../statusjune.md) §4 | MEASURED |
| **Audit %** | `security_patterns/` doc + executable registry + detector coverage from [`coverage_gap_analysis.md`](coverage_gap_analysis.md) | MEASURED / INFERRED |
| **Benchmarks %** | Generation YAML suite + audit registry materialization | MEASURED |
| **Composite Ready** | Derived: `Yes` only if Gen ≥85%, Audit ≥85%, no known composition-blocking failure | INFERRED |

**Composition-blocking failures (MEASURED):**
- `coverage_stability_results.json`: `A_split_multisig` FAILED compile
- `statusjune.md`: split_payment latest conv **50%** (RED)
- `hashlock_layer_diagnosis.md`: routes to `conditional_spend`; rules injection partial
- `refundable_generation_rca.md`: subscription/vesting compile failures

---

## Executive Scorecard

| Pattern | Gen | Audit | Benchmarks | Composite Ready | Evidence |
|---------|-----|-------|------------|-----------------|----------|
| **Split Payment** | 50% | 88% | 72% | **No** | MEASURED conv; payroll audit fixtures exist |
| **Escrow** | 100%† | 92% | 95% | **Yes** | MEASURED bench; †regression conflict |
| **Multisig** | 100% | 90% | 88% | **Yes** | MEASURED GREEN |
| **Timelock** | 100% | 75% | 70% | **Almost** | MEASURED compile; evaluator gaps |
| **Hashlock** | 80% | 55% | 65% | **Almost** | MEASURED; no hashlock detector |
| **Vault** | 67% | 85% | 90% | **Almost** | MEASURED vaults_real; evaluator FN |
| **Refundable Payment** | 67% | 82% | 68% | **No** | MEASURED; routing + compile RCA |
| **Subscription** | 25% | 40% | 35% | **No** | INFERRED; refundable variant only |
| **Conditional Spend** | 60% | 70% | 62% | **Partial** | MEASURED suite |
| **Covenant** | 100%‡ | 72% | 55% | **Partial** | ‡compile; intent 0.22 |
| **CashTokens FT** | 95% | 95% | 92% | **Yes** | MEASURED Wave 2 gates |
| **CashTokens NFT** | 90% | 92% | 88% | **Yes** | MEASURED family benchmarks |

---

## Per-Pattern Detail

### Split Payment — Composite Ready: **No**

| Dimension | Score | Notes | Label |
|-----------|-------|-------|-------|
| Gen | 50% | `bench_20260331_2125_2cb6`: 3/6 converged | MEASURED |
| Audit | 88% | [`payroll.md`](security_patterns/payroll.md); 4 executable payroll benches | MEASURED |
| Benchmarks | 72% | 6 YAML cases; registry migration stubs; no composite gen bench | INFERRED |
| Blocker | N-output conservation hardcoded for 2 outputs | [`split_payment_state_report.md`](split_payment_state_report.md) | MEASURED |

### Escrow — Composite Ready: **Yes**

| Dimension | Score | Notes | Label |
|-----------|-------|-------|-------|
| Gen | 100% | `bench_20260331_2120_3d04`: 6/6 | MEASURED |
| Audit | 92% | 6 escrow fixtures; 2-of-3, timeout, dispute | MEASURED |
| Benchmarks | 95% | 16 YAML + registry entries | MEASURED |
| Caveat | `regression_results.json` escrow FAILED | Different harness | MEASURED |

### Multisig — Composite Ready: **Yes**

| Dimension | Score | Notes | Label |
|-----------|-------|-------|-------|
| Gen | 100% | `bench_20260331_2118_ff90`: 6/6 | MEASURED |
| Audit | 90% | Distinctness detectors; spurious token_validation on BCH-only | MEASURED |
| Benchmarks | 88% | 6 YAML cases | MEASURED |

### Timelock — Composite Ready: **Almost**

| Dimension | Score | Notes | Label |
|-----------|-------|-------|-------|
| Gen | 100% | Latest compile 100% | MEASURED |
| Audit | 75% | `time_validation_error` partial; no timelock rail | INFERRED |
| Benchmarks | 70% | 5 YAML; no executable timelock-only fixture | INFERRED |
| Gap | Evaluator `timestamp_based` mapping | [`timelock_layer_diagnosis.md`](timelock_layer_diagnosis.md) | MEASURED |

### Hashlock — Composite Ready: **Almost**

| Dimension | Score | Notes | Label |
|-----------|-------|-------|-------|
| Gen | 80% | Latest 4/5 compile | MEASURED |
| Audit | 55% | 3 fixtures; **no** hashlock detector | MEASURED |
| Benchmarks | 65% | 5 YAML; HTLC in refundable fixture | MEASURED |
| Gap | Routes to `swap`→`conditional_spend` | [`hashlock_layer_diagnosis.md`](hashlock_layer_diagnosis.md) | MEASURED |

### Vault — Composite Ready: **Almost**

| Dimension | Score | Notes | Label |
|-----------|-------|-------|-------|
| Gen | 67% | `vaults_real` 16/24 conv | MEASURED |
| Audit | 85% | Vault pattern doc; staged spending helpers | INFERRED |
| Benchmarks | 90% | 34 cases across suites | MEASURED |
| Gap | Evaluator false negatives; timeouts vr_010/vr_023 | [`vault_layer_diagnosis.md`](vault_layer_diagnosis.md) | MEASURED |

### Refundable Payment — Composite Ready: **No**

| Dimension | Score | Notes | Label |
|-----------|-------|-------|-------|
| Gen | 67% | Latest 4/6 | MEASURED |
| Audit | 82% | 4 refundable fixtures incl. HTLC, subscription | MEASURED |
| Benchmarks | 68% | 6 YAML; golden crowdfund | MEASURED |
| Gap | rp_003 subscription, rp_004 vesting compile fail | [`refundable_generation_rca.md`](refundable_generation_rca.md) | MEASURED |

### Subscription — Composite Ready: **No**

| Dimension | Score | Notes | Label |
|-----------|-------|-------|-------|
| Gen | 25% | Not first-class; `rp_003` variant only | INFERRED |
| Audit | 40% | [`subscription.md`](security_patterns/subscription.md) doc only | INFERRED |
| Benchmarks | 35% | `subscription_secure.cash` fixture; no gen suite | MEASURED |
| Gap | No Phase 1 routing to subscription profile | [`refundable_state_report.md`](refundable_state_report.md) | INFERRED |

### Conditional Spend — Composite Ready: **Partial**

| Dimension | Score | Notes | Label |
|-----------|-------|-------|-------|
| Gen | 60% | Latest 3/5 | MEASURED |
| Audit | 70% | 4 cs fixtures; multi-path secure | MEASURED |
| Benchmarks | 62% | 5 YAML; swap routing hijack cases | MEASURED |

### Covenant — Composite Ready: **Partial**

| Dimension | Score | Notes | Label |
|-----------|-------|-------|-------|
| Gen | 100% | Latest 3/3 compile | MEASURED |
| Audit | 72% | Continuation partial; state fork reasoning only | INFERRED |
| Benchmarks | 55% | 6 YAML; low intent 0.22 | MEASURED |

### CashTokens FT — Composite Ready: **Yes**

| Dimension | Score | Notes | Label |
|-----------|-------|-------|-------|
| Gen | 95% | Wave 2 family 100% conv | MEASURED |
| Audit | 95% | Full detector stack; 6+ executable | MEASURED |
| Benchmarks | 92% | 11 cashtokens YAML suites | MEASURED |

### CashTokens NFT — Composite Ready: **Yes**

| Dimension | Score | Notes | Label |
|-----------|-------|-------|-------|
| Gen | 90% | Minting 75%; immutable/mutable 100% | MEASURED |
| Audit | 92% | NFT fixtures; commitment loss detector | MEASURED |
| Benchmarks | 88% | NFT family suites | MEASURED |

---

## Composite-Ready Pattern Sets

**Ready for 2-pattern composition today (INFERRED):**
- Escrow + Multisig
- Escrow + Timelock
- Multisig + Timelock
- CashTokens FT + Escrow (golden `escrow_2of3_nft`)
- CashTokens NFT + Escrow

**Blocked — do not compose until pattern fixed:**
- Any composition requiring **Split** as primary distribution
- **Subscription** as recurring logic layer
- **Refundable** + complex vesting (rp_004)

**Almost — feasible with golden template, not free synthesis:**
- Vault + Timelock
- Vault + Multisig
- Hashlock + Timelock (HTLC)
- Vault + CashTokens NFT

---

## Outputs for Composition Matrix

| Pattern | Weight in matrix | Rationale |
|---------|------------------|-----------|
| Escrow, Multisig, FT, NFT | High | Composite Ready = Yes |
| Timelock, Hashlock, Vault, Covenant, Conditional Spend | Medium | Almost / Partial |
| Split, Refundable, Subscription | Low (blocking) | No — composition-blocked |

---

## Related Documents

- [`composition_matrix.md`](composition_matrix.md) — pairwise interactions
- [`pattern_maturity_heatmap.md`](pattern_maturity_heatmap.md) — dimensional expansion
- [`statusjune.md`](../statusjune.md) — generation convergence source
- [`coverage_gap_analysis.md`](coverage_gap_analysis.md) — audit gap source
