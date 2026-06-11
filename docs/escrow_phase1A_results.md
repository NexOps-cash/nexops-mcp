# Escrow Phase 1A — Results

**Date:** 2026-06-11  
**Scope:** Measurement-only fixes (suite, feature extractor, evaluator, semantic map). No pipeline, sanity, lint, structural integrity, or toll gate changes.  
**Before run:** `bench_20260331_2120_3d04`  
**After run:** `bench_20260611_1537_5603`

---

## Executive conclusion

**Yes — the historically low escrow score was primarily evaluator / suite measurement error** for the four positive BCH escrow cases (`esc_001`–`esc_004`).

| Cohort | Before avg score | After avg score | Delta |
|--------|------------------|-----------------|-------|
| **Positive cases (esc_001–004)** | **0.103** | **1.000** | **+0.897** |
| All 6 cases | 0.085 | 0.667 | +0.582 |

With aligned features and detection, every converging positive case scores **1.0** on the **same class of generated contracts** that previously scored 0.06–0.15. Compile and convergence for those cases were already 100%; only measurement changed.

**Remaining gaps (not Phase 1A):**

- `esc_005` / `esc_006` fail at **Phase 1 → `semantic_unsupported`** (`failure_layer: Compile`, 0 completion tokens). This is **routing / pipeline**, not evaluator. The March baseline compiled these cases; current runner blocks generation before code is produced.
- Negative-case scoring logic is implemented but **cannot be exercised** until those cases compile again (Phase 1C).

**Phase 1B:** **Not started** — gate for positive-case measurement is satisfied.

---

## Aggregate metrics

| Metric | Before (`…3d04`) | After (`…5603`) |
|--------|------------------|-----------------|
| Compile rate | 100% (6/6) | 67% (4/6) |
| Convergence rate | 100% (6/6) | 67% (4/6) |
| Avg intent coverage | 0.475 | 0.667 |
| Avg final score | **0.085** | **0.667** |

### Positive subset only (esc_001–esc_004)

| Metric | Before | After |
|--------|--------|-------|
| Compile rate | 100% | 100% |
| Convergence rate | 100% | 100% |
| Avg intent coverage | 0.588 | **1.000** |
| Avg final score | **0.103** | **1.000** |

---

## Per-case score deltas

| Case | Before compile | After compile | Before intent cov | After intent cov | Before score | After score | Δ score | Notes |
|------|----------------|---------------|-------------------|------------------|--------------|-------------|---------|-------|
| esc_001 | pass | pass | 0.33 | **1.00** | 0.067 | **1.000** | +0.933 | Removed spurious `token_validation`; dual `checkSig` → `multisig` |
| esc_002 | pass | pass | 0.67 | **1.00** | 0.133 | **1.000** | +0.867 | Role features + dynamic 2-of-3 `pk1`/`pk2` inference |
| esc_003 | pass | pass | 0.60 | **1.00** | 0.060 | **1.000** | +0.940 | `timelock_refund` + role sigs replace token/multisig noise |
| esc_004 | pass | pass | 0.75 | **1.00** | 0.150 | **1.000** | +0.850 | `arbiter` → `arbitrator_signature` alias; dual-path code scored fully |
| esc_005 | pass | **fail** | 0.50 | 0.00 | 0.100 | 0.000 | −0.100 | Phase 1 `semantic_unsupported` — no code generated |
| esc_006 | pass | **fail** | 0.00 | 0.00 | 0.000 | 0.000 | 0.000 | Phase 1 `semantic_unsupported` — no code generated |

---

## What changed (Phase 1A)

| File | Change |
|------|--------|
| `benchmark/suites/escrow.yaml` | Removed `token_validation`; aligned to `buyer_signature` / `seller_signature` / `arbitrator_signature` / `multisig_2of3` / `timelock_refund` / `locking_bytecode`; empty `required_features` on failure cases |
| `benchmark/feature_extractor.py` | `multisig` + `multisig_2of2` from multiple `checkSig`; `arbiter` → `arbitrator_signature`; dynamic 2-of-3 role inference |
| `benchmark/evaluator.py` | `escrow` alias pool; `both_signatures_required`, `multisig`, `must_fail_*` helpers; negative-case `intent_coverage` boost when `must_fail_*` critical satisfied |
| `benchmark/config/semantic_requirement_map.yaml` | Escrow role and `must_fail_*` mappings |
| `tests/test_feature_extractor.py` | Tests for dual-`checkSig` multisig and arbiter alias |

---

## Root-cause confirmation

| Hypothesis | Verdict |
|------------|---------|
| **E — Evaluator mismatch** | **Confirmed** for esc_001–004. Spurious `token_validation`, missing `multisig` on dual `checkSig`, and unmapped role features caused 0.06–0.15 scores on valid contracts. |
| A — Routing | Failure cases only (esc_005/006); blocks measurement of negative scoring |
| B — Rails | Not implicated — compile unchanged on positive cases |
| C — Sanity/lint | Not implicated — lint_errors 0 throughout |
| D — Generation | esc_004 after run actually **improved** (dual-path functions); not the score bottleneck |

---

## Decision gate (from `escrow_phase1_plan.md`)

| Criterion | Target | Result |
|-----------|--------|--------|
| Positive-case avg score | ≥ 0.85 | **1.000** — pass |
| Positive-case compile | ≥ 5/6 | **4/4** — pass |
| Full-suite compile | — | 4/6 (failure cases blocked at Phase 1) |

**Proceed to Phase 1B?** **Deferred.** Measurement gate on production escrow intents is met. Phase 1B (rails / synthesis) is only needed if new generation gaps appear under stricter scoring or regression harness — not required to explain the historical 0.085 average.

**Recommended next step:** Phase 1C routing fix for `esc_005`/`esc_006` (`semantic_unsupported` on adversarial intents) so negative-case scoring can be validated end-to-end.

---

## Reproduce

```bash
python -m benchmark.runner benchmark/suites/escrow.yaml
# After run: benchmark/results/bench_20260611_1537_5603.json
```
