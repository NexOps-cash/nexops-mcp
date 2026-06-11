# Timelock Phase 1A — Measurement Alignment Results

**Date:** 2026-06-11  
**Scope:** Evaluator and suite alignment only. No changes to `pipeline.py`, generation rails, toll gate, sanity checker, lint rules, or structured knowledge.  
**After run:** `bench_20260611_1632_0d72` (full 5-case suite)  
**Before baseline:** `bench_20260331_2116_af18` (March historical)  
**Phase 1 validation (pre-1A):** `bench_20260611_1609_*` (4-case, 0.917 avg)

---

## Executive conclusion

**Production timelock patterns are measurement-aligned.** All four positive intent classes (`tl_001`–`tl_003`, `tl_005`) score **1.0** with **100% compile and convergence** when evaluator detection is current (verified on latest runs).

**Full `timelock.yaml` gate is not met** because `tl_004` (adversarial failure case) **does not compile** — pipeline exhausts after toll-gate retries (0 completion tokens). This mirrors Multisig `ms_004`/`ms_005` and Escrow `esc_005`/`esc_006`: **not an evaluator gap**.

### Decision gate (full 5-case suite)

| Gate | Threshold | Full suite | Positive 4-case |
|------|-----------|------------|-----------------|
| Compile | ≥ 85% | **80%** (4/5) | **100%** (4/4) |
| Convergence | ≥ 85% | **80%** (4/5)* | **100%** (4/4) |
| Avg score | ≥ 0.85 | **0.80**† | **1.000** |

\*With final `block_height_based` detection, `tl_003` converges at 1.0 (`bench_20260611_1634_88a8`).  
†Adjusted from run `…0d72` raw 0.733: `tl_003` 0.667 → 1.0 after `lockBlocks` CSV detection.

**Classification:** **TIMELOCK PRODUCTION CONVERGED** (positive cases). **Full-suite gate: NOT MET.**

**Do not start Hashlock** until the full-suite gate passes or failure-case compile is explicitly scoped out (same policy as Multisig/Escrow).

---

## Aggregate metrics

| Metric | Before (`…af18` Mar) | Phase 1 validation | **After 1A (full suite)** | **Positive subset** |
|--------|----------------------|--------------------|-----------------------------|---------------------|
| Compile rate | 100% | 100% (4/4) | **80%** (4/5) | **100%** (4/4) |
| Convergence rate | 100%* | 75% | **80%** (4/5) | **100%** (4/4) |
| Avg intent coverage | 0.567 | 0.917 | **0.80** | **1.000** |
| Avg final score | **0.093** | 0.917 | **0.80** | **1.000** |

\*Historical convergence used a loose gate despite 0.05–0.13 intent scores.

---

## Per-case results (after 1A)

| Case | Compile | Converged | Intent cov | Score | First failure | Notes |
|------|---------|-----------|------------|-------|---------------|-------|
| tl_001 | pass | yes | 1.0 | **1.0** | — | Block-height CLTV; `signature_verification` removed from suite |
| tl_002 | pass | yes | 1.0 | **1.0** | — | `timestamp_based` wired; was 0.667 in Phase 1 |
| tl_003 | pass | yes | 1.0 | **1.0** | — | `block_height_based` for CLTV + `lockBlocks` CSV |
| tl_004 | **fail** | no | 0.0 | 0.0 | **Compile** | FAILURE CASE — toll gate + retry exhaustion |
| tl_005 | pass | yes | 1.0 | **1.0** | — | `relative_timelock` + `sequence_check`; was 0.0 historical |

### Score deltas (vs March baseline `…af18`)

| Case | Before score | After score | Δ | Layer |
|------|--------------|-------------|---|-------|
| tl_001 | 0.10 | **1.000** | +0.90 | Evaluator + suite (`block_height_based`, drop spurious sig) |
| tl_002 | 0.133 | **1.000** | +0.87 | Evaluator (`timestamp_based`) |
| tl_003 | 0.133 | **1.000** | +0.87 | Evaluator (`block_height_based` / `lockBlocks`) |
| tl_004 | 0.10 | 0.000 | −0.10 | **Compile** (generation cannot emit failing pattern) |
| tl_005 | 0.00 | **1.000** | +1.00 | Evaluator (`relative_timelock`, `sequence_check`) |

---

## First-failure analysis

| Case | First failure layer | Root cause |
|------|---------------------|------------|
| tl_001 | — | None |
| tl_002 | — | None |
| tl_003 | — | None |
| tl_004 | **Compile** | Pipeline exhausted (3 attempts); toll gate rejects invalid time-field patterns before compile |
| tl_005 | — | None |

**Evaluator-only blockers eliminated** for all compiling cases. Remaining full-suite gap is **generation/routing on adversarial failure intent**, not measurement.

---

## Changes implemented (Phase 1A only)

### `benchmark/config/feature_rules.yaml`

- Added regex features: `timestamp_based`, `block_height_based`, `relative_timelock`, `sequence_check`
- Extended `block_height_based` for `lockBlocks` / `unlockBlocks` CSV maturity

### `benchmark/evaluator.py`

- `_must_fail_wrong_time_field` — detects `tx.timestamp`, `block.timestamp`, `tx.locktime`
- `_timestamp_based_timelock`, `_block_height_based_timelock`, `_relative_timelock`, `_sequence_check`
- `timelock` alias pool wired into `_cashtoken_alias_pool`
- `timelock_semantic_relaxed` — vault TERMINAL/no-re-anchor rule must not penalize valid timelock covenants
- `locktime_check` critical feature uses `time_validation` capability path

### `benchmark/config/semantic_requirement_map.yaml`

- Mapped: `time_validation`, `timestamp_based`, `block_height_based`, `relative_timelock`, `sequence_check`, `must_fail_wrong_time_field`
- Fixed `locktime_check` (was incorrectly tied to `terminating_output`)

### `benchmark/suites/timelock.yaml`

- **tl_001:** Dropped `signature_verification` — intent is block-height CLTV only (“spent after block height 800000”); optional owner sig in generated code does not fail measurement
- **tl_004:** `required_features: []` — negative case scored via `must_fail_wrong_time_field` critical only (mirror escrow/multisig failure cases)
- **tl_005:** Dropped `signature_verification` — intent is relative block maturity, not auth model

---

## tl_001 intent review

| Question | Decision |
|----------|----------|
| Is `signature_verification` required? | **No** — intent specifies only block-height lock; no signer or spend authorization in the prompt |
| Suite alignment | `required_features: [time_validation, block_height_based]`; critical `locktime_check` |
| Generated code with `checkSig` | Still scores **1.0** — extra sig is not penalized as missing required feature |

---

## Recommendation

1. **Treat timelock as production-converged** for CLTV, timestamp CLTV, block-count savings, and relative CSV patterns.
2. **Do not start Hashlock** until full-suite gate ≥85% or `tl_004` compile is addressed under a separate security-negative benchmark track.
3. **Do not start Timelock Phase 1B** (rails/golden) — no generation failure on positive validation evidence.

---

## Reproduce

```bash
python -m benchmark.runner benchmark/suites/timelock.yaml
python -m benchmark.runner benchmark/suites/timelock.yaml --ids tl_001,tl_002,tl_003,tl_005
python scripts/diagnose_timelock_case.py all
```
