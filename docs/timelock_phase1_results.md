# Timelock Phase 1 — Validation Results

**Date:** 2026-06-11  
**Scope:** Audit and 4-case benchmark only — no fixes implemented.  
**Audit:** [`timelock_state_report.md`](timelock_state_report.md), [`timelock_layer_diagnosis.md`](timelock_layer_diagnosis.md)  
**Tool:** `scripts/diagnose_timelock_case.py`

---

## Executive summary

### **TIMELOCK MOSTLY CONVERGED**

Timelock follows the **Escrow/Multisig measurement pattern**, not the Split generation pattern.

| Evidence | Finding |
|----------|---------|
| 4-case validation | **100% compile**, **75% convergence**, **0.917 avg score** |
| Composite paths | escrow refund + multisig backup → **1.0** |
| Pure timelock gap | **`timestamp_based` unmapped** on `tl_002` (evaluator only) |
| Historical full suite | **100% compile**, avg score **0.093** — evaluator false positives |
| Rails | No dedicated rail — **not blocking** |
| Generation | CLTV, CSV (`this.age`), multi-path timelock all compile |

---

## Metrics (4-case validation)

| Case | ID | Suite | Compile | Converged | Intent cov | Score | First failure |
|------|-----|-------|---------|-----------|------------|-------|---------------|
| A — Simple release | tl_001 | timelock.yaml | pass | yes | 1.0 | **1.0** | — |
| B — Absolute timeout | tl_002 | timelock.yaml | pass | no | 0.667 | 0.667 | **Evaluator** |
| C — Refund path | escrow_timeout_refund | escrow_suite.yaml | pass | yes | 1.0 | **1.0** | — |
| D — + multisig | ms_006 | multisig.yaml | pass | yes | 1.0 | **1.0** | — |

| Metric | Value |
|--------|-------|
| **Compile rate** | **100%** (4/4) |
| **Convergence rate** | **75%** (3/4) |
| **Avg intent coverage** | **0.917** |
| **Avg final score** | **0.917** |
| Avg retries | 1.0 |

**Runs:** `bench_20260611_1609_1d83`, `bench_20260611_1609_f76d`, `bench_20260611_1609_ec8e`

---

## Before / after context

| Cohort | Run | Compile | Converged | Avg score |
|--------|-----|---------|-----------|-----------|
| Full suite (historical) | `bench_20260331_2116_af18` | 100% | 100%* | **0.093** |
| tl_001 only (historical) | same | pass | yes | 0.10 |
| tl_001 (validation) | `bench_20260611_1609_1d83` | pass | yes | **1.0** |
| 4-case validation | 2026-06-11 | 100% | 75% | **0.917** |

\*Historical convergence gate passed despite low intent coverage.

### Per-case historical → validation (timelock.yaml cases)

| Case | Historical score | Validation score | Δ | Notes |
|------|------------------|------------------|---|-------|
| tl_001 | 0.10 | **1.0** | +0.90 | Model now emits `checkSig`; was unsigned covenant |
| tl_002 | 0.133 | 0.667 | +0.53 | Still missing `timestamp_based` mapping |

---

## Root cause classification

| Class | Cases | Verdict |
|-------|-------|---------|
| **Routing** | 0 | Profile and `contract_type: timelock` correct |
| **Rails** | 0 | No rail; not a compile blocker |
| **Sanity** | 0 | No failures |
| **Lint** | 0 | LNC-008/003 skipped for timelock mode |
| **Compile** | 0 | 4/4 pass |
| **Evaluator** | tl_002 (+ historical tl_001–005) | Unmapped `timestamp_based`, `block_height_based`, `relative_timelock`, `must_fail_wrong_time_field` |
| **Generation** | 0 on validation | `tl_005` historical unsigned spend — optional sig vs suite requirement |

**Confirmation:** Remaining validation failure (`tl_002`) is **evaluator-only**. Not routing, rails, sanity, lint, or compile.

---

## Full suite risks (not re-run)

| Case | Risk | Layer |
|------|------|-------|
| tl_003 | `block_height_based` unmapped | Evaluator |
| tl_004 | `must_fail_wrong_time_field` unwired | Evaluator |
| tl_005 | `relative_timelock`, `sequence_check` unmapped | Evaluator |

No evidence of Split-style structural compile failure on timelock suite.

---

## Recommendation

### **2. Small timelock Phase 1A (measurement alignment only)**

Mirror Escrow/Multisig 1A:

1. Map `timestamp_based`, `block_height_based`, `relative_timelock`, `sequence_check` in evaluator / feature_rules
2. Wire `must_fail_wrong_time_field` for `tl_004`
3. Align `tl_001` required features with intent (optional sig vs `owner_signature`)
4. Rerun `timelock.yaml` (5 cases) — expect ≥85% convergence if mappings correct

**Do not start Timelock Phase 1B** (rails/golden) — no generation failure on validation evidence.

**Do not mark timelock complete** and move to hashlock until Phase 1A gate passes on full `timelock.yaml`.

---

## Reproduce

```bash
python scripts/diagnose_timelock_case.py all
python -m benchmark.runner benchmark/suites/timelock.yaml --ids tl_001,tl_002
python -m benchmark.runner benchmark/suites/escrow_suite.yaml --ids escrow_timeout_refund
python -m benchmark.runner benchmark/suites/multisig.yaml --ids ms_006
```
