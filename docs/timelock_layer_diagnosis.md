# Timelock — Layer Diagnosis

**Purpose:** First failure per pipeline layer for timelock validation cases.  
**Diagnostics:** `benchmark/results/timelock_diagnostics/<case_id>.json`  
**Tool:** `python scripts/diagnose_timelock_case.py [case_id|all]`  
**Benchmark:** `bench_20260611_1609_1d83`, `bench_20260611_1609_f76d`, `bench_20260611_1609_ec8e`  
**Historical:** `bench_20260331_2116_af18` (full 5-case)

---

## Layer definitions

| Layer | Pass criteria |
|-------|----------------|
| Phase 1 routing | `contract_type` + `features` parsed; profile appropriate |
| Rules loaded | `timelock_rules_loaded: true` (or escrow/multisig rules for composites) |
| Rails loaded | Informational — `[RAIL: TIMELOCK MODE]` does not exist |
| Sanity pass | No `Sanity Check failed (STRICT)` |
| Lint pass | No blocking LNC violations |
| Compile pass | `cashc` succeeds |
| Evaluator pass | `intent_coverage >= 0.70`, `converged: true` |

---

## Validation subset — 4 cases (2026-06-11)

| Case | Role | Routing | Rules | Rails | Sanity | Lint | Compile | Evaluator | First failure |
|------|------|---------|-------|-------|--------|------|---------|-----------|---------------|
| tl_001 | Simple CLTV release | pass | pass | n/a | pass | pass | pass | pass | — |
| tl_002 | Absolute timestamp | pass | pass | n/a | pass | pass | pass | **fail** | **Evaluator** (`timestamp_based`) |
| escrow_timeout_refund | Refund path | pass (escrow) | pass (escrow) | escrow | pass | pass | pass | pass | — |
| ms_006 | + multisig backup | pass (multisig) | pass (multisig) | escrow | pass | pass | pass | pass | — |

**Aggregate:** Compile **4/4**; first failure **evaluator only** on `tl_002`.

---

## Full `timelock.yaml` — historical (`bench_20260331_2116_af18`)

All cases: compile pass, lint pass, converged true. First failure = **Evaluator** for scoring quality.

| Case | Routing | Rules | Sanity | Lint | Compile | Evaluator | First failure | Missing features (historical) |
|------|---------|-------|--------|------|---------|-----------|---------------|------------------------------|
| tl_001 | pass | pass | pass | pass | pass | **fail** | **Evaluator** | `signature_verification` (no checkSig in code) |
| tl_002 | pass | pass | pass | pass | pass | **fail** | **Evaluator** | `timestamp_based` |
| tl_003 | pass | pass | pass | pass | pass | **fail** | **Evaluator** | `block_height_based` |
| tl_004 | pass | pass | pass | pass | pass | **fail** | **Evaluator** | `must_fail_wrong_time_field` not scored |
| tl_005 | pass | pass | pass | pass | pass | **fail** | **Evaluator** + partial gen | `relative_timelock`, `signature_verification`, `time_validation`* |

\*`tl_005` code has `this.age >= 144` but `time_validation` not credited — mapping gap; no `checkSig` in generated code.

---

## Routing diagnostics detail

| Case | contract_type | effective_mode | timelock_rules | escrow_rail |
|------|---------------|----------------|----------------|-------------|
| tl_001 | timelock | timelock | yes | no |
| tl_002 | timelock | timelock | yes | no |
| escrow_timeout_refund | escrow | escrow | no | yes |
| ms_006 | multisig | multisig | no | yes |

`timelock_rail_loaded` is **false** for all cases — no rail exists in codebase.

---

## Aggregated first-failure counts

| First failure | Validation 4-case | Historical 5-case |
|---------------|-------------------|-------------------|
| **Evaluator** | 1 (tl_002) | 5 |
| Generation | 0 | 0 (tl_005 unsigned is suite/evaluator mismatch) |
| Routing | 0 | 0 |
| Lint / Sanity / Compile | 0 | 0 |

---

## Diagnostics JSON reference

```json
{
  "case_id": "tl_001",
  "contract_type": "timelock",
  "effective_mode": "timelock",
  "pattern_profile_loaded": true,
  "timelock_rules_loaded": true,
  "timelock_rail_loaded": false
}
```
