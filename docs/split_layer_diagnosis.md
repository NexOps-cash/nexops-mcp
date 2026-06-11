# Split Payment — Layer Diagnosis

**Purpose:** Record **first failure** per pipeline layer (not just final `failure_layer`).  
**Diagnostics JSON:** `benchmark/results/split_diagnostics/<case_id>.json`  
**Tool:** `python scripts/diagnose_split_case.py [case_id|all]`

---

## Layer definitions

| Layer | Pass criteria |
|-------|----------------|
| Phase 1 routing | `contract_type` + `features` parsed; `effective_mode` set |
| Rules loaded | `split_rules_loaded: true` in diagnostics JSON |
| Rails loaded | `split_rail_loaded: true` in diagnostics JSON |
| Sanity pass | No `Sanity Check failed (STRICT)` on first converging attempt |
| Lint pass | `[DSLLint] PASSED` or no blocking LNC violations |
| Compile pass | `cashc` succeeds |
| Evaluator pass | `intent_coverage > 0` and `converged: true` |

**First failure** = earliest layer marked fail in a run.

---

## Baseline — pre-Phase 1A (`bench_20260607_2109_cdbc` + diagnostics `2026-06-11`)

From `benchmark/results/split_diagnostics/*.json` (before profile alias fix):

| Case | Phase 1 routing | Rules loaded | Rails loaded | Sanity | Lint | Compile | Evaluator | First failure |
|------|-----------------|--------------|--------------|--------|------|---------|-----------|---------------|
| split_001_treasury | pass (`distribution`+`split`→`effective_mode=split`) | **fail** | pass | fail | fail (LNC-004) | fail | fail | Rules / Lint |
| split_002_payroll | pass (`ft_transfer`, not split mode) | **fail** (ft profile, no split_rules) | pass | unknown | unknown | fail | fail | Routing (wrong mode) |
| split_003_multisig_distribution | pass (`split`+`multisig`) | **fail** | pass | fail | fail (LNC-015) | fail | fail | Rules / Lint |
| split_004_revenue_share | pass (`split`) | **fail** | pass | fail | fail (LNC-004/005) | fail | fail | Rules / Lint |

Known routing bug: `canonical_pattern("split")` did not map to `split_payment` → `split_rules.yaml` never loaded despite `split_rail_loaded: true`.

---

## Post-Phase 1A (`bench_20260611_1340_e8c2` + diagnostics `2026-06-11`)

Profile alias fix applied. **0/2 compile** (gate: continue to Phase 1B).

| Case | Phase 1 routing | Rules loaded | Rails loaded | Sanity | Lint | Compile | Evaluator | First failure |
|------|-----------------|--------------|--------------|--------|------|---------|-----------|---------------|
| split_001_treasury | pass | **pass** | pass | unknown | fail (LNC-004) | fail | fail | Lint / structural |
| split_002_payroll | pass (`ft_transfer`) | **fail** (pre-overlay) | pass | unknown | fail (LNC-014) | fail | fail | Lint / structural |

Diagnostics after alias: `split_001` → all three JSON flags `true`. Routing fixed for split mode; compile unchanged.

---

## Post-Phase 1B (`bench_20260611_1344_cb95` + diagnostics `2026-06-11`)

WP1/WP2/WP3/WP4/WP6 implemented. **0/4 compile** — first failure moved past routing/rules.

| Case | Phase 1 routing | Rules loaded | Rails loaded | Sanity | Lint | Compile | Evaluator | First failure |
|------|-----------------|--------------|--------------|--------|------|---------|-----------|---------------|
| split_001_treasury | pass | pass | pass | unknown | unknown | fail | fail | Structural integrity |
| split_002_payroll | pass | **pass** (tag overlay) | pass | unknown | unknown | fail | fail | Structural integrity |
| split_003_multisig_distribution | pass | pass | pass | unknown | unknown | fail | fail | Structural integrity |
| split_004_revenue_share | pass | pass | pass | unknown | unknown | fail | fail | Structural integrity |

All four cases: `pattern_profile_loaded`, `split_rules_loaded`, `split_rail_loaded` = **true** in JSON diagnostics. Bottleneck is now **LLM structural generation** (invalid/malformed code pre-compile), not routing.

---

## Diagnostics JSON reference

```json
{
  "contract_type": "...",
  "effective_mode": "...",
  "features": ["..."],
  "pattern_profile_loaded": true,
  "split_rules_loaded": true,
  "split_rail_loaded": true
}
```
