# Multisig Phase 1 — Validation Results

**Date:** 2026-06-11  
**Scope:** Diagnosis and 4-case benchmark only — no pipeline fixes.  
**Audit:** [`multisig_state_report.md`](multisig_state_report.md)  
**Diagnostics:** `benchmark/results/multisig_diagnostics/`  
**Tool:** `python scripts/diagnose_multisig_case.py all`

---

## Executive summary

### **MULTISIG MOSTLY CONVERGED**

Generation compiles and produces structurally valid multisig for all four representative cases. **Composite multisig+split is fully converged** (score 1.0). **Pure multisig suite cases fail the convergence gate only because of spurious `token_validation`** — the same evaluator mismatch pattern resolved for Escrow in Phase 1A.

| Blocker type | Verdict |
|--------------|---------|
| Routing | No |
| Rails | No (informational gap only) |
| Sanity / Lint | No |
| Compile / Generation | No on validation subset |
| **Evaluator** | **Yes** — `token_validation` on BCH ms_001/ms_002 |
| Regression harness | Flaky (model-dependent) |

### Recommendation

**Perform small multisig Phase 1** — evaluator and suite alignment only (mirror Escrow Phase 1A: remove `token_validation`, map `both_signatures_required` / `three_of_five_logic`, wire `must_fail_*`). Do **not** mark multisig complete. Do **not** launch major rail/golden work until measurement gate passes.

---

## Metrics (4-case validation)

| Metric | Value |
|--------|-------|
| **Compile rate** | **100%** (4/4) |
| **Convergence rate** | **50%** (2/4) |
| **Avg intent coverage** | **0.833** |
| **Avg final score** | **0.833** |
| Avg retries | 1.0 |

### By case

| Case | Role | Compile | Converged | Intent cov | Score | First failure layer | Retries |
|------|------|---------|-----------|------------|-------|---------------------|---------|
| ms_001 | 2-of-2 | pass | **no** | 0.667 | 0.667 | **Evaluator** | 1 |
| ms_002 | 2-of-3 | pass | **no** | 0.667 | 0.667 | **Evaluator** | 1 |
| ms_006 | + timelock | pass | yes | 1.000 | 1.000 | — | 1 |
| split_003 | + split | pass | yes | 1.000 | 1.000 | — | 1 |

**Runs:** `bench_20260611_1552_cbe5` (ms_001–006), `bench_20260611_1553_8eee` (split_003)

### ms_001 / ms_002 missing features (evaluator only)

```
missing_features: ["token_validation"]
detected_features: includes multisig, multisig_2of2 or multisig_2of3, alice_signature, ...
```

Generated code is valid 2-of-2 / 2-of-3 multisig. Escrow Phase 1A extractor fix confirms `multisig` detection works; **only `token_validation` prevents intent_coverage ≥ 0.70**.

---

## Failure breakdown

| Class | Cases | Evidence |
|-------|-------|----------|
| **Routing** | 0 | Diagnostics: correct `contract_type` / `effective_mode` for all 4 |
| **Rails** | 0 | No compile impact; `multisig_rail_loaded: false` by design |
| **Sanity** | 0 | No sanity failures in benchmark JSON |
| **Lint** | 0 | `lint_errors: 0` all cases |
| **Compile** | 0 | 4/4 compile pass |
| **Evaluator** | 2 | ms_001, ms_002 — `token_validation` spurious requirement |
| **Generation** | 0 | Valid checkSig / checkMultiSig structures in all outputs |

---

## Routing diagnostics summary

| Case | contract_type | effective_mode | multisig_rules | Rails loaded |
|------|---------------|----------------|----------------|--------------|
| ms_001 | multisig | multisig | yes | — |
| ms_002 | multisig | multisig | yes | — |
| ms_006 | multisig | multisig | yes | escrow |
| split_003 | distribution | split | split_rules | split |

---

## Comparison to historical baseline

| Metric | `bench_20260331_2118_ff90` (6-case) | Validation 4-case (2026-06-11) |
|--------|--------------------------------------|--------------------------------|
| Compile | 100% | 100% |
| Convergence (strict) | 100%* | 50% |
| Avg score | 0.135 | **0.833** |
| Primary score drag | token_validation + missing multisig on dual checkSig | token_validation only |

\*Historical convergence used same loose gate but ms_001 had intent_cov 0.33; post-extractor `multisig` is detected, score improved to 0.667 but convergence now **fails** at 0.70 threshold.

---

## Regression harness (out of benchmark scope)

| Model | Result |
|-------|--------|
| Llama 3.3 (`regression_results.json`) | SUCCESS |
| Claude 4.6 (`regression_results_run2.json`) | FAILED |

Not a stable multisig signal — different models, fallbacks enabled, vague prompt. Address after evaluator Phase 1A.

---

## Decision matrix

| Option | Fit |
|--------|-----|
| Mark multisig complete → move to timelock | **No** — suite still has spurious requirements; failure cases unwired |
| **Small multisig Phase 1 (evaluator/suite)** | **Yes** — mirrors escrow 1A; ~0.5 day |
| Major stabilization (rail, golden, toll gate) | **Defer** — generation already passes validation subset |

---

## Suggested Phase 1A scope (not implemented)

1. Remove `token_validation` from `ms_001`–`ms_003` in `multisig.yaml`
2. Align role-based features (`alice_signature`, etc.) or map `both_signatures_required`
3. Wire `must_fail_pubkey_substitution` / `must_fail_duplicate_signer`
4. Rerun `ms_001`–`ms_006` + `split_003` gate

**Exit target:** 4/4 convergence, avg score ≥ 0.85 on validation subset.

---

## Reproduce

```bash
python scripts/diagnose_multisig_case.py all
python -m benchmark.runner benchmark/suites/multisig.yaml --ids ms_001,ms_002,ms_006
python -m benchmark.runner benchmark/suites/split_payment.yaml --ids split_003_multisig_distribution
```
