# Escrow — Layer Diagnosis

**Purpose:** Record **first failure** per pipeline layer (not just final `failure_layer`).  
**Diagnostics JSON:** `benchmark/results/escrow_diagnostics/<case_id>.json`  
**Tool:** `python scripts/diagnose_escrow_case.py [case_id|all]`  
**Benchmark evidence:** `bench_20260331_2120_3d04` (escrow.yaml), `bench_20260315_1101_4fa4` (escrow_suite.yaml), `bench_20260314_1530_7fe0` (legacy), `regression_results.json` (`2_escrow`)

---

## Layer definitions

| Layer | Pass criteria |
|-------|----------------|
| Phase 1 routing | `contract_type` + `features` parsed; `effective_mode` appropriate for intent |
| Rules loaded | `escrow_rules_loaded: true` in diagnostics JSON |
| Rails loaded | `escrow_rail_loaded: true` (informational — not required for compile on most cases) |
| Sanity pass | No `Sanity Check failed (STRICT)` on converging attempt |
| Lint pass | No blocking LNC violations |
| Compile pass | `cashc` succeeds |
| Evaluator pass | `intent_coverage` meets suite expectation; negative cases fail appropriately |

**First failure** = earliest layer marked fail for the case’s primary success criterion.

---

## Suite A — `escrow.yaml` (`bench_20260331_2120_3d04`)

All cases: **compile pass**, **converged**, **lint pass**, **sanity pass** (no sanity failures recorded). First failure is **Evaluator** for all six.

| Case | Phase 1 routing | Rules loaded | Rails loaded | Sanity | Lint | Compile | Evaluator | First failure |
|------|-----------------|--------------|--------------|--------|------|---------|-----------|---------------|
| esc_001 | pass (`escrow`, multisig) | pass | **fail** | pass | pass | pass | **fail** (cov 0.33; missing multisig, token_validation) | **Evaluator** |
| esc_002 | pass (`escrow`, multisig) | pass | **fail** | pass | pass | pass | **fail** (cov 0.67; missing token_validation) | **Evaluator** |
| esc_003 | pass (`escrow`, timelock) | pass | pass | pass | pass | pass | **fail** (cov 0.60; missing multisig, token_validation) | **Evaluator** |
| esc_004 | pass (`escrow`, distribution) | pass | **fail** | pass | pass | pass | **fail** (cov 0.75; missing token_validation; **generation**: single-path code) | **Evaluator** (+ gen gap) |
| esc_005 | **fail** (diag: `nft_minting`) | **fail** | **fail** | pass | pass | pass | **fail** (cov 0.50; negative test not enforced) | **Evaluator** / routing (diag) |
| esc_006 | **fail** (diag: `nft_minting`) | **fail** | **fail** | pass | pass | pass | **fail** (cov 0.00; generated permanent covenant) | **Generation** + **Evaluator** |

**Notes:**

- Routing column for esc_005/esc_006 reflects **2026-06-11 diagnostics** (`disable_golden=True`). Benchmark run still tagged `pattern: escrow` and compiled — Phase 1 may differ when golden/fallback paths participate.
- `esc_004` compiles but generated code has only one `release()` with a single `recipientLockingBytecode` — dual-destination intent not implemented (**generation quality**, not compile failure).
- `esc_006` model produced intentional-looking permanent covenant (`hold()` + `this.activeBytecode`) — correct adversarial behavior, but suite does not score it as `must_fail_permanent_covenant` pass.

---

## Suite B — `escrow_suite.yaml` (`bench_20260315_1101_4fa4`)

All cases: **full pass** through evaluator (avg score 1.0).

| Case | Phase 1 routing | Rules loaded | Rails loaded | Sanity | Lint | Compile | Evaluator | First failure |
|------|-----------------|--------------|--------------|--------|------|---------|-----------|---------------|
| escrow_basic_multisig | pass | pass | **fail** | pass | pass | pass | pass | — |
| escrow_timeout_refund | pass | pass | pass | pass | pass | pass | pass | — |
| escrow_arbiter_resolution | pass | pass | **fail** | pass | pass | pass | pass | — |
| escrow_2of3_release | pass | pass | **fail** | pass | pass | pass | pass | — |
| escrow_timeout_with_arbiter | pass | pass | pass | pass | pass | pass | pass | — |
| escrow_value_preservation | pass | pass | **fail** | pass | pass | pass | pass | — |
| escrow_single_output_rule | pass | pass | **fail** | pass | pass | pass | pass | — |
| escrow_dual_resolution | pass | pass | pass | pass | pass | pass | pass | — |
| escrow_role_separation | pass | pass | **fail** | pass | pass | pass | pass | — |
| escrow_extreme_protocol | pass | pass | pass | pass | pass | pass | pass | — |

**Takeaway:** Role-based required features (`buyer_signature`, etc.) align with `feature_extractor.py`. Low rail attachment does not block this suite.

---

## Legacy subset (`bench_20260314_1530_7fe0`)

| Case | Phase 1 routing | Rules | Rails | Sanity | Lint | Compile | Evaluator | First failure |
|------|-----------------|-------|-------|--------|------|---------|-----------|---------------|
| escrow_easy_1 | pass | pass | **fail** | pass | pass | pass | pass | — |
| escrow_medium_1 | pass | pass | **fail** | pass | pass | pass | **fail** (cov 0.25) | **Evaluator** |
| escrow_hard_1 | pass | pass | pass | pass | pass | pass | pass | — |
| escrow_extreme_1 | pass | pass | pass | pass | pass | pass | pass | — |

**escrow_medium_1:** `checkMultiSig` with pubkey `arbiter` — extractor emits `arbiter_signature`, suite requires `arbitrator_signature` → **evaluator naming mismatch**.

---

## Regression harness — `2_escrow`

**Prompt:** `"2-of-3 multisig escrow with 30 day timeout reclaim"`  
**Source:** `regression_results.json`, `regression_results_run2.json`

| Layer | Llama 3.3 | Claude 4.6 |
|-------|-----------|------------|
| Phase 1 routing | unknown (no diagnostics artifact) | unknown |
| Rules / rails | unknown | unknown |
| Sanity / lint | unknown | unknown |
| Compile | **fail** (`compile_exhausted`) | **fail** (`compile_exhausted`) |
| Evaluator | fail (no output) | fail (no output) |

**First failure:** **Compile** (generation / fix-loop exhaustion). Distinct from benchmark suites which use explicit multi-line intents and `disable_fallbacks` in runner.

---

## Routing diagnostics — rail attachment pattern (`2026-06-11`)

| `escrow_rail_loaded` | Cases |
|----------------------|-------|
| **true** | esc_003, escrow_timeout_refund, escrow_timeout_with_arbiter, escrow_dual_resolution, escrow_extreme_protocol |
| **false** | All other cases in default 16-case set |

Rail attaches when Phase 1 places `"escrow"` in the `features` list (often alongside `timelock` + `distribution`), not merely when `effective_mode == "escrow"`.

---

## Aggregated first-failure counts (all known escrow benchmarks)

| First failure layer | Cases | Share |
|---------------------|-------|-------|
| **Evaluator** | esc_001–005, escrow_medium_1 | 6 |
| **Generation** (intent not reflected in code) | esc_004 (dual path), esc_006 (adversarial), `2_escrow` | 3 |
| **Compile** | `2_escrow` (regression only) | 1 harness |
| **Routing** (diagnostics only) | esc_005, esc_006 | 2 |
| **None (full pass)** | escrow_suite 10/10 + 3 legacy | 13 |

---

## Diagnostics JSON reference

```json
{
  "case_id": "esc_003",
  "contract_type": "escrow",
  "effective_mode": "escrow",
  "features": ["multisig", "timelock", "distribution", "escrow"],
  "pattern_profile_loaded": true,
  "escrow_rules_loaded": true,
  "escrow_rail_loaded": true,
  "golden_path_candidate": false
}
```

| Field | True when |
|-------|-----------|
| `pattern_profile_loaded` | `get_pattern_profile(effective_mode)` returns `knowledge_files` |
| `escrow_rules_loaded` | Structured knowledge contains escrow rules markers |
| `escrow_rail_loaded` | `build_pattern_rails(...)` contains `[RAIL: ESCROW MODE]` |
| `golden_path_candidate` | `contract_type == escrow_2of3_nft` after Phase 1 |

---

## Classification summary

| Class | Primary? | Evidence |
|-------|----------|----------|
| A — Routing | Minor | esc_005/esc_006 misroute in diagnostics; positive cases OK |
| B — Rails | Low | Under-attachment; not blocking compile |
| C — Sanity/lint | Low | 0 lint failures in committed escrow runs |
| D — Generation | Moderate | `2_escrow`, esc_004 dual-path, esc_006 adversarial output |
| **E — Evaluator** | **Yes** | escrow.yaml avg score 0.085 despite 100% convergence |
