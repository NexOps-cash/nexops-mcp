# Vault — Layer Diagnosis

**Purpose:** First failure per pipeline layer for vault validation cases.  
**Diagnostics:** `benchmark/results/vault_diagnostics/<case_id>.json`  
**Tool:** `python scripts/diagnose_vault_case.py [case_id|all]`  
**Canonical runs:** `bench_20260331_2128_47e9` (`vaults.yaml`), `bench_20260401_2119_3456` (`vaults_real`)

---

## Layer definitions

| Layer | Pass criteria |
|-------|----------------|
| Routing | `contract_type: vault`, `effective_mode: vault`, correct profile |
| Rules | `vault_rules.yaml` injected (`VLT-*` rules) |
| Rails | `_VAULT_RAIL` attached |
| Sanity | No `Sanity Check failed (STRICT)` |
| Lint | No blocking LNC violations |
| Compile | `cashc` succeeds |
| Evaluator | `intent_coverage >= 0.70`, `converged: true`, criticals satisfied |

---

## Routing diagnostics — 8 representative cases (2026-06-11)

| Case | Suite | contract_type | effective_mode | vault_rules | vault_rail | escrow feature co-tag |
|------|-------|---------------|----------------|-------------|------------|------------------------|
| v_001 | vaults.yaml | vault | vault | yes | yes | no |
| v_002 | vaults.yaml | vault | vault | yes | yes | no |
| v_003 | vaults.yaml | vault | vault | yes | yes | **yes** |
| v_007 | vaults.yaml | vault | vault | yes | yes | **yes** |
| vr_001 | vaults_real | vault | vault | yes | yes | no |
| vr_003 | vaults_real | vault | vault | yes | yes | **yes** |
| vr_006 | vaults_real | vault | vault | yes | yes | **yes** |
| vr_009 | vaults_real | vault | vault | yes | yes | no |

All cases: `canonical_pattern: vault`, `knowledge_files: [vault_rules.yaml]`.

---

## Layer table — `vaults.yaml` (`bench_20260331_2128_47e9`)

| Case | Routing | Rules | Rails | Sanity | Lint | Compile | Evaluator | First failure |
|------|---------|-------|-------|--------|------|---------|-----------|---------------|
| v_001 | pass | pass | pass | pass | pass | pass | **fail** | **Evaluator** |
| v_002 | pass | pass | pass | pass | pass | pass | **fail** | **Evaluator** |
| v_003 | pass | pass | pass | pass | pass | pass | **fail** | **Evaluator** |
| v_004 | pass | pass | pass | pass | pass | pass | **fail** | **Evaluator** |
| v_005 | pass | pass | pass | pass | pass | pass | **fail** | **Evaluator** |
| v_006 | pass | pass | pass | pass | pass | pass | **fail** | **Evaluator** (failure case) |
| v_007 | pass | pass | pass | pass | pass | pass | **fail** | **Evaluator** |
| v_008 | pass | pass | pass | pass | pass | **fail** | — | **Compile** |

**Aggregate:** Compile **7/8**; first failure **evaluator on 7/7** compiling positives; **compile on 1** failure case.

### Evaluator gaps (`vaults.yaml`)

| Case | Missing / penalty features | Code evidence |
|------|---------------------------|---------------|
| v_001 | `time_validation`, `token_validation` | `this.age >= delaySeconds` in finalize; BCH-only (no tokens) |
| v_002 | `output_value_validation` | Staged value split present; not credited |
| v_003 | `time_validation`, `token_validation` | Emergency + delayed paths present |
| v_004 | `time_validation` | `this.age` / cancel path |
| v_005 | `time_validation`, `output_value_validation` | Tiered thresholds in code |
| v_006 | `covenant_continuation` | Failure case — `must_fail_permanent_covenant` unwired |
| v_007 | partial | Multisig recovery path; score 0.20 |

---

## Layer table — `vaults_real` subset (`bench_20260401_2119_3456`)

| Case | Routing | Rules | Rails | Sanity | Lint | Compile | Evaluator | First failure |
|------|---------|-------|-------|--------|------|---------|-----------|---------------|
| vr_001 | pass | pass | pass | pass | pass | pass | pass | — |
| vr_002 | pass | pass | pass | pass | pass | pass | pass | — |
| vr_003 | pass | pass | pass | pass | pass | pass | pass | — |
| vr_004 | pass | pass | pass | pass | pass | pass | pass | — |
| vr_005 | pass | pass | pass | pass | pass | pass | pass | — |
| vr_006 | pass | pass | pass | pass | pass | pass | **fail** | **Evaluator** (`multisig`) |
| vr_007 | pass | pass | pass | pass | pass | pass | pass | — |
| vr_008 | pass | pass | pass | pass | pass | pass | pass | — |
| vr_009 | pass | pass | pass | pass | pass | pass | **fail** | **Evaluator** (`semantic_pass`) |
| vr_010 | pass | pass | pass | pass | pass | **fail** | — | **Timeout** |
| vr_011–018 | pass | pass | pass | pass | pass | pass | pass | — |
| vr_019–022 | pass | pass | pass | pass | pass | pass | **fail** | **Evaluator** (failure cases) |
| vr_023 | pass | pass | pass | pass | pass | **fail** | — | **Timeout** |
| vr_024 | pass | pass | pass | pass | pass | pass | pass | — |

**Full run aggregate:** Compile **22/24**; Convergence **16/24**; Avg score **0.718**.

---

## Aggregated first-failure counts

| First failure | `vaults.yaml` (8-case) | `vaults_real` (24-case) |
|---------------|------------------------|-------------------------|
| **Evaluator** | 7 | 6 |
| **Compile** | 1 | 0 |
| **Timeout** | 0 | 2 |
| Routing | 0 | 0 |
| Lint / Sanity | 0 | 0 |

---

## Failure-class matrix

| Class | Description | Vault evidence |
|-------|-------------|----------------|
| **A — Production converged** | Strong compile + correct generation + good scores | 18/24 `vaults_real` at 1.0 in `bench_20260401_2119_3456` |
| **B — Measurement-limited** | Compile OK, low scores | `vaults.yaml` avg **0.10** despite valid staged vault code |
| **C — Generation-limited** | Compile/synthesis dominates | Mar 20 runs (0% compile); `vr_010`/`vr_023` timeout; `v_008` compile |
| **D — Routing-limited** | Wrong profile/rails | **Ruled out** — all diagnostics pass |
| **E — Mixed** | Combination | **Overall** — B on canonical suite, A on real-world subset, C on hard edge cases |

---

## Diagnostics JSON reference

```json
{
  "case_id": "v_001",
  "contract_type": "vault",
  "effective_mode": "vault",
  "canonical_pattern": "vault",
  "pattern_profile_loaded": true,
  "vault_rules_loaded": true,
  "vault_rail_loaded": true,
  "knowledge_files": ["vault_rules.yaml"],
  "features": ["timelock", "stateful", "spending"]
}
```

---

## Security-negative / failure cases (track separately)

| Case | Suite | First failure | Notes |
|------|-------|---------------|-------|
| v_006 | vaults.yaml | Evaluator | `must_fail_permanent_covenant` |
| v_008 | vaults.yaml | Compile | `must_fail_missing_amount_validation` |
| vr_019–022 | vaults_real | Evaluator | Failure / adversarial intents |

Same bucket as `esc_005`/`esc_006`, `ms_004`/`ms_005`, `tl_004`, `hl_005`.

---

## Next step (audit only)

**Vault Phase 1A** — evaluator + semantic map alignment for `vaults.yaml` requirements and vault critical features. No rails, pipeline, or generation changes in 1A scope.

```bash
python scripts/diagnose_vault_case.py all
```
