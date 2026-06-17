# Conditional Spend / Swap — Layer Diagnosis

**Purpose:** First failure per pipeline layer for conditional spend, swap, and HTLC representative cases.  
**Diagnostics:** `benchmark/results/conditional_spend_diagnostics/<case_id>.json`  
**Tool:** `python scripts/diagnose_conditional_spend_case.py [case_id|all]`  
**Canonical runs:** `bench_20260331_2132_4ce4` (conditional_spend), `bench_20260611_1708_0154` (hashlock post-1A), `bench_20260612_1952_c07e` (rp_002)

---

## Layer definitions

| Layer | Pass criteria |
|-------|----------------|
| Phase 1 routing | `contract_type` + `features` parsed; knowledge profile matches benchmark `pattern` intent |
| Rules loaded | `conditional_spend_rules.yaml` for conditional-spend intents; `hashlock_rules.yaml` for hashlock overlay when appropriate |
| Rails loaded | `_SWAP_RAIL` for HTLC/swap; pattern-appropriate rails otherwise |
| Sanity | No `Sanity Check failed (STRICT)` |
| Lint | No blocking LNC violations |
| Compile | `cashc` succeeds |
| Evaluator | `intent_coverage >= 0.70`, `converged: true`, critical features satisfied |

---

## Routing diagnostics — 9-case subset (2026-06-12)

| Case | Suite | Routing | Rules | Rails | `routing_mismatch` |
|------|-------|---------|-------|-------|-------------------|
| cs_001 | conditional_spend.yaml | **fail** → timelock | **fail** (timelock_rules) | partial (escrow) | **yes** |
| cs_002 | conditional_spend.yaml | **fail** → timelock | **fail** | none | **yes** |
| cs_003 | conditional_spend.yaml | **fail** → covenant | **fail** (covenant_rules) | partial (escrow) | **yes** |
| cs_004 | conditional_spend.yaml | **fail** → timelock | **fail** | none | **yes** |
| hl_001 | hashlock.yaml | partial → swap | partial (conditional_spend) | **fail** | no† |
| hl_002 | hashlock.yaml | partial → swap | partial | **fail** | no† |
| hl_003 | hashlock.yaml | partial → swap | partial | **fail** | no† |
| hl_004 | hashlock.yaml | partial → swap | partial | **fail** | no† |
| rp_002 | refundable_payment.yaml | partial → swap | partial | **fail** | **yes** |

†Benchmark `pattern: hashlock` intentionally maps to `swap` → `conditional_spend`; `hashlock_rules.yaml` still not loaded.

### Routing detail

| Case | `contract_type` | `effective_mode` | `canonical_pattern` | `knowledge_files` | `conditional_spend_rules` | `hashlock_rules` | `swap_rail` |
|------|-----------------|------------------|---------------------|-------------------|---------------------------|------------------|-------------|
| cs_001 | timelock | timelock | timelock | timelock_rules.yaml | false | false | false |
| cs_002 | timelock | timelock | timelock | timelock_rules.yaml | false | false | false |
| cs_003 | stateful | stateful | covenant | covenant_rules.yaml | false | false | false |
| cs_004 | timelock | timelock | timelock | timelock_rules.yaml | false | false | false |
| hl_001 | swap | swap | conditional_spend | conditional_spend_rules.yaml | true | false | false |
| hl_002 | swap | swap | conditional_spend | conditional_spend_rules.yaml | true | false | false |
| hl_003 | swap | swap | conditional_spend | conditional_spend_rules.yaml | true | false | false |
| hl_004 | swap | swap | conditional_spend | conditional_spend_rules.yaml | true | false | false |
| rp_002 | swap | swap | conditional_spend | conditional_spend_rules.yaml | true | false | false |

---

## Layer table — `conditional_spend.yaml` (`bench_20260331_2132_4ce4`)

| Case | Phase 1 | Rules | Rails | Sanity | Lint | Compile | Evaluator | First failure |
|------|---------|-------|-------|--------|------|---------|-----------|---------------|
| cs_001 | **partial** | **fail**‡ | partial | pass | pass | pass | **fail** | **Evaluator** |
| cs_002 | **partial** | **fail**‡ | — | pass | pass | pass | **fail** | **Evaluator** |
| cs_003 | **partial** | **fail**‡ | partial | pass | pass | pass | **fail** | **Evaluator** |
| cs_004 | **partial** | **fail**‡ | — | — | — | **fail** | — | **Compile** |
| cs_005 | **partial** | **fail**‡ | — | — | — | **fail** | — | **Compile** |

‡Benchmark expects `conditional_spend_rules.yaml`; Phase 1 routes to timelock/covenant profiles.

**Aggregate:** Compile **3/5**; convergence gate **3/5**; true quality avg score **0.083**; first failure **evaluator on 3/3** compiling positives, **compile on 2/5**.

### Evaluator gaps (compiling cases)

| Case | Issue | Code evidence |
|------|-------|---------------|
| cs_001 | Low `final_score` (0.20) despite coverage 1.0 | Valid dual-path `release`/`reclaim` with `tx.time >= timeout` |
| cs_002 | `time_validation` miss; score 0.07 | Uses `this.age >= inactivityTimeout` instead of `tx.time` |
| cs_003 | `multisig` miss; score 0.15 | Third path uses dual `checkSig` without `checkMultiSig` |

---

## Layer table — `hashlock.yaml`

### Post-1A (`bench_20260611_1708_0154`)

| Case | Phase 1 | Rules | Sanity | Lint | Compile | Evaluator | First failure |
|------|---------|-------|--------|------|---------|-----------|---------------|
| hl_001 | partial | partial‡ | pass | pass | pass | pass | — |
| hl_002 | partial | partial‡ | pass | pass | pass | pass | — |
| hl_003 | partial | partial‡ | pass | pass | pass | pass | — |
| hl_004 | partial | partial‡ | pass | pass | pass | pass | — |
| hl_005 | partial | partial‡ | pass | pass | **fail** | — | **Compile** |

‡`conditional_spend_rules.yaml` loaded; `hashlock_rules.yaml` not loaded.

### Pre-1A historical (`bench_20260331_2117_fd6a`)

| Case | Compile | Evaluator | First failure | Missing (evaluator) |
|------|---------|-----------|---------------|---------------------|
| hl_001 | pass | **fail** | **Evaluator** | `hash_verification`, `preimage_validation` |
| hl_002 | pass | **fail** | **Evaluator** | `hash_verification`; critical `sha256_check` |
| hl_003 | pass | **fail** | **Evaluator** | `hash_verification`, `preimage_validation` |
| hl_004 | **fail** | — | **Compile** | — |
| hl_005 | pass | **fail** | **Evaluator** | `must_fail_missing_token_validation` (safe code scored 0) |

**Aggregate (historical):** Compile **4/5**; first failure **evaluator on 4/4** compiling cases (fixed post-1A for hl_001–hl_003).

---

## Layer table — HTLC composite (`rp_002`, `bench_20260612_1952_c07e`)

| Case | Phase 1 | Rules | Sanity | Lint | Compile | Evaluator | First failure |
|------|---------|-------|--------|------|---------|-----------|---------------|
| rp_002 | partial | partial‡ | pass | pass | pass | **fail** | **Evaluator** |

- `intent_coverage`: **1.0** — all required features detected including `hash_verification`, `preimage_validation`, `hashlock`
- `final_score`: **0.20** — critical **`sha256_check`** not satisfied
- Generated code uses `hash160(preimage) == paymentHash` in `AtomicSwap.claim` — valid BCH HTLC, mismatched suite critical

---

## Aggregated first-failure counts (representative 14 case-runs)

| First failure | conditional_spend (5) | hashlock post-1A (5) | rp_002 (1) |
|---------------|----------------------|----------------------|------------|
| **Evaluator** | 3 | 0 | 1 |
| **Compile** | 2 | 1 | 0 |
| Routing (hard block) | 0 | 0 | 0 |
| Lint / Sanity | 0 | 0 | 0 |

---

## Failure-class matrix

| Class | Description | Evidence |
|-------|-------------|----------|
| **A — Production converged** | Compile + converge + score ≥ threshold | hl_001–hl_003 post-1A only |
| **B — Measurement-limited** | Compile OK, low scores | cs_001–cs_003; pre-1A hashlock; rp_002 critical hash |
| **C — Routing-limited** | Wrong profile/rules | **4/4** cs_* → timelock/covenant; hashlock_rules + swap_rules + `_SWAP_RAIL` unused |
| **D — Generation-limited** | Synthesis/compile dominates | cs_004, cs_005, hl_004 (historical), hl_005 |

### Classification verdict: **C + B (mixed)**

- **Primary on `conditional_spend.yaml`:** **C (routing)** — benchmark pattern never reaches `conditional_spend_rules.yaml`
- **Primary on compiling positives:** **B (measurement)** — low scores despite valid dual-path codegen
- **Hashlock slice post-1A:** **A** on hl_001–hl_003 — **masks** umbrella gaps
- **Residual:** **D** on hard/adversarial cases

---

## Security-negative / failure cases

| Case | Suite | First failure | Notes |
|------|-------|---------------|-------|
| cs_005 | conditional_spend.yaml | Compile | `must_fail_path_isolation` — generation cannot emit vulnerable mixed-path contract |
| hl_005 | hashlock.yaml | Compile (latest) | `must_fail_missing_token_validation` — safe token checks in generated code |

---

## Phase 1A scope pointer

See `docs/conditional_spend_state_report.md` §6. Layer diagnosis supports **measurement-first** Phase 1A:

1. Conditional-spend evaluator aliases and critical mappings
2. Re-benchmark `conditional_spend.yaml` after scoring fix
3. `rp_002` `sha256_check` vs `hash160` critical alignment
4. Routing overlay deferred unless 1A proves generation sufficient under corrected scores
