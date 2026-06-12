# Refundable Payment — Layer Diagnosis

**Purpose:** First failure per pipeline layer for refundable payment validation cases.  
**Diagnostics:** `benchmark/results/refundable_diagnostics/<case_id>.json`  
**Tool:** `python scripts/diagnose_refundable_case.py [case_id|all]`  
**Canonical run:** `bench_20260331_2121_6f05` (`refundable_payment.yaml`)  
**Confirmed routing:** `rp_002` in `benchmark/results/hashlock_diagnostics/rp_002.json`

---

## Layer definitions

| Layer | Pass criteria |
|-------|----------------|
| Routing | `canonical_pattern: refundable_payment` or intentional subtype with equivalent rules; benchmark `pattern` aligned with injected knowledge |
| Rules | `refundable_payment_rules.yaml` injected (`RP-*` rules) when benchmark expects refundable semantics |
| Rails | Pattern-appropriate rail (escrow / swap / none) attached when features warrant |
| Sanity | No `Sanity Check failed (STRICT)` |
| Lint | No blocking LNC violations |
| Compile | `cashc` succeeds |
| Evaluator | `intent_coverage >= 0.70`, `converged: true`, criticals satisfied |

---

## Routing diagnostics — 6 cases

| Case | Suite | Inferred `contract_type` | `effective_mode` | `canonical_pattern` | `refundable_rules` | `swap_rail` | `routing_mismatch` |
|------|-------|---------------------------|------------------|----------------------|-------------------|-------------|-------------------|
| rp_001 | refundable_payment.yaml | escrow | escrow | escrow | **no** | no | **yes** |
| rp_002 | refundable_payment.yaml | swap | swap | conditional_spend | **no** | **no**† | **yes** |
| rp_003 | refundable_payment.yaml | escrow | escrow | escrow | **no** | no | **yes** |
| rp_004 | refundable_payment.yaml | linear_vesting | linear_vesting | decay | **no** | no | **yes** |
| rp_005 | refundable_payment.yaml | escrow | escrow | escrow | **no** | no | **yes** |
| rp_006 | refundable_payment.yaml | refundable_crowdfund | refundable_crowdfund | **refundable_payment** | **yes** | no | no |

†`rp_002` confirmed: Phase 1 `features` lack `htlc`/`swap` tag → `_SWAP_RAIL` not injected despite HTLC-shaped codegen.

**Aggregate:** **5/6** cases mismatch benchmark `refundable_payment` profile; **1/6** (`rp_006`) loads `refundable_payment_rules.yaml`.

---

## Layer table — `refundable_payment.yaml` (`bench_20260331_2121_6f05`)

| Case | Routing | Rules | Rails | Sanity | Lint | Compile | Evaluator | First failure |
|------|---------|-------|-------|--------|------|---------|-----------|---------------|
| rp_001 | **partial** | partial (escrow) | partial | pass | pass | pass | **fail** | **Evaluator** |
| rp_002 | **partial** | partial (conditional_spend) | partial | pass | pass | pass | **fail** | **Evaluator** |
| rp_003 | partial | partial | — | pass | pass | **fail** | — | **Compile** |
| rp_004 | **partial** | partial (decay) | — | pass | pass | **fail** | — | **Compile** |
| rp_005 | partial | partial | partial | pass | pass | pass | **fail** | **Evaluator** (failure case) |
| rp_006 | pass | pass | — | pass | pass | pass | **fail**‡ | **Evaluator** |

‡Historical evaluator miss on `output_value_validation`; offline re-score → **1.0** with current helpers.

**Aggregate:** Compile **4/6**; first failure **evaluator on 4/4** compiling cases; **compile on 2** (`rp_003`, `rp_004`).

### Evaluator gaps (compiling cases)

| Case | Missing / penalty features | Code evidence |
|------|---------------------------|---------------|
| rp_001 | `token_validation` | BCH-only `PaymentWithRefund`; `tx.time >= refundTimeout` on refund |
| rp_002 | `token_validation` (historical also `hash_verification`) | `hash256(preimage) == paymentHash` present — hash fixed post Hashlock 1A |
| rp_005 | `must_fail_wrong_time_field` critical | Uses **correct** `tx.time >= deadline` on both paths — safe code |
| rp_006 | `output_value_validation` (historical) | `value >= goalAmount` / full value refund paths present |

---

## Aggregated first-failure counts

| First failure | Count (6-case) |
|---------------|----------------|
| **Evaluator** | 4 |
| **Compile** | 2 |
| Routing (hard block) | 0 |
| Lint / Sanity | 0 |

---

## Failure-class matrix

| Class | Description | Refundable evidence |
|-------|-------------|---------------------|
| **A — Measurement-limited** | Compile OK, low scores | rp_001–002, rp_006 — valid claim/refund code, avg score **0.064** |
| **B — Generation-limited** | Compile/synthesis dominates | rp_003, rp_004 compile fail; rp_005 cannot emit wrong time field |
| **C — Routing-limited** | Wrong profile/rules | 5/6 cases never load `refundable_payment_rules.yaml`; rp_002 → `conditional_spend` |
| **D — Mixed** | Combination | **Overall** — A on positives, B on hard variants, C on knowledge injection |

### Classification verdict: **D — Mixed**

- **Primary blocker on positives:** **A (Measurement)** — spurious `token_validation`, missing refundable alias pool  
- **Secondary:** **C (Routing)** — benchmark pattern ≠ pipeline canonical for most intents  
- **Residual:** **B (Generation)** — subscription/vesting compile; adversarial rp_005

---

## Security-negative / failure cases

| Case | Suite | First failure | Notes |
|------|-------|---------------|-------|
| rp_005 | refundable_payment.yaml | Evaluator | `must_fail_wrong_time_field` — generation produced **valid** `tx.time` usage |

Same bucket as `tl_004`, `hl_005`, `v_006`/`v_008`: failure intent not emitted; **not** an evaluator gap when code is semantically safe.

---

## Phase 1A gate (measurement only)

| Criterion | Threshold | Compiling positives (rp_001, rp_002, rp_006) | Full 6-case |
|-----------|-----------|-----------------------------------------------|-------------|
| Intent coverage | ≥ 0.70 | **Achievable** after 1A (`token_validation` fix) | Blocked by compile cases |
| Avg score | ≥ 0.85 | **Justified** target post-1A | **Not met** until rp_003/rp_004 compile |

**Proceed with Refundable Phase 1A** (evaluator + semantic map only) — **yes**, for compiling positives.  
**Do not** conflate with routing overlay or subscription/vesting generation in 1A scope.

---

## Diagnostics JSON reference

```json
{
  "case_id": "rp_002",
  "benchmark_pattern": "refundable_payment",
  "contract_type": "swap",
  "effective_mode": "swap",
  "canonical_pattern": "conditional_spend",
  "refundable_rules_loaded": false,
  "conditional_spend_rules_loaded": true,
  "routing_mismatch": true,
  "knowledge_files": ["conditional_spend_rules.yaml"]
}
```

---

## Next step (audit only)

**Refundable Payment Phase 1A** — evaluator alias pool + `token_validation` alignment for BCH-only cases. No rails, pipeline, or generation changes in 1A scope.

```bash
python scripts/diagnose_refundable_case.py all
```
