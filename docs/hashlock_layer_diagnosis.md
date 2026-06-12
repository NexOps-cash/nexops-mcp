# Hashlock — Layer Diagnosis

**Purpose:** First failure per pipeline layer for hashlock validation cases.  
**Diagnostics:** `benchmark/results/hashlock_diagnostics/<case_id>.json`  
**Tool:** `python scripts/diagnose_hashlock_case.py [case_id|all]`  
**Validation benchmark:** `bench_20260611_1659_0cd2` (hl_001–hl_003)  
**Historical:** `bench_20260331_2117_fd6a` (full 5-case)

---

## Layer definitions

| Layer | Pass criteria |
|-------|----------------|
| Phase 1 routing | `contract_type` + `features` parsed; knowledge profile appropriate for intent |
| Rules loaded | `hashlock_rules.yaml` injected when hashlock intent (currently **fails** — loads `conditional_spend_rules.yaml`) |
| Rails loaded | `_SWAP_RAIL` when HTLC/swap intent (currently **fails** — features omit `htlc`/`swap`) |
| Sanity pass | No `Sanity Check failed (STRICT)` |
| Lint pass | No blocking LNC violations |
| Compile pass | `cashc` succeeds |
| Evaluator pass | `intent_coverage >= 0.70`, `converged: true`, critical features satisfied |

---

## Validation subset — 4 routing diagnostics (2026-06-11)

| Case | Role | Routing | Rules | Rails | Sanity | Lint | Compile | Evaluator | First failure |
|------|------|---------|-------|-------|--------|------|---------|-----------|---------------|
| hl_001 | Simple SHA256 hashlock | **partial** | **fail**† | **fail** | pass | pass | pass | **fail** | **Evaluator** |
| hl_002 | HTLC claim + refund | **partial** | **fail**† | **fail** | pass | pass | pass | **fail** | **Evaluator** |
| hl_003 | RIPEMD160 / hash160 | **partial** | **fail**† | **fail** | pass | pass | pass | **fail** | **Evaluator** |
| rp_002 | Refundable + preimage composite | **partial** | **fail**† | **fail** | — | — | — | — | *(not re-benchmarked)* |

†`contract_type: swap` → `conditional_spend_rules.yaml`; `hashlock_rules.yaml` not loaded.

**Routing note:** Phase 1 returns `swap` for all hashlock intents — acceptable coarse routing, but **benchmark pattern `hashlock` ≠ pipeline knowledge overlay**.

---

## Validation benchmark — 3 cases (`bench_20260611_1659_0cd2`)

| Case | Routing | Rules | Sanity | Lint | Compile | Evaluator | First failure | Missing (evaluator) |
|------|---------|-------|--------|------|---------|-----------|---------------|---------------------|
| hl_001 | partial | fail† | pass | pass | pass | **fail** | **Evaluator** | `hash_verification`, `preimage_validation`; critical `sha256_check` |
| hl_002 | partial | fail† | pass | pass | pass | **fail** | **Evaluator** | `hash_verification`; critical `sha256_check`, `locktime_check` |
| hl_003 | partial | fail† | pass | pass | pass | **fail** | **Evaluator** | `hash_verification`, `preimage_validation`; critical `ripemd160_check` |

**Aggregate:** Compile **3/3**; convergence **0/3**; first failure **evaluator only**.

### Generated code vs measurement

| Case | Hash logic in code | `hashlock` detected | Suite score |
|------|-------------------|---------------------|-------------|
| hl_001 | `sha256(preimage) == paymentHash` | yes | 0.0 |
| hl_002 | `hash256(preimage)` + `tx.time >= timeout` | yes | 0.133 |
| hl_003 | `hash160(secret) == secretHash` | yes | 0.0 |

---

## Full `hashlock.yaml` — historical (`bench_20260331_2117_fd6a`)

| Case | Routing | Rules | Sanity | Lint | Compile | Evaluator | First failure |
|------|---------|-------|--------|------|---------|-----------|---------------|
| hl_001 | partial | fail† | pass | pass | pass | **fail** | **Evaluator** |
| hl_002 | partial | fail† | pass | pass | pass | **fail** | **Evaluator** |
| hl_003 | partial | fail† | pass | pass | pass | **fail** | **Evaluator** |
| hl_004 | partial | fail† | pass | pass | **fail** | — | **Compile** |
| hl_005 | partial | fail† | pass | pass | pass | **fail** | **Evaluator** |

---

## Routing diagnostics detail

| Case | contract_type | effective_mode | canonical_pattern | knowledge_files | hashlock_rules | swap_rail |
|------|---------------|----------------|-------------------|-----------------|----------------|-----------|
| hl_001 | swap | swap | conditional_spend | conditional_spend_rules.yaml | false | false |
| hl_002 | swap | swap | conditional_spend | conditional_spend_rules.yaml | false | false |
| hl_003 | swap | swap | conditional_spend | conditional_spend_rules.yaml | false | false |
| rp_002 | swap | swap | conditional_spend | conditional_spend_rules.yaml | false | false |

`hashlock_rail_loaded` does not exist — no rail in codebase.

---

## Aggregated first-failure counts

| First failure | Validation 3-case | Historical 5-case |
|---------------|-------------------|-------------------|
| **Evaluator** | 3 | 4 |
| **Compile** | 0 | 1 (hl_004) |
| Routing (knowledge mismatch) | 3‡ | 5‡ |
| Lint / Sanity | 0 | 0 |

‡Knowledge mismatch does not block compile on current evidence; tracked as routing debt, not first hard failure.

---

## Failure-class matrix

| Class | Description | Hashlock evidence |
|-------|-------------|-------------------|
| **A — Measurement-limited** | Evaluator / suite / semantic map | **Dominant** — compile + correct hash logic, score ≈ 0 |
| **B — Generation-limited** | Split-style structural compile failure | **Absent** on hl_001–003; hl_004 only |
| **C — Routing-limited** | Wrong profile / rules / rail | **Secondary** — swap→conditional_spend; hashlock_rules unused |
| **D — New synthesis family** | Needs new rails / major prompt work | **No** — HTLC generates without dedicated rail |

---

## Diagnostics JSON reference

```json
{
  "case_id": "hl_001",
  "benchmark_pattern": "hashlock",
  "contract_type": "swap",
  "effective_mode": "swap",
  "canonical_pattern": "conditional_spend",
  "hashlock_rules_loaded": false,
  "conditional_spend_rules_loaded": true,
  "swap_rail_loaded": false,
  "knowledge_files": ["conditional_spend_rules.yaml"]
}
```

---

## Next step (audit only — no implementation)

**Hashlock Phase 1A** (measurement alignment): evaluator pool + semantic map + suite alias alignment — same playbook as Timelock 1A. Routing overlay (`hashlock` in Phase 1 enum or `swap`→`hashlock` profile) is a **separate routing decision**, not required to prove generation health on validation subset.
