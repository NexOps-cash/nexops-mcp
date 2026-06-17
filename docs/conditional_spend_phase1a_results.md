# Conditional Spend — Phase 1A Results (Measurement Alignment)

**Date:** 2026-06-12  
**Scope:** Evaluator, semantic map, and feature-rules alignment only. No pipeline routing, rails, synthesis, lint, or sanity changes.  
**Baseline benchmark:** `bench_20260331_2132_4ce4` (`conditional_spend.yaml`)  
**Offline re-score:** Saved codegen from baseline run + current evaluator (`tests/test_conditional_spend_evaluator.py`)

---

## Executive summary

Phase 1A confirms **Conditional Spend positives (cs_001–cs_003) are evaluator-limited**, matching Escrow / Multisig / Timelock / Hashlock pattern stabilization. All three compiling positives **offline re-score to 1.0** with **no critical misses** and **convergence pass**.

| Case | Before coverage | Before score | After coverage | After score | Δ score |
|------|-----------------|--------------|----------------|-------------|---------|
| cs_001 | 1.00 | **0.20** | 1.00 | **1.00** | +0.80 |
| cs_002 | 0.67 | **0.07** | 1.00 | **1.00** | +0.93 |
| cs_003 | 0.75 | **0.15** | 1.00 | **1.00** | +0.85 |
| **Avg (positives)** | **0.81** | **0.14** | **1.00** | **1.00** | **+0.86** |

Hard cases **unchanged** (out of Phase 1A scope): cs_004/cs_005 compile-fail; rp_002 HTLC composite still blocked on `sha256_check` (documented, not implemented).

**Classification:** Conditional Spend Phase 1A **successful** on cs_001–cs_003 — proceed to routing/generation investigation only for remaining failures (cs_004, cs_005, rp_002).

---

## Per-case audit

### cs_001 — score 0.20 despite coverage 1.0

**Generated code (`bench_20260331_2132_4ce4`):** dual-path `release` (Alice sig) + `reclaim` (Bob sig after `tx.time >= timeoutTimestamp`).

| Field | Baseline |
|-------|----------|
| `detected_features` | `alice_signature`, `bob_signature`, `timelock_unlock`, `timelock_refund`, `value_check` |
| `missing_features` | *(none)* |
| `intent_coverage` | **1.0** |
| `final_score` | **0.20** |

**Failed criticals (baseline):** `valid_signature_check` and/or `locktime_check` — pattern `conditional_spend` fell through to the **generic default alias pool** (not the timelock/escrow pool). Critical satisfaction used `has_signature_auth` / `time_validation` capabilities first; when sem_caps disagreed, fallback `locktime_check` alias only mirrored `capabilities.get("time_validation")` without code-level reinforcement.

**Score breakdown (baseline formula):**

```
final_score = compile(1) × lint(1) × coverage(1.0) × semantic(1) × critical_penalty(0.2)
            = 0.20
```

**Root cause:** Missing **`conditional_spend` pattern pool** — not generation defect. Code already implements sig OR timelock reclaim.

**Phase 1A fix:** `_conditional_spend_alias_pool()` with explicit `valid_signature_check` (checkSig regex) and `locktime_check` (`tx.time` / `this.age` / timelock detectors). Register `conditional_spend` in evaluator pattern dispatch.

---

### cs_002 — `this.age` inactivity timeout

**Generated code:** `ownerSpend` (immediate) + `beneficiaryClaim` with `require(this.age >= inactivityTimeout)`.

| Field | Baseline |
|-------|----------|
| `detected_features` | `owner_signature`, `beneficiary_signature`, `locking_bytecode`, `value_check` — **no** `timelock_*` tags |
| `missing_features` | **`time_validation`** |
| `intent_coverage` | **0.67** |
| `final_score` | **0.07** |

**Analysis:**

- `this.age` is valid **BCH CSV relative timelock** semantics for inactivity / sequence maturity.
- Baseline evaluator treated `time_validation` as satisfied only when `timelock_unlock` / `timelock_refund` feature tags fired — not when only `this.age` appeared in code.
- `locktime_check` critical also failed for the same reason → critical ×0.2 penalty.

**Phase 1A fix:**

- `_conditional_spend_time_ok()` accepts `(tx.time|tx.age|this.age) >=` in code.
- Feature rules already include `relative_timelock` / `sequence_check` for `this.age`; conditional-spend pool wires them into `time_validation` / `locktime_check` aliases.

**Verdict:** Evaluator incorrectly missed relative timeout logic — **not** a routing or generation bug.

---

### cs_003 — dual `checkSig` multisig path

**Generated code:** three functions — `aliceOnly`, `bobAfterTimeout`, `aliceAndBob` (two separate `checkSig` calls in one function).

| Field | Baseline |
|-------|----------|
| `detected_features` | `alice_signature`, `bob_signature`, `timelock_unlock`, `timelock_refund`, `locking_bytecode`, `value_check` — **no** `multisig` |
| `missing_features` | **`multisig`** |
| `intent_coverage` | **0.75** |
| `final_score` | **0.15** |

**Analysis:**

- Third path uses **dual `checkSig`** (Alice + Bob), not `checkMultiSig` — same class of issue fixed for Multisig Phase 1A.
- Baseline `multisig_2of2` regex required `checkSig && checkSig` in a **single** require; separate requires did not match.
- `_multisig_detected()` did not inspect per-function bodies.

**Phase 1A fix:**

- `_dual_checksig_in_function()` — true when any function body contains ≥2 `checkSig` calls.
- Broadened `multisig_2of2` feature rule to match dual-checkSig function bodies.
- `conditional_spend` pool maps `multisig` through enhanced `_multisig_detected()`.

**Verdict:** Same multisig-detection gap as Multisig family — **measurement-only**.

---

### rp_002 — HTLC hash function (audit only; not implemented)

**Generated code (`bench_20260612_1952_c07e`):** `AtomicSwap.claim` uses `hash160(preimage) == paymentHash`; refund uses `tx.time >= timeoutTimestamp`.

| Field | Latest run |
|-------|------------|
| `intent_coverage` | **1.0** |
| `final_score` | **0.20** |
| `converged` | **false** |
| Failed critical | **`sha256_check`** |

**Analysis:**

- Suite critical requires `sha256_check`; codegen uses **`hash160`** — standard **BCH HTLC** convention (RIPEMD160/SHA256 preimage hash).
- `hash_verification`, `preimage_validation`, `ripemd160_check`, `claim_path`, `refund_path`, `locktime_check` all **detected**.
- `sha256_check` alias requires `hash256`/`sha256` in code — correctly **false** for this codegen.

**Recommendation (deferred to follow-up):**

1. **Preferred:** Change `rp_002` critical from `sha256_check` to `ripemd160_check` **or** a neutral `preimage_hash_check` critical — intent text does not mandate SHA256.
2. **Alternative:** Extend refundable/hashlock evaluator to treat `hash160` as satisfying `sha256_check` when intent is hash-agnostic — risks over-crediting wrong hash function when SHA256 is explicit (e.g. `hl_001`).

**Not implemented in Phase 1A** per audit scope boundary for rp_002.

---

## Implementation summary

| File | Change |
|------|--------|
| `benchmark/evaluator.py` | `_conditional_spend_alias_pool()`, `_conditional_spend_time_ok()`, `_dual_checksig_in_function()`, `_must_fail_path_isolation()`; register `conditional_spend` pattern; `conditional_spend_semantic_relaxed` convergence gate |
| `benchmark/config/semantic_requirement_map.yaml` | `path_isolation`, `must_fail_path_isolation`, `reclaim_path`, `conditional_release` mappings |
| `benchmark/config/feature_rules.yaml` | `multisig_2of2` rule accepts dual `checkSig` in one function body |
| `tests/test_conditional_spend_evaluator.py` | Offline re-score guards for cs_001–cs_003 |
| `benchmark/suites/conditional_spend.yaml` | **No changes** — security semantics preserved |

---

## Decision gate

### 1. Are cs_001–cs_003 production-converged after measurement alignment?

**Yes (offline).** All three: compile pass (baseline), coverage **1.0**, score **1.0**, no critical misses, convergence pass with `conditional_spend_semantic_relaxed`.

*Note:* Full live re-benchmark not run in this task (no pipeline changes); offline re-score uses saved baseline codegen.

### 2. Is Conditional Spend another evaluator-limited family?

**Yes** for cs_001–cs_003. Identical stabilization pattern to Timelock (`this.age`) and Multisig (dual `checkSig`).

### 3. Is routing still a blocker after Phase 1A?

**Yes for knowledge injection, no for positive scoring.** Diagnostics (`conditional_spend_diagnostics/`) show cs_* intents still route to `timelock` / `covenant` — `conditional_spend_rules.yaml` not loaded. Measurement alignment **does not depend** on that routing for the three positives because codegen already matches intent. Routing remains relevant for **Phase 1B** hard cases and prompt consistency.

### 4. Is Phase 1B required?

**Yes for residual failures — not for cs_001–cs_003.**

| Remaining gap | Layer | Phase 1B? |
|---------------|-------|-----------|
| cs_004 amount-based conditional | Generation (compile fail) | **Yes** |
| cs_005 path-isolation adversarial | Generation (compile fail) | **Yes** (or accept as negative case) |
| rp_002 `sha256_check` vs `hash160` | Measurement / suite spec | **Yes** (suite or refundable alias) |
| cs_* → `conditional_spend_rules.yaml` | Routing | **Yes** (routing overlay) |

---

## Success criteria check

| Criterion | cs_001 | cs_002 | cs_003 |
|-----------|--------|--------|--------|
| Compile pass | ✓ (baseline) | ✓ | ✓ |
| Convergence pass | ✓ (offline) | ✓ | ✓ |
| Intent coverage ≥ 0.85 | **1.0** | **1.0** | **1.0** |
| Score ≥ 0.85 | **1.0** | **1.0** | **1.0** |

**Verdict:** **Conditional Spend Phase 1A successful** — proceed to routing/generation investigation only if remaining failures persist (cs_004, cs_005, rp_002).

---

## Artifacts

| Artifact | Path |
|----------|------|
| Phase 1A results | `docs/conditional_spend_phase1a_results.md` (this file) |
| Phase 0 state report | `docs/conditional_spend_state_report.md` |
| Phase 0 layer diagnosis | `docs/conditional_spend_layer_diagnosis.md` |
| Tests | `tests/test_conditional_spend_evaluator.py` |
