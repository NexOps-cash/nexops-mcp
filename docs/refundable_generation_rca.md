# Refundable Payment — Phase 1B Generation RCA

**Date:** 2026-06-11  
**Scope:** Generation audit for `rp_003` (subscription) and `rp_004` (gradual vesting). **No evaluator changes. No rails.**  
**Historical baseline:** `bench_20260331_2121_6f05` — both cases `compile_pass: false`, `failure_layer: Compile`, `code: null`, 3 retries exhausted.  
**Tools:** `scripts/diagnose_refundable_generation.py` (live trace), `scripts/refundable_generation_rca_offline.py` (routing + gate replay)

**LLM note:** Live Phase1/Phase2 traces blocked (OpenRouter 402 / OpenAI quota). RCA combines historical benchmark metadata, deterministic routing inference from `pipeline.py`, and offline gate replay on representative synthesis drafts.

---

## Executive conclusion

| Case | Routing mismatch? | First **hard** failure (generation) | Benchmark label |
|------|-------------------|-------------------------------------|-----------------|
| **rp_003** | Yes → **escrow** (not `refundable_payment`) | **DSLLint** on staged remainder shapes (`LNC-005`); simple 2-path escrow draft **passes all gates** | `Compile` (coarse) |
| **rp_004** | Yes → **linear_vesting / decay** (not `refundable_payment`) | **DSLLint** on covenant vesting (`LNC-016`) and decay math (`LNC-010`, `LNC-011`) | `Compile` (coarse) |

**Routing contributes** (wrong knowledge family: `escrow_rules.yaml` / `decay_rules.yaml` instead of `refundable_payment_rules.yaml`), but **routing alone does not explain compile fail** — representative drafts fail earlier at **DSL lint** or exhaust retry loops before a converged artifact is returned.

**Phase 1B should target generation + lint alignment**, not evaluator and not rails in the first pass.

---

## Summary table

| Case | First failure | Compile error | Lint | Sanity | Draft exists |
|------|---------------|---------------|------|--------|--------------|
| **rp_003** | **DSLLint** (`LNC-005` on remainder-split attempt) | Not reached on failing shape; simple draft compiles | **Fail** on covenant remainder draft: implicit value subtraction | Pass on representative simple draft | **Yes** (representative); **No** in historical JSON |
| **rp_004** | **DSLLint** (`LNC-016` covenant; `LNC-010`/`LNC-011` formula) | Not reached on failing shapes | **Fail** on both vesting representative drafts | Not reached | **Yes** (representative); **No** in historical JSON |

Artifacts:
- `benchmark/results/refundable_generation/rp_003_representative_draft.cash`
- `benchmark/results/refundable_generation/rp_004_representative_draft.cash`
- `benchmark/results/refundable_generation/rp_003_rca_offline.json`
- `benchmark/results/refundable_generation/rp_004_rca_offline.json`

---

## Question-by-question determination

### Is rp_003 failing because routing sends it to escrow?

**Partially — routing is mismatched, but not the first hard blocker.**

| Field | Value |
|-------|-------|
| Inferred `contract_type` | **escrow** |
| `canonical_pattern` | **escrow** |
| `knowledge_files` | `escrow_rules.yaml` |
| `refundable_payment_rules.yaml` | **Not loaded** |
| `_ESCROW_RAIL` | Only if Phase 1 tags `escrow` in features (often absent) |

Intent signals: *subscription*, *service claim monthly*, *subscriber cancel*, *reclaim remainder* — no crowdfund keywords. Phase 1 enum has no `refundable_payment`; LLM + keyword heuristics land on **escrow + timelock**.

**Gate replay:**
- **Simple 2-path escrow** (`claim` + `cancel`, full-value outputs): lint ✓, compile ✓, toll gate ✓, sanity ✓
- **Staged remainder covenant** (subtract `payoutAmount` from input): **lint ✗ `LNC-005`** — *"Implicit fee arithmetic… Do NOT subtract fees from value"*

**Verdict:** Historical failure is consistent with the model repeatedly emitting **remainder/staged subscription** patterns that **die at DSL lint**, not with escrow routing alone.

---

### Is rp_004 failing because routing sends it to decay?

**Yes for knowledge family; first hard failure is still DSL lint.**

| Field | Value |
|-------|-------|
| Inferred `contract_type` | **linear_vesting** |
| `canonical_pattern` | **decay** |
| `knowledge_files` | `decay_rules.yaml` |
| Golden path | `linear_vesting.cash` exists but **disabled** in benchmark (`disable_golden=True`) |

Intent signals: *gradual release*, *25% every 7 days*, *sender reclaims if inactive* — matches `linear_vesting` keyword upgrade in `pipeline.py` (~749–757).

**Gate replay:**
- **3-output self-anchor vesting** (golden-like): **lint ✗ `LNC-016`** — re-anchor without full value conservation on continuation output
- **Elapsed-time formula** (`payout = totalAmount * elapsed / duration`): **lint ✗ `LNC-010`** (nested `tx.time` arithmetic), **`LNC-011`** (division without `duration > 0`)

**Verdict:** Decay/vesting routing steers synthesis toward **covenant continuation** and **decay math** — both collide with **LNC-016 / LNC-010 / LNC-011** before `cashc`.

---

### Is it a DSL lint issue?

**Yes — primary hard failure for both cases on representative drafts.**

| Case | Lint rules | Message (abbrev.) |
|------|------------|-------------------|
| rp_003 (remainder draft) | **LNC-005** | Implicit subtraction `input.value - payoutAmount` |
| rp_004 (covenant draft) | **LNC-016** | Self-anchor at `outputs[2]` without value preservation |
| rp_004 (formula draft) | **LNC-010**, **LNC-011** | Nested time math; unguarded division |

Pipeline runs up to **4 lint retries** per generation attempt, then full regen (max 3). Lint non-convergence → `synthesis_failed_no_fallback` → benchmark stores **no code**.

---

### Is it a toll gate issue?

**Secondary for rp_003; not first failure on representative drafts.**

Simple rp_003 draft: toll gate **passed** (non-critical warnings: `implicit_output_ordering`, `multisig_distinctness_flaw`).

If synthesis produces code that passes lint but trips **critical** toll detectors, Phase 3 would retry — could contribute to 3-attempt exhaustion. **Not observed as first failure** in offline replay.

---

### Is it a CashScript compile issue?

**Not the first hard failure** on representative failing shapes — **lint blocks before `cashc`**.

Benchmark `failure_layer: Compile` is **misleading**: `evaluator.py` maps all `synthesis_failed_no_fallback` errors to `"Compile"` regardless of whether the last loop died on lint, toll gate, or compile.

---

## Per-case detail

### rp_003 — Subscription payment

**Intent:** Service claims monthly; subscriber can cancel and reclaim remainder.

**Routing (deterministic inference):**
```json
{
  "contract_type": "escrow",
  "canonical_pattern": "escrow",
  "knowledge_files": ["escrow_rules.yaml"],
  "routing_mismatch": true
}
```

**Representative final draft (simple — passes gates):**  
`benchmark/results/refundable_generation/rp_003_representative_draft.cash`

```cashscript
function claim(sig serviceSig) {
    require(checkSig(serviceSig, service));
    require(tx.time >= monthlyPeriod);
    require(tx.outputs.length == 1);
    require(tx.outputs[0].value == tx.inputs[this.activeInputIndex].value);
}
function cancel(sig subscriberSig) { /* full refund path */ }
```

**Failing shape (likely LLM target for “remainder”):**
```cashscript
require(tx.outputs[0].value == tx.inputs[this.activeInputIndex].value - payoutAmount);
```
→ **DSLLint `LNC-005`** (first hard failure)

**Historical run:** 79.2s, 3 retries, no saved code.

---

### rp_004 — Gradual release / inactivity reclaim

**Intent:** 25% every 7 days; sender reclaims after 30 days inactive.

**Routing (deterministic inference):**
```json
{
  "contract_type": "linear_vesting",
  "canonical_pattern": "decay",
  "knowledge_files": ["decay_rules.yaml"],
  "routing_mismatch": true
}
```

**Representative draft:**  
`benchmark/results/refundable_generation/rp_004_representative_draft.cash`

**First hard failure:** **DSLLint `LNC-016`** (3-output re-anchor without conservation)

Alternate synthesis path (proportional unlock formula) fails **LNC-010** + **LNC-011** first.

**Historical run:** 52.5s, 3 retries, no saved code.

---

## Why benchmark says “Compile”

```text
pipeline exhausted (lint/toll/compile/sanity)
  → synthesis_failed_no_fallback
    → evaluator failure_layer = "Compile"  # default bucket
    → code = null
```

Improvement for future audits: propagate `last_failure_layer` from `pipeline_engine.py` into benchmark results.

---

## Phase 1B design (after RCA — not implemented)

### Do first (generation / knowledge)

| Priority | Target | Action |
|----------|--------|--------|
| P0 | **rp_004 vesting** | Enable **golden `linear_vesting`** for vesting-shaped refundable intents OR add Phase 2 decay block with **LNC-010/011-safe** payout template |
| P0 | **rp_004 lint** | Teach **3-output value conservation** (`outputs[0]+outputs[1]+outputs[2] == input`) in decay/vesting synthesis rules |
| P1 | **rp_003 subscription** | Steer toward **simple dual-path escrow** (no staged remainder) OR document allowed subscription split pattern that satisfies **LNC-005** (named fee/limit CSV) |
| P1 | **rp_003 lint** | Subscription profile: whitelist monthly claim + cancel without `value - withdraw` subtraction |

### Defer (not first)

| Item | Why defer |
|------|-----------|
| **Refundable rail** | First failure is lint/synthesis, not missing rail text |
| **Routing overlay to `refundable_payment_rules`** | Helpful later; does not unblock LNC-005/016/010 |
| **Evaluator changes** | Phase 1A complete; not generation-blocking |

### Success criteria (Phase 1B gate)

| Case | Target |
|------|--------|
| rp_003 | `compile_pass: true`, draft saved, intent coverage ≥ 0.70 |
| rp_004 | `compile_pass: true`, draft saved, intent coverage ≥ 0.70 |

---

## Reproduce

```bash
# Live trace (requires LLM credits)
REFUNDABLE_GEN_PROVIDER=openai python scripts/diagnose_refundable_generation.py rp_003
REFUNDABLE_GEN_PROVIDER=openai python scripts/diagnose_refundable_generation.py rp_004

# Offline routing + gate replay (no LLM)
python scripts/refundable_generation_rca_offline.py

# Routing only
python scripts/diagnose_refundable_case.py rp_003
python scripts/diagnose_refundable_case.py rp_004
```
