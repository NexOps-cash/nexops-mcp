# Refundable Payment Phase 1A — Measurement Alignment Results

**Date:** 2026-06-11  
**Scope:** Evaluator + semantic map + suite alignment only (no pipeline/rails/generation).  
**Before baseline:** `bench_20260331_2121_6f05` (avg score **0.064**, 67% compile)  
**Live after 1A:** `bench_20260611_1832_a6cc` — **blocked by OpenRouter 402** (no codegen)  
**Validation:** Offline re-score of historical compiling codes with current evaluator + updated suite

---

## Executive conclusion

**Measurement was the main blocker for positive compiling cases.** Offline re-score confirms **rp_001, rp_002, rp_006 → 1.0** with structurally valid historical code.

**Decision gate: Scenario A** — positives at 1.0; **rp_003/rp_004 still compile fail** on historical run → **Refundable is not complete**; needs **Phase 1B generation** for subscription/vesting variants.

---

## Modified files

| File | Changes |
|------|---------|
| `benchmark/evaluator.py` | `_refundable_*` helpers, `_refundable_alias_pool`, `refundable_payment` pattern pool, BCH-only `token_validation` in `legacy_capabilities` |
| `benchmark/config/semantic_requirement_map.yaml` | `token_validation` alias pool; `refund_path`, `claim_path`, `goal_threshold_logic`, `crowdfund_refund_path` |
| `benchmark/config/feature_rules.yaml` | Regex features for refund/claim/goal/crowdfund paths |
| `benchmark/suites/refundable_payment.yaml` | Dropped `token_validation` from rp_001/rp_002; added refund/claim criticals; crowdfund criticals on rp_006 |

---

## Semantic mappings added

| Key | Detector | Pattern | Cases |
|-----|----------|---------|-------|
| `refund_path` | `function refund` + `tx.time >=` + `checkSig` | `function refund(sig buyerSig) { require(tx.time >= ...)` | rp_001, rp_002, rp_006 |
| `claim_path` | `function claim/release` + `checkSig` | `function claim(...)` / `release(...)` | rp_001, rp_002, rp_006 |
| `goal_threshold_logic` | `goalAmount` vs input value | `require(tx.inputs[...].value >= goalAmount)` | rp_006 |
| `crowdfund_refund_path` | refund + goal-not-met | `value < goalAmount` in refund | rp_006 |
| `token_validation` | BCH-only relax | No `tokenCategory`/`tokenAmount` in code → pass | rp_001, rp_002 |

---

## Offline re-score (historical code, Phase 1A evaluator)

| Case | Before score | After (offline) | Compile | Gate |
|------|--------------|-----------------|---------|------|
| **rp_001** | 0.15 | **1.00** | pass | Positive ✓ |
| **rp_002** | 0.06 | **1.00** | pass | Positive ✓ |
| rp_003 | 0.00 | — | **fail** | Generation |
| rp_004 | 0.00 | — | **fail** | Generation |
| rp_005 | 0.10 | 0.10† | pass | Failure case |
| **rp_006** | 0.075 | **1.00** | pass | Positive ✓ |

†rp_005 uses correct `tx.time` — `must_fail_wrong_time_field` correctly fails (generation, not measurement).

---

## Decision gate

### Scenario A — **CONFIRMED**

| Criterion | Result |
|-----------|--------|
| rp_001, rp_002, rp_006 = 1.0 | **Yes** (offline) |
| rp_003, rp_004 compile fail | **Yes** (historical) |

**Verdict:** Refundable **not complete**. Proceed to **Phase 1B generation** for subscription (`rp_003`) and vesting (`rp_004`). Do **not** block 1B on routing unless compile remains stuck after generation fixes.

### Scenario B — Not met

`rp_003`/`rp_004` did not compile in historical or live rerun (LLM credits).

---

## Reproduce

```bash
python -m benchmark.runner benchmark/suites/refundable_payment.yaml
python -m benchmark.runner benchmark/suites/refundable_payment.yaml --ids rp_001,rp_002,rp_006
```

Offline re-score uses saved code in `benchmark/results/bench_20260331_2121_6f05.json`.
