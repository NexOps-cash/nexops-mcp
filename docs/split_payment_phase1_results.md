# Split Payment Phase 1 — Benchmark Results & Root-Cause Analysis

**Suite:** `benchmark/suites/split_payment.yaml`  
**Settings:** `disable_fallbacks=True`, free synthesis only

---

## Run history

| Phase | Run ID | Cases | Compile | Converge | Notes |
|-------|--------|-------|---------|----------|-------|
| Pre-1A baseline | `bench_20260607_2109_cdbc` | 4 | 0% | 0% | Rules not loading |
| Phase 1A | `bench_20260611_1340_e8c2` | 2 | 0% | 0% | Profile alias fix only |
| Phase 1B | `bench_20260611_1344_cb95` | 4 | 0% | 0% | WP1–WP6 implemented |

---

## Phase 1A gate (`bench_20260611_1340_e8c2`)

**Change:** `canonical_pattern("split")` → `split_payment` in [`pattern_profiles.py`](../src/services/pattern_profiles.py).

| Case | compile | conv | score | retries | failure_layer |
|------|---------|------|-------|---------|---------------|
| split_001_treasury | fail | no | 0.0 | 3 | Compile |
| split_002_payroll | fail | no | 0.0 | 3 | Compile |

**Gate result:** 0/2 compile → routing investigation continued into Phase 1B.

**Diagnostics (post-1A):** `split_001` — all routing flags true. `split_002` — rules still false until tag overlay (Phase 1B).

---

## Phase 1B (`bench_20260611_1344_cb95`)

**Changes:** N-output conservation helper, lint/sanity, N-output rails/rules, tag-overlay for split_rules, multisig+split routing, evaluator `split_payment` pool, `multiple_outputs` feature rule, unit tests.

| Case | compile | conv | intent_cov | score | retries | failure_layer | contract |
|------|---------|------|------------|-------|---------|---------------|----------|
| split_001_treasury | fail | no | 0.0 | 0.0 | 3 | Compile | none |
| split_002_payroll | fail | no | 0.0 | 0.0 | 3 | Compile | none |
| split_003_multisig_distribution | fail | no | 0.0 | 0.0 | 3 | Compile | none |
| split_004_revenue_share | fail | no | 0.0 | 0.0 | 3 | Compile | none |

**Log pattern:** `[StructuralIntegrity] Post-lint code invalid — skipping compile, regen` on all cases.

**Diagnostics (post-1B):** All 4 cases — `pattern_profile_loaded`, `split_rules_loaded`, `split_rail_loaded` = **true**. JSON in `benchmark/results/split_diagnostics/`.

---

## Root-cause analysis (updated)

### Is split itself broken?

**Generation quality for N>2 is broken under benchmark settings.** Routing and rules are now correct (diagnostics confirm). Legacy 2-output suite still converges at ~50%.

### Is N-output conservation the bottleneck?

**No longer the first failure.** Lint/sanity N-output helpers deployed; pre-1B failures were LNC-004/014. Post-1B, code does not reach compile — structural integrity rejects malformed LLM output first.

### Is token distribution the bottleneck?

**Secondary.** `split_002` now loads split_rules via tag overlay. Compile still fails on structural invalidity before token conservation can be scored.

### Is multisig composition the bottleneck?

**Not at routing layer post-1B.** `split_003` loads split rules + rail. Generation still fails structurally.

### Priority next steps (beyond Phase 1B)

1. **Structural integrity / generation** — N-output contracts need stronger synthesis templates or golden fallback for 3/4-output shapes
2. **Compile-fix loop** — investigate why structural integrity blocks before `cashc` on all retries
3. **Optional:** enable pattern-specific fallback for split benchmark runs (production uses fallbacks; benchmark disables them)

### Should split_payment remain the convergence target?

**Yes**, but the next increment is **generation/structural quality for N outputs**, not more routing or conservation regex work. Infrastructure (1A + 1B) is in place.

---

## Artifacts

| Artifact | Path |
|----------|------|
| Layer diagnosis | [`split_layer_diagnosis.md`](split_layer_diagnosis.md) |
| Routing JSON | `benchmark/results/split_diagnostics/*.json` |
| Diagnostic tool | `scripts/diagnose_split_case.py` |
| Conservation tests | `tests/test_split_conservation.py` (4 passed) |
| Phase 1B results | `benchmark/results/bench_20260611_1344_cb95.json` |

---

## Re-run commands

```bash
# Routing diagnostics only (no benchmark API cost for generation)
python scripts/diagnose_split_case.py all

# Full subset benchmark
python -m benchmark.runner benchmark/suites/split_payment.yaml \
  --ids split_001_treasury,split_002_payroll,split_003_multisig_distribution,split_004_revenue_share
```
