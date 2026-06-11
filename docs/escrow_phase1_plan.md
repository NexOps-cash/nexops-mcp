# Escrow Phase 1 — Implementation Plan (1A / 1B / 1C)

**Date:** 2026-06-11  
**Goal:** Raise escrow from “compiles but scores 0.085” to ≥85% convergence **and** ≥0.85 avg final score on the canonical 6-case `escrow.yaml` subset, without destabilizing the 10-case `escrow_suite.yaml` (currently 1.0).  
**Baseline:** `bench_20260331_2120_3d04` — 6/6 compile, avg score **0.085**; diagnostics `2026-06-11`.  
**Audit docs:** [`escrow_state_report.md`](escrow_state_report.md), [`escrow_layer_diagnosis.md`](escrow_layer_diagnosis.md)

---

## Strategy

Unlike split payment, escrow’s bottleneck is **not** a single hardcoded conservation invariant. Failure classes split as:

- **E (evaluator)** — dominant on `escrow.yaml`
- **D (generation)** — regression `2_escrow`, dual-path / arbiter completeness
- **A (routing)** — failure-case intents only

Phase work is gated:

- **Phase 1A (~1 day):** Evaluator + suite alignment — answer *“Are we measuring the right things?”*
- **Phase 1B (~2 days):** Rails, rules, synthesis — only if 1A proves compile-stable but quality gaps remain on multi-path intents
- **Phase 1C (~1–2 days):** Regression convergence + adversarial routing — after 1A/1B

**Do not start with** NFT golden path changes or covenant lint rewrites.

---

## Diagnostic infrastructure (complete)

| Artifact | Status |
|----------|--------|
| `scripts/diagnose_escrow_case.py` | Done |
| `benchmark/results/escrow_diagnostics/*.json` | Populated 2026-06-11 |
| `docs/escrow_layer_diagnosis.md` | Done |
| `docs/escrow_state_report.md` | Done |

**Decision gate (after 1A):** Rerun `escrow.yaml` 6 cases. If avg final score ≥0.85 with compile ≥5/6 → defer 1B rail expansion. If score <0.5 with compile 6/6 → 1A incomplete. If compile <5/6 → investigate generation (1B) before further evaluator edits.

---

## Phase 1A — Evaluator + suite alignment (~1 day)

**Question:** Are low scores an artifact of bad benchmarks?

### In scope

| Area | Change |
|------|--------|
| `benchmark/suites/escrow.yaml` | Remove `token_validation` from pure BCH cases esc_001–004; align required features with `escrow_suite` (`buyer_signature`, `seller_signature`, `multisig_2of3`, `timelock_refund`) |
| `benchmark/feature_extractor.py` | Treat two+ `checkSig` calls in same function as `multisig` / `multisig_2of2`; alias `arbiter` → `arbitrator_signature` |
| `benchmark/evaluator.py` | Map `multisig` required feature → `multisig` OR `multisig_2of2` OR `multisig_2of3` OR ≥2 `*_signature`; add `escrow` alias pool if needed |
| `benchmark/config/semantic_requirement_map.yaml` | Add `multisig`, `both_signatures_required` mappings |
| Negative cases esc_005/006 | Add `must_fail_*` critical features + evaluator negate scoring (mirror hashlock failure cases) |

### Out of scope

- `pipeline.py` generation changes
- `_ESCROW_RAIL` edits
- Sanity / lint rule changes

### Verification

```bash
python scripts/diagnose_escrow_case.py esc_001 esc_003
python -m benchmark.runner benchmark/suites/escrow.yaml
```

**Success:** avg final score ≥0.85, compile ≥5/6, `escrow_suite.yaml` still ≥9/10 at 1.0.

---

## Phase 1B — Rails, rules, synthesis (~2 days)

**Trigger:** 1A complete but esc_003/esc_004 still show generation gaps (single path, wrong destination branching).

### In scope

| File | Change |
|------|--------|
| `pipeline.py` | Attach `_ESCROW_RAIL` when `effective_mode == "escrow"` OR `"escrow" in tags`; expand rail text for 2-of-3, arbiter, dual `lockingBytecode` |
| `escrow_rules.yaml` | Add branches: `branch_arbitrate`, dual-destination rules, `checkMultiSig` variant |
| `synthesis_rules.yaml` | Add `canonical_escrow_2of2`, `canonical_escrow_2of3_timeout` snippets |
| `pipeline.py` Phase 2 | Optional `ESCROW MODE` covenant_rule block (mirror split Phase 2 branch) for timeout + arbiter intents |

### Out of scope

- Golden `escrow_2of3_nft` path (NFT custody is separate track)
- Evaluator changes unless 1A left gaps

### Verification

```bash
python scripts/diagnose_escrow_case.py all   # expect escrow_rail_loaded ↑
python -m benchmark.runner benchmark/suites/escrow.yaml --ids esc_003,esc_004
```

**Success:** esc_003 has distinct `release` + `reclaim`/`refund`; esc_004 has two functions with distinct destination checks.

---

## Phase 1C — Regression + adversarial routing (~1–2 days)

**Trigger:** Benchmark suites green but `2_escrow` still `compile_exhausted`.

### In scope

| Area | Change |
|------|--------|
| Phase 1 prompt | Stabilize vague “2-of-3 escrow timeout reclaim” → `contract_type: escrow`, signers + `timeout_days` |
| `check_pure_bch_escrow_mismatch` | Do not send adversarial “FAILURE CASE” intents to `semantic_unsupported` |
| `fallback_escrow.cash` | Ensure 2-of-3 + timeout structure for regression path |
| `tests/test_regression.py` | Optional: assert diagnostics flags before full pipeline |

### Verification

```bash
pytest tests/test_regression.py -k 2_escrow
```

---

## Work packages (ordered)

| WP | Description | Phase |
|----|-------------|-------|
| WP0 | Diagnostics + audit docs | Done |
| WP1 | Clean `escrow.yaml` required features | 1A |
| WP2 | Feature extractor multisig + arbiter aliases | 1A |
| WP3 | Evaluator legacy mappings + negative scoring | 1A |
| WP4 | Rerun escrow.yaml gate | 1A |
| WP5 | Expand `_ESCROW_RAIL` + rules | 1B |
| WP6 | Synthesis canonical escrow templates | 1B |
| WP7 | Phase 1 failure-case routing fix | 1C |
| WP8 | Regression `2_escrow` convergence | 1C |

---

## Risk register

| Risk | Mitigation |
|------|------------|
| Fixing evaluator masks real generation gaps | Keep esc_004 dual-path as explicit generation check in 1B |
| Rail over-constrains simple 2-of-2 | Attach expanded rail only when arbiter/threshold>2 or dual-destination detected |
| escrow_suite regression | Run both suites after every WP |
| NFT escrow conflation | Leave `escrow_2of3_nft` golden path unchanged in Phase 1 |

---

## Files to touch (by phase)

**1A:** `benchmark/suites/escrow.yaml`, `benchmark/feature_extractor.py`, `benchmark/evaluator.py`, `benchmark/config/semantic_requirement_map.yaml`  
**1B:** `pipeline.py`, `escrow_rules.yaml`, `synthesis_rules.yaml`  
**1C:** `pipeline.py` (Phase 1), `fallback_escrow.cash`, possibly `sanity_checker.py` for `must_fail_*`

**No changes yet** — implementation waits for explicit approval after this audit.
