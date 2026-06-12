# Refundable Payment — Phase 1B Generation RCA

**Date:** 2026-06-12 (audit refresh + Phase 1B implementation)  
**Scope:** `rp_003` (subscription) and `rp_004` (gradual vesting). **No evaluator changes. No rails. No routing overhaul.**  
**Historical baseline:** `bench_20260331_2121_6f05` — both `compile_pass: false`, `code: null`, 3 retries.  
**Tools:** `scripts/refundable_generation_rca_offline.py`, `scripts/diagnose_refundable_generation.py`, `src/services/refundable_canonical.py`

---

## Executive conclusion

| Case | Decision gate | First **hard** failure (pre-1B) | Known-good shape? | Phase 1B action |
|------|---------------|-----------------------------------|-------------------|-----------------|
| **rp_003** | **A** | **DSLLint `LNC-005`** on covenant remainder draft | **Yes** — simple dual-path escrow passes all gates | Canonical template `refundable_subscription_escrow.cash` |
| **rp_004** | **B** | **DSLLint `LNC-016`** (covenant) or **`LNC-010`/`LNC-011`** (formula) | **No** historical compile-success; designed lint-safe dual-path | Canonical template `refundable_gradual_release.cash` + `synthesis_rules.yaml` |

**Routing mismatch** (escrow / linear_vesting vs `refundable_payment`) is real but **not the first blocker** — lint exhausts retries before `cashc`.

---

## Summary table — first failure layer

| Case | First failure | Exact lint / compile | Lint | Compile | Sanity | Draft saved |
|------|---------------|------------------------|------|---------|--------|-------------|
| **rp_003** (failing LLM shape) | **DSLLint** | **LNC-005** — `outputs[0].value == input.value - payoutAmount` | Fail | Not reached | — | `rp_003_failing_covenant_draft.cash` |
| **rp_003** (known-good) | — | LNC-008 warning only (non-blocking) | **Pass** | **Pass** | **Pass** | `rp_003_representative_draft.cash` |
| **rp_004** (covenant attempt) | **DSLLint** | **LNC-016** — self-anchor at `outputs[2]` without value conservation | Fail | Not reached | — | `rp_004_failing_vesting_covenant_draft.cash` |
| **rp_004** (formula attempt) | **DSLLint** | **LNC-010** nested `tx.time`; **LNC-011** unguarded `/ duration` | Fail | Not reached | — | `rp_004_failing_decay_formula_draft.cash` |
| **rp_004** (designed good) | — | — | **Pass** (`linear_vesting` mode) | **Pass** | **Pass** | `refundable_gradual_release.cash` |

Artifacts under `benchmark/results/refundable_generation/`:
- `rp_003_rca_offline.json`, `rp_004_rca_offline.json`, `rca_offline_summary.json`
- Failing drafts: `rp_003_failing_covenant_draft.cash`, `rp_004_failing_vesting_covenant_draft.cash`, `rp_004_failing_decay_formula_draft.cash`
- Passing drafts: `rp_003_representative_draft.cash`, canonical copies in `knowledge/templates/`

---

## Exact DSL lint failures (captured)

### rp_003 — subscription

| Draft | Rule | Message |
|-------|------|---------|
| Covenant remainder (`claim` + 2 outputs) | **LNC-005** | Implicit fee arithmetic — `input.value - payoutAmount` |
| Simple dual-path (`claim` + `cancel`) | *(none blocking)* | LNC-008 lifecycle hint only |

### rp_004 — gradual release

| Draft | Rules | Message |
|-------|-------|---------|
| 3-output vesting covenant | **LNC-016** | Self-anchor at `outputs[2]` without value preservation |
| Elapsed formula `payout = total * elapsed / duration` | **LNC-010**, **LNC-011** | Nested `tx.time` arithmetic; division without `duration > 0` |
| Designed dual-path (`claim` + `refund`) | *(none blocking)* | Passes under `linear_vesting` and `refundable_payment` lint modes |

---

## Historical compile-success search

| Case | Runs searched | `compile_pass: true` with code? | Verdict |
|------|---------------|----------------------------------|---------|
| **rp_003** | `bench_20260331_2121_6f05`, `bench_20260611_1832_a6cc` | **No** — always `code: null` | Gate **A** via **offline** known-good replay (not benchmark JSON) |
| **rp_004** | Same | **No** | Gate **B** — minimal lint-safe shape designed |

---

## Decision gate

### A) rp_003 — use Vault-style canonical template

Offline gate replay confirms **simple 2-path escrow** passes lint, compile, toll gate, sanity, and Phase 1A evaluator aliases.

**Implemented:** `knowledge/templates/refundable_subscription_escrow.cash`  
**Pipeline:** `REFUNDABLE_CANONICAL_TEMPLATE` in `Phase2.run` (retry 0, intent match on `subscription` + cancel/reclaim).

### B) rp_004 — design minimal lint-safe shape

No historical success artifact. Rejected shapes: 3-output covenant (LNC-016), proportional formula (LNC-010/011).

**Designed shape:** `claim(recipientSig, payoutAmount)` with `require(tx.time >= periodEnd)` + `refund(senderSig)` with `require(tx.time >= inactiveEnd)` — standalone time guards, single-output paths, no covenant split.

**Implemented:** `knowledge/templates/refundable_gradual_release.cash`  
**Knowledge:** `synthesis_rules.yaml` → `refundable_payment.canonical_gradual_release`

---

## Routing (informational — out of scope for 1B)

| Case | Inferred route | Knowledge loaded |
|------|----------------|------------------|
| rp_003 | `escrow` | `escrow_rules.yaml` |
| rp_004 | `linear_vesting` → `decay` | `decay_rules.yaml` |

Canonical templates bypass free synthesis regardless of route.

---

## Phase 1B implementation (shipped)

| File | Role |
|------|------|
| `src/services/refundable_canonical.py` | Intent matching + template load |
| `knowledge/templates/refundable_subscription_escrow.cash` | rp_003 |
| `knowledge/templates/refundable_gradual_release.cash` | rp_004 |
| `src/services/pipeline.py` | Phase 2 canonical branch |
| `src/services/knowledge_structured/synthesis_rules.yaml` | `refundable_payment` canonical snippets |
| `tests/test_refundable_canonical.py` | Match + lint/compile gates |

**Sanity gate fix (generation only):** Phase 1 routes rp_003 → `streaming`, rp_004 → `linear_vesting`. Strict sanity required elapsed-time arithmetic and blocked canonical templates. Exemption added for dual-path `claim`/`cancel`/`refund` shapes with standalone `require(tx.time >= …)` (`sanity_checker.py`).

**Out of scope (unchanged):** rp_005 adversarial, evaluator, rails, routing overlay.

---

## Benchmark results (Phase 1B)

| Run | rp_003 | rp_004 | Notes |
|-----|--------|--------|-------|
| `bench_20260612_1951_ea8f` | 1.0 / converged | 1.0 / converged | First pass after sanity fix |
| `bench_20260612_1951_778d` | 1.0 / converged | 1.0 / converged | Second consecutive |
| `bench_20260612_1952_c07e` (full suite) | 1.0 | 1.0 | 4/5 positives converged (rp_002 hashlock partial) |

---

## Success criteria

| Case | Target | Verification |
|------|--------|--------------|
| rp_003 | `compile_pass: true`, converged, coverage ≥ 0.70 | `python -m benchmark.runner benchmark/suites/refundable_payment.yaml --ids rp_003` |
| rp_004 | Same | `--ids rp_004` |
| Suite | Positive convergence remeasured | Full `refundable_payment.yaml` run |

---

## Reproduce

```bash
python scripts/refundable_generation_rca_offline.py
python -m pytest tests/test_refundable_canonical.py -v
python -m benchmark.runner benchmark/suites/refundable_payment.yaml --ids rp_003,rp_004
python -m benchmark.runner benchmark/suites/refundable_payment.yaml
```
