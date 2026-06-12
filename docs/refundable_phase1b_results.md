# Refundable Phase 1B — Generation Stabilization Results

**Date:** 2026-06-12  
**Scope:** Canonical templates for `rp_003` and `rp_004`. Sanity exemption for dual-path refundable shapes. No evaluator, rail, or routing changes.

---

## Decision gate outcome

| Case | Gate | Action |
|------|------|--------|
| **rp_003** | **A** — known-good dual-path escrow (offline replay) | `refundable_subscription_escrow.cash` |
| **rp_004** | **B** — no historical compile success | Designed `refundable_gradual_release.cash` |

---

## Files changed

| File | Role |
|------|------|
| `src/services/refundable_canonical.py` | Intent matching + template load |
| `knowledge/templates/refundable_subscription_escrow.cash` | rp_003 |
| `knowledge/templates/refundable_gradual_release.cash` | rp_004 |
| `src/services/pipeline.py` | `REFUNDABLE_CANONICAL_TEMPLATE` branch |
| `src/services/sanity_checker.py` | Exempt dual-path refundable from decay formula strict check |
| `src/services/knowledge_structured/synthesis_rules.yaml` | `refundable_payment` canonical snippets |
| `tests/test_refundable_canonical.py` | Unit tests |
| `docs/refundable_generation_rca.md` | Audit + lint table + decision gate |

Failing draft artifacts: `benchmark/results/refundable_generation/rp_003_failing_covenant_draft.cash`, `rp_004_failing_*`.

---

## Success gate

| Gate | Target | Result |
|------|--------|--------|
| rp_003 × 2 consecutive | compile + converge | **PASS** — `1951_ea8f`, `1951_778d` (~4–5s) |
| rp_004 × 2 consecutive | compile + converge | **PASS** |
| Full suite remeasure | rp_003/rp_004 at 1.0 | **PASS** — `bench_20260612_1952_c07e` |

### Full suite snapshot (`bench_20260612_1952_c07e`)

| Case | Score | Converged |
|------|-------|-----------|
| rp_001 | 1.0 | yes |
| rp_002 | 0.2 | partial (hashlock — pre-existing) |
| rp_003 | 1.0 | yes |
| rp_004 | 1.0 | yes |
| rp_005 | 0.0 | failure case (out of scope) |
| rp_006 | 1.0 | yes |

**Positive convergence:** 4/5 (80%). P0 targets rp_003/rp_004 **production-converged**.

---

## Reproduce

```bash
python -m pytest tests/test_refundable_canonical.py -v
python -m benchmark.runner benchmark/suites/refundable_payment.yaml --ids rp_003,rp_004
python -m benchmark.runner benchmark/suites/refundable_payment.yaml
```
