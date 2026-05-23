# CashTokens semantic constraint layers (v1)

NexOps Phase 1 extracts four composable fields on `IntentModel`:

| Field | Values |
|-------|--------|
| `ownership_mode` | transferable, soulbound, covenant_retained, delegated |
| `lifecycle_mode` | persistent, terminating, state_transition, migratory |
| `supply_mode` | fixed, capped_mint, burnable, redeemable |
| `commitment_schema` | opaque, expiry, governance |

Deterministic normalization in `semantic_normalization.py` overrides LLM drift after CashToken class routing. Phase 1 uses **Claude Haiku 4.5** on OpenRouter by default for sharper tag/semantic JSON. `resolve_semantic_constraints()` in `semantic_profiles.py` resolves known conflicts (e.g. soulbound + migratory → state_transition).

## Supported for demos (target Tier B)

- Soulbound NFT (#2)
- Burnable token (#3)
- Marketplace listing (#5)
- Often: escrow (#1), capped mint (#6), voucher (#8)

## Out of benchmark suite (deferred)

- Treasury governance (#4), streaming (#7) — in suite but may be flaky
- Removed from suite: collateral (#9), LP (#10), stablecoin authority (#11), auction (#12)

## Exit gate

**≥6/8** in-scope cases converged (compile + critical_features). See `docs/cashtokens_semantic_runs.md`.

## Wave 1.5 (invariant unification)

Shared semantic capabilities drive benchmark `satisfies()` (declarative YAML), capability traces, and high-priority detectors. See `docs/wave_1_5_semantic_invariant_unification.md`. **Wave 2 expansion remains frozen.**

## Wave 1 freeze (stabilization)

Semantic expansion is **paused**. No new semantic fields, LP/proportional supply, authority-model expansion, or cross-contract reasoning until:

- `semantic_005` compiles consistently (structural repair + marketplace rail)
- `semantic_008` reaches Tier B (evaluator redeem burn calibration)
- Family benchmarks stable on **positive** paths (done 2026-05-23 — see `docs/cashtokens_family_benchmark_report.md`)

Pipeline focus: `structural_integrity.py`, compile-repair observability under `benchmark/results/repair_debug/`, and `tests/test_structural_integrity.py`. See `docs/semantic_005_008_investigation.md`.
