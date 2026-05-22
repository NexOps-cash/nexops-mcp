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

## Experimental (v1 — not gated)

- Treasury governance (#4), streaming (#7) — flaky
- Collateral receipt (#9), stablecoin authority (#10), auction (#11) — Tier D
- LP (#10 original list) — **removed** from v1

## Exit gate

≥7/11 semantic benchmark cases converged (compile + critical_features). See `docs/cashtokens_semantic_runs.md`.
