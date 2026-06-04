# CashTokens generation (hard launch)

NexOps generates **compilable CashScript ^0.13** contracts for five CashToken pattern classes. This document describes supported intents, pipeline guarantees, limitations, and how to reproduce benchmark evidence.

## Supported intents

| Class | `contract_type` / mode | Example phrases that route correctly |
|-------|------------------------|--------------------------------------|
| FT transfer | `token_ft` / `ft_transfer` | "transfer fungible tokens", "FT payout with change" |
| Immutable NFT | `nft_immutable` / `nft_transfer_immutable` | "transfer immutable NFT", "P2PK NFT send" |
| Mutable NFT | `nft_mutable` / `nft_mutable_state_update` | "update NFT commitment", "mutable NFT state" |
| Minting authority | `nft_minting` / `nft_minting_authority` | "mint new NFTs", "PFP drop with locked minting authority" |
| Hybrid vault | `hybrid_token` / `stablecoin_minter_sidecar` | "stateful token vault", "stablecoin minter sidecar", "hybrid FT + NFT state" |

Routing is deterministic in `apply_cashtoken_intent_routing()` (immutable → hybrid → minting → mutable → FT). A `cashtoken_routed` guard prevents vault/vesting golden templates from stealing hybrid or minting intents.

## What is generated

- **Output:** `.cash` source that passes the **cashc 0.13 compile gate** when the pipeline converges.
- **Phase 1:** Intent model + CashToken class routing.
- **Phase 2:** Pattern rails (`_FT_RAIL`, `_NFT_*_RAIL`, `_HYBRID_RAIL`), YAML knowledge, optional golden template adaptation.
- **DSL lint:** LNC-008/017/018/020–025 and mode-specific profiles (`pattern_profiles.py`).
- **Sanity check:** Feature evidence; multisig accountancy **skipped** for `hybrid_token`, `nft_minting_authority`, and related covenant modes.
- **Phase 3 toll gate:** Structural score + `MintingAuthorityEscapeDetector` for minting paths.

## Limitations (read before mainnet use)

- **Not audited.** Generated code is a starting point; human review is required.
- **Not mainnet-ready by default.** Deployment gate (audit score) is separate from benchmark convergence.
- **FT capped mint** via `ft_mint_authority` golden, `_FT_MINT_RAIL`, and `cashtokens_ft_mint.yaml` benchmarks (Wave 2A).
- **No BCMR metadata** generation.
- **Minting / hybrid** may need retries on hard intents; use `security_level="high"` and golden templates when available.
- **Golden adaptation** applies only to registered templates under `knowledge/golden/patterns/`.

## CLI: prompt → generated contract

From `nexops-mcp/` with API keys in `.env`:

```powershell
python scripts/generate.py "PFP drop: minting authority 0x02 must stay in this.activeBytecode"
python scripts/generate.py -p "loyalty points fungible token transfer" --out Loyalty.cash
python scripts/generate.py -p "stateful token vault five-point covenant" --code-only
```

Use `--golden` to enable golden templates (default is free synthesis, same as the benchmark).

The **WebSocket `/ws/generate` API** uses the same defaults as the benchmark evaluator: free synthesis, no secure fallback, three attempts. Responses include `data.synthesis` (`converged`, `fallback_used`, `attempt_number`, etc.). Legacy behavior: `context.allow_fallback: true` or `context.benchmark_synthesis: false`.

## Reproduce benchmark numbers

From `nexops-mcp/` with `OPENROUTER_API_KEY` in `.env`. Phase 1 defaults to `anthropic/claude-haiku-4.5` (override with `OPENROUTER_PHASE1_MODEL`; fallback `OPENROUTER_PHASE1_FALLBACK_MODEL`):

```powershell
# Free synthesis (no golden)
python -m benchmark.runner benchmark/suites/cashtokens.yaml

# Golden-enabled pass
python -m benchmark.runner benchmark/suites/cashtokens.yaml --use-golden

# Compare to baseline
python -m benchmark.compare benchmark/results/cashtokens_baseline.json benchmark/results/cashtokens_postupgrade_golden.json
```

Subset run (faster):

```powershell
python -m benchmark.runner benchmark/suites/cashtokens.yaml --ids ct_hybrid_002,ct_minting_003
```

Unit tests (no API keys):

```powershell
python -m pytest tests/cashtokens/ -q --ignore=tests/cashtokens/test_generation_e2e.py
python scripts/check_cash_compile.py
```

See [`cashtokens_benchmark.md`](cashtokens_benchmark.md) for the latest baseline vs post-upgrade diff.

## Semantic constraint layers (v1)

Phase 1 also extracts `ownership_mode`, `lifecycle_mode`, `supply_mode`, and `commitment_schema` (see [`cashtokens_semantic_layers.md`](cashtokens_semantic_layers.md)). Normalization runs after CashToken class routing; lint and Phase 2 rails are lifecycle-aware.

11 real-world prompts (LP excluded):

```powershell
python scripts/run_semantic_benchmark.py --all
python scripts/run_semantic_benchmark.py --ids semantic_002 semantic_005
```

Results: [`cashtokens_semantic_runs.md`](cashtokens_semantic_runs.md). Exit gate: **≥7/11 converged** with API credits available.
