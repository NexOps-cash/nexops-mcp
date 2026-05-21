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
- **No FT genesis** or BCMR metadata generation.
- **Minting / hybrid** may need retries on hard intents; use `security_level="high"` and golden templates when available.
- **Golden adaptation** applies only to registered templates under `knowledge/golden/patterns/`.

## Reproduce benchmark numbers

From `nexops-mcp/` with API keys in `.env` (`OPENROUTER_API_KEY` or `GROQ_API_KEY`):

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
