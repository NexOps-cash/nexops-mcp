# CashTokens semantic benchmark runs

Free synthesis (`disable_golden=True`). LP (#10) excluded from the 11-case suite.

Exit gate: **≥7/11 Tier B** (converged = compile + critical_features).

## Run bench_20260522_1808_5cf6 — 2026-05-22 (cashtokenupgrade)

| Case | Compile | Converged | Coverage | Notes |
|------|---------|-----------|----------|-------|
| semantic_001 | yes | no | 100% | Tier B: missing critical payout/migratory checks in codegen |
| semantic_002 | yes | no | 50% | Soulbound path; evaluator tightened post-run |
| semantic_003–011 | no | no | 0% | LLM fallback exhaustion (OpenRouter 402 / Groq) after case 2 |

**Tier B (converged): 0/11** on this run — infrastructure-limited, not semantic-layer complete.

### 12-prompt reliability scorecard (plan expectation vs this run)

| # | Prompt | Plan tier | This run |
|---|--------|-----------|----------|
| 1 | NFT Escrow | Often | Compile only |
| 2 | Soulbound | Reliable | Compile only |
| 3 | Burnable | Reliable | API fail |
| 4 | Treasury | Flaky | API fail |
| 5 | Marketplace | Reliable | API fail |
| 6 | Capped mint | Often | API fail |
| 7 | Streaming | Flaky | API fail |
| 8 | Voucher | Often | API fail |
| 9 | Collateral | Not v1 | API fail |
| 10 | LP | Excluded | — |
| 11 | Stablecoin | Not v1 | API fail |
| 12 | Auction | Not v1 | API fail |

Re-run when OpenRouter/Groq credits are available: `python scripts/run_semantic_benchmark.py --all`

### Family regression (same session)

Family suite re-run hit **OpenRouter 402 insufficient credits** mid-`nft_immutable`. Prior family results on `cashtokenupgrade` remain the regression baseline until credits are restored.

## Run bench_20260522_1808_5cf6 — 2026-05-22T12:40:38.918131+00:00


| Case | Compile | Converged | Coverage |
|------|---------|-----------|----------|
| semantic_001 | yes | no | 100% |
| semantic_002 | yes | no | 50% |
| semantic_003 | no | no | 0% |
| semantic_004 | no | no | 0% |
| semantic_005 | no | no | 0% |
| semantic_006 | no | no | 0% |
| semantic_007 | no | no | 0% |
| semantic_008 | no | no | 0% |
| semantic_009 | no | no | 0% |
| semantic_010 | no | no | 0% |
| semantic_011 | no | no | 0% |

**Tier B (converged): 0/11** (gate: ≥7/11)

## Run bench_20260522_1811_2bd4 — 2026-05-22T12:41:13.813622+00:00


| Case | Compile | Converged | Coverage |
|------|---------|-----------|----------|
| semantic_002 | no | no | 0% |

**Tier B (converged): 0/1** (gate: ≥7/11)
