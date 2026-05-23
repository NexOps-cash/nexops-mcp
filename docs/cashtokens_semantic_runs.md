# CashTokens semantic benchmark runs

Free synthesis (`disable_golden=True`). **8 in-scope cases** (#1–#8; #9 collateral, #10 LP, #11 stablecoin, #12 auction removed).

Exit gate: **≥6/8 Tier B** (converged = compile + critical_features).

## Wave 1.5 parity — 2026-05-23

**Unit parity (no API):** `pytest tests/test_semantic_capabilities.py tests/cashtokens/test_capability_detectors.py tests/test_invariant_engine_core.py tests/cashtokens/test_evaluator_pools.py` — capability extraction, declarative `satisfies_requirement`, evaluator alias pools, unified enforcer profiles.

**Full semantic/family re-run:** requires `OPENROUTER_API_KEY`. Expect capability traces under `benchmark/results/capability_traces/` per case. Regex fallback paths appear in trace `requirement_results.*.path` as `fallback_regex_alias` when YAML capability predicates miss.

**Known family delta (unchanged):** `ct_mint_family_fail_001` negative-case may fail at compile vs converge — documented in `docs/cashtokens_family_benchmark_report.md`.

## Family benchmarks post–Wave 1 — 2026-05-23

`python scripts/run_family_benchmarks.py` — positive-path families (**FT, immutable, mutable, minting 001–003, hybrid**) match prior **2026-05-22** regression (100% compile & converge where expected).

**Delta:** `ct_mint_family_fail_001` (intentional capability-leak probe) previously **compiled** malformed output (converged N); after structural / lint tightening it often **never reaches compile** (pipeline exhaustion). Aggregate `nft_minting` compile rate **75%** vs prior **100%** — see drift table in `docs/cashtokens_family_benchmark_report.md`.

## Run bench_20260522_1808_5cf6 — 2026-05-22 (cashtokenupgrade)

| Case | Compile | Converged | Coverage | Notes |
|------|---------|-----------|----------|-------|
| semantic_001 | yes | no | 100% | Tier B: missing critical payout/migratory checks in codegen |
| semantic_002 | yes | no | 50% | Soulbound path; evaluator tightened post-run |
| semantic_003–011 | no | no | 0% | OpenRouter 402 insufficient credits after case 2 |

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

Re-run when OpenRouter credits are available: `python scripts/run_semantic_benchmark.py --all`

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

## Run bench_20260522_1908_b2aa — 2026-05-22T13:43:03.242055+00:00


| Case | Compile | Converged | Coverage |
|------|---------|-----------|----------|
| semantic_001 | yes | yes | 100% |
| semantic_002 | yes | yes | 100% |
| semantic_003 | no | no | 0% |
| semantic_004 | no | no | 0% |
| semantic_005 | no | no | 0% |
| semantic_006 | yes | yes | 100% |
| semantic_007 | yes | yes | 100% |
| semantic_008 | no | no | 0% |

**Tier B (converged): 4/8** (gate: ≥6/8)

## Run bench_20260522_1914_sem — 2026-05-22T13:49:02.516975+00:00


| Case | Compile | Converged | Coverage |
|------|---------|-----------|----------|
| semantic_001 | yes | no | 100% |
| semantic_002 | yes | yes | 100% |
| semantic_003 | yes | yes | 100% |
| semantic_004 | yes | yes | 100% |
| semantic_005 | no | no | 0% |
| semantic_006 | yes | yes | 100% |
| semantic_007 | yes | no | 50% |
| semantic_008 | yes | no | 50% |

**Tier B (converged): 4/8** (gate: ≥6/8)

## Run bench_20260522_1919_sem — 2026-05-22T13:52:32.976927+00:00


| Case | Compile | Converged | Coverage |
|------|---------|-----------|----------|
| semantic_001 | no | no | 0% |
| semantic_005 | no | no | 0% |
| semantic_007 | yes | yes | 100% |
| semantic_008 | yes | no | 50% |

**Tier B (converged): 1/4** (gate: ≥6/8)

## Run bench_20260522_1919_sem — 2026-05-22T13:54:10.084144+00:00


| Case | Compile | Converged | Coverage |
|------|---------|-----------|----------|
| semantic_001 | no | no | 0% |
| semantic_002 | yes | yes | 100% |
| semantic_003 | yes | yes | 100% |
| semantic_004 | yes | yes | 100% |
| semantic_005 | no | no | 0% |
| semantic_006 | yes | yes | 100% |
| semantic_007 | yes | yes | 100% |
| semantic_008 | yes | no | 50% |

**Tier B (converged): 5/8** (gate: ≥6/8)

## Run bench_20260522_1919_sem — 2026-05-22T13:56:40.775274+00:00


| Case | Compile | Converged | Coverage |
|------|---------|-----------|----------|
| semantic_001 | yes | yes | 100% |
| semantic_002 | yes | yes | 100% |
| semantic_003 | yes | yes | 100% |
| semantic_004 | yes | yes | 100% |
| semantic_005 | no | no | 0% |
| semantic_006 | yes | yes | 100% |
| semantic_007 | yes | yes | 100% |
| semantic_008 | yes | no | 50% |

**Tier B (converged): 6/8** (gate: ≥6/8)

## Run bench_20260523_0817_sem — 2026-05-23T08:18:33.688588+00:00


| Case | Compile | Converged | Coverage |
|------|---------|-----------|----------|
| semantic_001 | yes | yes | 100% |
| semantic_002 | yes | yes | 100% |
| semantic_003 | yes | yes | 100% |
| semantic_004 | yes | yes | 100% |
| semantic_005 | yes | yes | 100% |
| semantic_006 | yes | yes | 100% |
| semantic_007 | yes | yes | 100% |
| semantic_008 | yes | yes | 100% |

**Tier B (converged): 8/8** (gate: ≥6/8)
