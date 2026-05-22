# CashTokens benchmark comparison

- Baseline run: `bench_20260521_1709_5b5f`
- Post run: `bench_20260521_1942_7149`
- Generated: 2026-05-21T14:16:10.418095Z

| Case | Pattern | Baseline | Post | Delta score | Verdict |
|------|---------|----------|------|-------------|---------|
| ct_ft_001 | token_ft | conv=Y score=1.00 | conv=Y score=1.00 | +0.00 | unchanged |
| ct_ft_002 | token_ft | conv=Y score=1.00 | conv=Y score=1.00 | +0.00 | unchanged |
| ct_ft_003 | token_ft | conv=Y score=1.00 | conv=Y score=1.00 | +0.00 | unchanged |
| ct_hybrid_001 | hybrid_token | conv=N score=0.20 | conv=Y score=0.75 | +0.55 | newly-passing |
| ct_hybrid_002 | hybrid_token | conv=N score=0.00 | conv=Y score=1.00 | +1.00 | newly-passing |
| ct_minting_001 | nft_minting | conv=N score=0.20 | conv=Y score=1.00 | +0.80 | newly-passing |
| ct_minting_002 | nft_minting | conv=N score=0.00 | conv=Y score=1.00 | +1.00 | newly-passing |
| ct_minting_003 | nft_minting | conv=N score=0.00 | conv=Y score=1.00 | +1.00 | newly-passing |
| ct_minting_fail_001 | nft_minting | conv=N score=0.00 | conv=N score=0.20 | +0.20 | improved |
| ct_nft_imm_001 | nft_immutable | conv=N score=0.20 | conv=Y score=1.00 | +0.80 | newly-passing |
| ct_nft_imm_002 | nft_immutable | conv=N score=0.00 | conv=Y score=1.00 | +1.00 | newly-passing |
| ct_nft_imm_003 | nft_immutable | conv=N score=0.20 | conv=Y score=1.00 | +0.80 | newly-passing |
| ct_nft_mut_001 | nft_mutable | conv=N score=0.20 | conv=Y score=1.00 | +0.80 | newly-passing |
| ct_nft_mut_002 | nft_mutable | conv=N score=0.20 | conv=Y score=1.00 | +0.80 | newly-passing |
| ct_nft_mut_003 | nft_mutable | conv=N score=0.20 | conv=Y score=1.00 | +0.80 | newly-passing |

## Summary
- Improved: 1
- Newly passing (convergence): 11
- Regressed / newly failing: 0
- Unchanged: 3

- Baseline avg score: 0.293
- Post avg score: 0.930
- Delta avg score: +0.637

## Per-pattern convergence rate
| Pattern | Baseline conv% | Post conv% | Delta |
|---------|----------------|------------|-------|
| hybrid_token | 0% | 100% | +100% |
| nft_immutable | 0% | 100% | +100% |
| nft_minting | 0% | 75% | +75% |
| nft_mutable | 0% | 100% | +100% |
| token_ft | 100% | 100% | +0% |

---

## Run configuration

- **Post (primary):** free synthesis (`disable_golden=True`), run `bench_20260521_1942_7149`, artifact `benchmark/results/cashtokens_postupgrade.json`.
- **Golden:** `python -m benchmark.runner benchmark/suites/cashtokens.yaml --use-golden` → `benchmark/results/cashtokens_postupgrade_golden.json` (see golden diff below when present).

### Post-upgrade pattern matrix (free synthesis)

| Pattern | Compile | Converge | Avg score |
|---------|---------|----------|-----------|
| token_ft | 100% | 100% | 1.00 |
| nft_immutable | 100% | 100% | 1.00 |
| nft_mutable | 100% | 100% | 1.00 |
| nft_minting | 100% | 75% | 0.80 |
| hybrid_token | 100% | 100% | 0.875 |

`ct_minting_fail_001` intentionally does not converge (negative test). All other 14 cases converged.

---

## Golden-enabled run (`--use-golden`)

- Post run: `bench_20260521_1945_3ddc`, artifact `benchmark/results/cashtokens_postupgrade_golden.json`.
- Golden templates accelerate FT/mutable/minting simple cases; hard cases (`ct_ft_003`, `ct_nft_imm_003`, `ct_minting_003`, `ct_hybrid_002`) may still fall back to free synthesis retries.

| Pattern | Compile | Converge | Avg score |
|---------|---------|----------|-----------|
| token_ft | 67% | 67% | 0.667 |
| nft_immutable | 67% | 67% | 0.667 |
| nft_mutable | 100% | 100% | 1.00 |
| nft_minting | 75% | 50% | 0.750 |
| hybrid_token | 50% | 50% | 0.500 |

- Baseline avg score: 0.293 → golden post avg: **0.733** (+0.440).
- **Hard-launch bar (90%+ converge per class):** met on free synthesis; golden path is supplementary until adaptation stability improves on hard cases.