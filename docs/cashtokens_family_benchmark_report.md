# CashTokens family benchmark report

Generated: 2026-05-22T11:58:13.854654+00:00

Configuration: **free synthesis** (`disable_golden=True`), `security_level=high` via benchmark evaluator.

---

## token_ft

- Suite: `benchmark/suites/cashtokens_ft.yaml`
- Run ID: `bench_20260522_1724_ca7d`
- Cases: 3
- Compile rate: **100%**
- Convergence rate: **100%**
- Avg final score: **1.000**
- Artifact: `benchmark/results/cashtokens_ft_family.json`

| Case | Compile | Converged | Score | Latency (s) | Notes |
|------|---------|-----------|-------|-------------|-------|
| ct_ft_family_001 | Y | Y | 1.00 | 12.4 |  |
| ct_ft_family_002 | Y | Y | 1.00 | 11.9 |  |
| ct_ft_family_003 | Y | Y | 1.00 | 12.7 |  |

## nft_immutable

- Suite: `benchmark/suites/cashtokens_nft_immutable.yaml`
- Run ID: `bench_20260522_1724_8721`
- Cases: 3
- Compile rate: **100%**
- Convergence rate: **100%**
- Avg final score: **1.000**
- Artifact: `benchmark/results/cashtokens_nft_immutable_family.json`

| Case | Compile | Converged | Score | Latency (s) | Notes |
|------|---------|-----------|-------|-------------|-------|
| ct_imm_family_001 | Y | Y | 1.00 | 12.7 |  |
| ct_imm_family_002 | Y | Y | 1.00 | 9.3 |  |
| ct_imm_family_003 | Y | Y | 1.00 | 12.8 |  |

## nft_mutable

- Suite: `benchmark/suites/cashtokens_nft_mutable.yaml`
- Run ID: `bench_20260522_1725_7a0b`
- Cases: 3
- Compile rate: **100%**
- Convergence rate: **100%**
- Avg final score: **1.000**
- Artifact: `benchmark/results/cashtokens_nft_mutable_family.json`

| Case | Compile | Converged | Score | Latency (s) | Notes |
|------|---------|-----------|-------|-------------|-------|
| ct_mut_family_001 | Y | Y | 1.00 | 11.4 |  |
| ct_mut_family_002 | Y | Y | 1.00 | 11.8 |  |
| ct_mut_family_003 | Y | Y | 1.00 | 16.0 |  |

## nft_minting

- Suite: `benchmark/suites/cashtokens_nft_minting.yaml`
- Run ID: `bench_20260522_1726_99ef`
- Cases: 4
- Compile rate: **100%**
- Convergence rate: **75%**
- Avg final score: **0.800**
- Artifact: `benchmark/results/cashtokens_nft_minting_family.json`

| Case | Compile | Converged | Score | Latency (s) | Notes |
|------|---------|-----------|-------|-------------|-------|
| ct_mint_family_001 | Y | Y | 1.00 | 17.5 |  |
| ct_mint_family_002 | Y | Y | 1.00 | 13.1 |  |
| ct_mint_family_003 | Y | Y | 1.00 | 30.9 |  |
| ct_mint_family_fail_001 | Y | N | 0.20 | 16.8 |  |

## hybrid_token

- Suite: `benchmark/suites/cashtokens_hybrid.yaml`
- Run ID: `bench_20260522_1727_d929`
- Cases: 2
- Compile rate: **100%**
- Convergence rate: **100%**
- Avg final score: **0.875**
- Artifact: `benchmark/results/cashtokens_hybrid_family.json`

| Case | Compile | Converged | Score | Latency (s) | Notes |
|------|---------|-----------|-------|-------------|-------|
| ct_hybrid_family_001 | Y | Y | 0.75 | 14.3 | missing: signature_verification |
| ct_hybrid_family_002 | Y | Y | 1.00 | 40.0 |  |

## Summary across families

| Family | Compile | Converge | Avg score |
|--------|---------|----------|-----------|
| token_ft | 100% | 100% | 1.000 |
| nft_immutable | 100% | 100% | 1.000 |
| nft_mutable | 100% | 100% | 1.000 |
| nft_minting | 100% | 75% | 0.800 |
| hybrid_token | 100% | 100% | 0.875 |
