# CashTokens family benchmark report

Generated: 2026-05-23T09:11:18.713443+00:00

Configuration: **free synthesis** (`disable_golden=True`), `security_level=high` via benchmark evaluator.

---

## token_ft

- Suite: `benchmark/suites/cashtokens_ft.yaml`
- Run ID: `bench_20260523_1437_bc3d`
- Cases: 3
- Compile rate: **100%**
- Convergence rate: **100%**
- Avg final score: **1.000**
- Artifact: `benchmark/results/cashtokens_ft_family.json`

| Case | Compile | Converged | Score | Latency (s) | Notes |
|------|---------|-----------|-------|-------------|-------|
| ct_ft_family_001 | Y | Y | 1.00 | 16.0 |  |
| ct_ft_family_002 | Y | Y | 1.00 | 9.7 |  |
| ct_ft_family_003 | Y | Y | 1.00 | 20.8 |  |

## nft_immutable

- Suite: `benchmark/suites/cashtokens_nft_immutable.yaml`
- Run ID: `bench_20260523_1438_d98a`
- Cases: 3
- Compile rate: **100%**
- Convergence rate: **100%**
- Avg final score: **1.000**
- Artifact: `benchmark/results/cashtokens_nft_immutable_family.json`

| Case | Compile | Converged | Score | Latency (s) | Notes |
|------|---------|-----------|-------|-------------|-------|
| ct_imm_family_001 | Y | Y | 1.00 | 10.7 |  |
| ct_imm_family_002 | Y | Y | 1.00 | 10.8 |  |
| ct_imm_family_003 | Y | Y | 1.00 | 9.9 |  |

## nft_mutable

- Suite: `benchmark/suites/cashtokens_nft_mutable.yaml`
- Run ID: `bench_20260523_1438_8e2b`
- Cases: 3
- Compile rate: **100%**
- Convergence rate: **100%**
- Avg final score: **1.000**
- Artifact: `benchmark/results/cashtokens_nft_mutable_family.json`

| Case | Compile | Converged | Score | Latency (s) | Notes |
|------|---------|-----------|-------|-------------|-------|
| ct_mut_family_001 | Y | Y | 1.00 | 11.7 |  |
| ct_mut_family_002 | Y | Y | 1.00 | 12.8 |  |
| ct_mut_family_003 | Y | Y | 1.00 | 12.1 |  |

## nft_minting

- Suite: `benchmark/suites/cashtokens_nft_minting.yaml`
- Run ID: `bench_20260523_1439_9006`
- Cases: 4
- Compile rate: **75%**
- Convergence rate: **75%**
- Avg final score: **0.750**
- Artifact: `benchmark/results/cashtokens_nft_minting_family.json`

| Case | Compile | Converged | Score | Latency (s) | Notes |
|------|---------|-----------|-------|-------------|-------|
| ct_mint_family_001 | Y | Y | 1.00 | 11.3 |  |
| ct_mint_family_002 | Y | Y | 1.00 | 11.4 |  |
| ct_mint_family_003 | Y | Y | 1.00 | 12.0 |  |
| ct_mint_family_fail_001 | N | N | 0.00 | 42.7 | Compile |

## hybrid_token

- Suite: `benchmark/suites/cashtokens_hybrid.yaml`
- Run ID: `bench_20260523_1440_e56b`
- Cases: 2
- Compile rate: **100%**
- Convergence rate: **100%**
- Avg final score: **0.875**
- Artifact: `benchmark/results/cashtokens_hybrid_family.json`

| Case | Compile | Converged | Score | Latency (s) | Notes |
|------|---------|-----------|-------|-------------|-------|
| ct_hybrid_family_001 | Y | Y | 0.75 | 27.6 | missing: signature_verification |
| ct_hybrid_family_002 | Y | Y | 1.00 | 17.0 |  |

## Summary across families

| Family | Compile | Converge | Avg score |
|--------|---------|----------|-----------|
| token_ft | 100% | 100% | 1.000 |
| nft_immutable | 100% | 100% | 1.000 |
| nft_mutable | 100% | 100% | 1.000 |
| nft_minting | 75% | 75% | 0.750 |
| hybrid_token | 100% | 100% | 0.875 |

---

## Baseline drift check (Wave 1 vs 2026-05-22 family report)

Compared to the archived run dated **2026-05-22** in git history (`bench_20260522_*`):

| Area | Expected | This run (`bench_20260523_*`) | Verdict |
|------|-----------|-------------------------------|---------|
| `token_ft` (3 cases) | 100% compile & converge | **100% / 100%** | OK |
| `nft_immutable` (3 cases) | 100% compile & converge | **100% / 100%** | OK |
| `nft_mutable` (3 cases) | 100% compile & converge | **100% / 100%** | OK |
| `hybrid_token` (2 cases) | 100% compile & converge; 001 score ~0.75 | **Matches** | OK |
| `nft_minting` positive paths (001–003) | 100% compile & converge | **100% / 100%** | OK |
| `ct_mint_family_fail_001` (failure / capability leak probe) | **Compile Y**, converge N, score ~0.20 | **Compile N**, converge N — pipeline exhausted (`disable_fallbacks`) | **Drift**: negative case no longer yields compileable leaky output; aggregate minting compile rate becomes **75%** (was 100%) |

**Production-relevant takeaway:** CashTokens **five family positive suites** match prior behavior for merge confidence. Treat the minting **failure** probe separately (benchmark design vs “must emit bad code”), or rerun if you require identical aggregate percentages including the negative fixture.
