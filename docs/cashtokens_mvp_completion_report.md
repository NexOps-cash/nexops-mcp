# CashTokens MVP Completion Report (Wave 2)

**Branch:** `cashtokenupgrade`  
**Date:** 2026-05-23

## Summary

| Promise | Before | After | Evidence |
|---------|--------|-------|----------|
| 1. Fungible token mint (supply enforcement) | PARTIALLY | **FULLY** | `ft_mint_authority` golden, `_FT_MINT_RAIL`, `enforces_supply_cap`, `unbounded_mint`, LNC-017 blocking, `cashtokens_ft_mint.yaml`, `test_ft_mint_supply.py` |
| 2. NFT mint + transfer | MOSTLY | **FULLY** | Existing family suites + Wave 2 invalid-logic corpus; audit parity on mint escape |
| 3. Token category validation | MOSTLY | **FULLY** | Stricter `preserves_token_category`, LNC-014, capability trace matrix, `cashtokens_validation.yaml` |
| 4. Token amount validation | MOSTLY | **FULLY** | Same-index amount + `preserves_split_token_supply`, evaluator `fallback: none` |
| 5. Detection of invalid token logic | PARTIALLY | **FULLY** | 8 detectors × secure/vulnerable fixtures, precision/recall 1.0 corpus, negative benchmarks |

## Phase gates

| Phase | Report | Gate |
|-------|--------|------|
| 2A | [wave_2_phase_2a_report.md](wave_2_phase_2a_report.md) | `test_ft_mint_supply.py` |
| 2A.5 | [wave_2_phase_2a5_report.md](wave_2_phase_2a5_report.md) | `test_capability_trace_integrity.py` (16) |
| 2B | (metrics JSON) | `test_cashtokens_invalid_corpus.py` + `cashtokens_detector_metrics.json` |
| 2C | [wave_2_audit_parity_report.md](wave_2_audit_parity_report.md) | `test_audit_parity_token_detectors.py` |
| 2D | [wave_2_phase_2d_report.md](wave_2_phase_2d_report.md) | `test_token_validation_hardening.py` |

## Honest BCH-1 claim

**Yes (narrow):** NexOps can claim the five CashTokens MVP bullets for **generation + deterministic verification** on the covered pattern classes, with mandatory capability trace integrity (2A.5) before detector expansion.

**Caveats:**

- API benchmarks (`cashtokens_ft_mint.yaml`, family suites) require `OPENROUTER_API_KEY` for full convergence evidence.
- Production UI must respect `synthesis.converged` and benchmark-parity controller settings.

## Verification commands

```powershell
cd nexops-mcp
python -m pytest tests/cashtokens/ tests/audit_engine/test_cashtokens_invalid_corpus.py tests/audit_engine/test_audit_parity_token_detectors.py tests/cashtokens/test_capability_trace_integrity.py -q
python scripts/cashtokens_detector_metrics.py
python scripts/audit_generation_parity.py
python scripts/validate_audit_sample.py
```

## Remaining risks

- LLM synthesis variance on API benchmarks (mitigated by rails, goldens, lint, TollGate).
- `cashtokenmvpstatus.md` predates Wave 2; this report supersedes it for completion status.
