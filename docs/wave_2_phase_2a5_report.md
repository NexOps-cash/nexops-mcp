# Wave 2 Phase 2A.5 — Capability trace validation

**Status:** PASS

## Matrix (12/12)

| Capability | valid | missing_evidence | misleading_lookalike |
|------------|-------|------------------|----------------------|
| enforces_supply_cap | PASS | PASS | PASS |
| preserves_token_category | PASS | PASS | PASS |
| preserves_token_amount | PASS | PASS | PASS |
| capability_retained | PASS | PASS | PASS |

## Golden cross-checks

- `ft_mint_authority.cash` → `enforces_supply_cap`
- `ft_transfer.cash` → `preserves_token_category`, `preserves_token_amount`
- `nft_minting_authority.cash` → `capability_retained`

## Validation

`pytest tests/cashtokens/test_capability_trace_integrity.py -q` → 16 passed

## Next

Phase 2B invalid token logic corpus.
