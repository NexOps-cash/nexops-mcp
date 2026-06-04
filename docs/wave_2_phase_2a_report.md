# Wave 2 Phase 2A — FT mint + supply enforcement

**Status:** PASS (unit gate)

## Delivered

- `ft_mint_authority` golden, `_FT_MINT_RAIL`, intent routing, semantic FT/NFT capped_mint split
- Capability `enforces_supply_cap` (require-scoped, not bare `maxSupply` fields)
- Detector `unbounded_mint`, LNC-017 blocking for `capped_mint` / `ft_mint*`
- Benchmark suite `benchmark/suites/cashtokens_ft_mint.yaml` (3 positive + 1 failure)
- Tests `tests/cashtokens/test_ft_mint_supply.py` (9/9)

## Validation

```text
pytest tests/cashtokens/test_ft_mint_supply.py -q  → 9 passed
```

API benchmark run (`cashtokens_ft_mint.yaml`) requires `OPENROUTER_API_KEY` — run before production sign-off.

## Next

Phase **2A.5** capability trace matrix (mandatory before 2B).
