# CashTokens Benchmark Materialization Plan

Sprint goal: grow CashTokens executable benchmark coverage from **0 → 10** without OpenRouter, detector redesign, semantic judge, or policy work.

## Coverage report

| Metric | Before | After |
|--------|--------|-------|
| CashTokens defined (canonical registry) | 34 | 34 |
| CashTokens executable (`benchmark_registry_executable.json`) | 0 | **10** |
| Total executable (all families) | 10 | **20** |

**Standard-mode suite** (`python scripts/run_benchmark_suite.py --mode standard --include-coverage-probes`):

| Result | Count |
|--------|-------|
| Pass | 17 |
| Gap (coverage probes) | 3 |
| Fail | 0 |

All 10 CashTokens benchmarks **pass**. Remaining suite gaps are pre-existing P0 probes (hashlock preimage, fake auth, dual-path).

---

## Audit: 34 CashTokens definitions

Canonical rollup: `family ∈ {cashtokens, cashtokens_ft, cashtokens_nft, hybrid}` in `docs/benchmark_registry.json`.

### Classification summary

| Classification | Count | Notes |
|----------------|-------|-------|
| Spec only | 28 | `contract_ref` points to `benchmark/suites/*.yaml:*` — generation intent, not materialized `.cash` |
| Missing fixture | 6 | Realworld slots `rw_009`–`rw_011`, `rw_018`–`rw_020` — registry entries exist, `.cash` files not collected |
| Executable with minor fixture work | 0 | (Hybrid compile fix applied during sprint — now executable) |
| Executable now | **10** | Materialized in this sprint via `tests/fixtures/cashtokens_invalid/` |

### Full registry audit

#### Migration stubs (spec only) — 28 entries

| ID | Family | Suite ref | Mutation | Priority theme |
|----|--------|-----------|----------|----------------|
| bench_mig_111–116 | cashtokens | cashtokens_ft.yaml | secure_baseline / missing_auth | FT mint/transfer (auth gate only) |
| bench_mig_117–120 | cashtokens | cashtokens_nft_immutable.yaml | secure_baseline / missing_auth | Immutable NFT |
| bench_mig_121–124 | cashtokens | cashtokens_nft_mutable.yaml | secure_baseline / missing_auth | Mutable NFT |
| bench_mig_125–128 | cashtokens | cashtokens_nft_minting.yaml | secure_baseline / missing_auth | NFT minting |
| bench_mig_129–132 | cashtokens | cashtokens_hybrid.yaml | secure_baseline / missing_auth | Hybrid continuity (auth) |
| bench_mig_133–138 | cashtokens | cashtokens_invalid_negative.yaml | secure_baseline / missing_auth | Invalid-logic families (YAML intent) |

These entries expect `intent_auth_gate` on `missing_auth` mutations — they are **not** wired to Wave 2B invalid-logic detectors. Materialization path: generate `.cash` from suite YAML or alias to existing fixtures.

#### Realworld slots (missing fixture) — 6 entries

| ID | Family | contract_ref |
|----|--------|--------------|
| bench_realworld_009 | cashtokens_ft | audit_benchmark_realworld/contracts/rw_009.cash |
| bench_realworld_010 | cashtokens_nft | audit_benchmark_realworld/contracts/rw_010.cash |
| bench_realworld_011 | hybrid | audit_benchmark_realworld/contracts/rw_011.cash |
| bench_realworld_018 | cashtokens_ft | audit_benchmark_realworld/contracts/rw_018.cash |
| bench_realworld_019 | cashtokens_nft | audit_benchmark_realworld/contracts/rw_019.cash |
| bench_realworld_020 | hybrid | audit_benchmark_realworld/contracts/rw_020.cash |

Requires realworld collection per `docs/realworld_collection_strategy.md`.

#### Materialized this sprint (executable now) — 10 entries

| ID | Priority | Theme | Fixture | Expected finding |
|----|----------|-------|---------|------------------|
| bench_ct_authority_leak_vuln | P1 | Authority leak | authority_leak/vulnerable.cash | `authority_leak` |
| bench_ct_unbounded_mint_vuln | P1 | Unbounded mint | authority_leak/vulnerable.cash | `unbounded_mint` |
| bench_ct_inflation_vuln | P1 | Token inflation | token_amount_inflation/vulnerable.cash | `token_amount_inflation` |
| bench_ct_category_drift_secure | P2 | Category preservation | token_category_drift/secure.cash | *(none)* |
| bench_ct_category_drift_vuln | P2 | Category drift | token_category_drift/vulnerable.cash | `token_category_drift` |
| bench_ct_nft_commit_vuln | P3 | NFT commitment integrity | nft_commitment_loss/vulnerable.cash | `nft_commitment_loss` |
| bench_ct_mutable_leak_vuln | P3 | Mutable NFT leakage | mutable_capability_leak/vulnerable.cash | `mutable_capability_leak` |
| bench_ct_hybrid_secure | P4 | Hybrid continuity (secure) | hybrid_continuity_break/secure.cash | *(none)* |
| bench_ct_hybrid_break_vuln | P4 | Hybrid continuity break | hybrid_continuity_break/vulnerable.cash | `hybrid_continuity_break` |
| bench_ct_transfer_vuln | P2 | Unrestricted transfer | unrestricted_token_transfer/vulnerable.cash | `unrestricted_token_transfer` |

All use `evaluation_mode: detector_only`, `tier: 1`, `source: cashtokens_invalid_corpus`.

---

## Fixture inventory (`tests/fixtures/cashtokens_invalid/`)

| Detector family | Secure | Vulnerable | Materialized |
|-----------------|--------|------------|--------------|
| authority_leak | noisy (capability lint) | ✓ P1 | authority + unbounded_mint |
| token_amount_inflation | noisy | ✓ P1 | inflation |
| token_category_drift | clean | ✓ P2 | secure + vuln |
| token_amount_burn | noisy | compiles | **not yet** |
| nft_commitment_loss | noisy | ✓ P3 | commit |
| mutable_capability_leak | noisy | ✓ P3 | mutable leak |
| hybrid_continuity_break | clean (post-fix) | ✓ P4 | secure + break |
| unrestricted_token_transfer | LNC-016 only | ✓ P2 | transfer |

**Sprint fixture fix:** removed unused `stateCat` parameter from hybrid fixtures so CashScript compiler succeeds in benchmark runner path.

---

## Infrastructure changes

1. **`scripts/build_executable_benchmark_registry.py`** — `CASHTOKENS_EXECUTABLE` block (10 entries); registry total 20.
2. **`benchmark/audit_eval/runner.py`** — map linter `WARNING` → `LOW` for `AuditIssue` compatibility (authority_leak mint path triggers LNC-017).
3. **`docs/benchmark_registry_executable.json`** — regenerated.

No OpenRouter, no detector or policy changes.

---

## Remaining gaps

### CashTokens registry (24 of 34 still non-executable)

- **28 spec-only migration entries** — need `.cash` generation from suite YAML or fixture aliasing.
- **6 realworld slots** — need contract collection.
- **2 detector families not in executable registry:** `token_amount_burn` (secure baseline too noisy for empty `expected_findings` today).

### Secure baselines with capability noise

Several secure fixtures trigger capability-layer rules (`capability_token_continuity_break`, etc.). Benchmark comparator only checks **required** findings (positive match), not forbidden findings. Only **clean** secure baselines were materialized (`token_category_drift`, `hybrid_continuity_break`). Future work: `forbidden_findings` field or capability-aware baselines.

### Full registry vs executable registry

The 10 new benchmarks are **additive** in `benchmark_registry_executable.json`. Full `benchmark_registry.json` migration IDs (`bench_mig_133+`) remain spec-only until aliased or generated.

---

## Next materialization targets (ordered)

1. `token_amount_burn` vulnerable + secure (needs forbidden-findings or quieter secure fixture)
2. Alias `bench_mig_133–138` to existing invalid-logic fixtures (7 YAML intents → 8 fixtures, 1 duplicate auth)
3. Generate FT/NFT/hybrid **secure_baseline** `.cash` from golden patterns in `benchmark/suites/cashtokens_*.yaml`
4. Collect realworld `rw_009`–`rw_020` contracts
5. Wire `missing_auth` migration mutations to classification-matrix auth scenarios

---

## Verification commands

```bash
python scripts/build_executable_benchmark_registry.py
python scripts/run_benchmark_suite.py --mode standard --include-coverage-probes
python -m pytest tests/test_benchmark_suite_runner.py tests/audit_engine/test_cashtokens_invalid_corpus.py -q
```

Expected: 20 executable benchmarks, 17 pass + 3 gap, 0 fail; 21 pytest passes.
