# CashTokens MVP Status — Evidence-Based Code Audit

> **Superseded for completion status:** see [cashtokens_mvp_completion_report.md](cashtokens_mvp_completion_report.md) (Wave 2, branch `cashtokenupgrade`).

**Audit date:** 2026-06-03  
**Method:** Source code, tests, benchmark suites, detectors, evaluators, generation/audit pipelines. Documentation used only as secondary context; **code wins on conflict**.

**Original MVP promises:**

1. Fungible token mint (with supply enforcement)
2. NFT mint + transfer
3. Token category validation
4. Token amount validation
5. Detection of invalid token logic

**Scope note:** NexOps “CashTokens hard launch” covers **five pattern classes** (FT transfer, immutable NFT, mutable NFT, minting authority, hybrid). That is **not identical** to the five MVP bullets above—especially promise #1 (FT **mint** vs FT **transfer**).

---

## Promise 1: Fungible token mint (with supply enforcement)

### Status: **PARTIALLY IMPLEMENTED**

Interpretation: **Minting new fungible CashTokens (FT genesis / capped inflation)**, not merely transferring pre-minted FT.

### Generation

| Aspect | Finding |
|--------|---------|
| FT transfer | **FULLY** supported via `_FT_RAIL`, golden `knowledge/golden/patterns/ft_transfer.cash`, Phase 2 routing `token_ft` / `ft_transfer` (`pipeline.py` `build_pattern_rails`, `resolve_effective_mode`). |
| FT mint | **NOT** first-class. `docs/cashtokens_generation.md` states **“No FT genesis”**. No `_FT_MINT_RAIL`, no `ft_mint` golden template, no `token_ft` benchmark case that mints new supply. |
| Supply on mint (any token type) | **PARTIAL.** `_check_token_mint_supply_enforcement` (LNC-017) in `dsl_lint.py` warns when a `mint` function lacks `maxSupply` / `totalMinted` guards. `semantic_normalization.py` sets `supply_mode = "capped_mint"` for “open edition” intents. `_NFT_MINTING_RAIL` line 259 requires `totalMinted + mintAmount <= maxSupply` when cap applies. |
| NFT authority mint with cap | **MOSTLY.** Free synthesis + golden `nft_minting_authority.cash`; rails enforce 0x02 custody + supply line. Recorded benchmark/prod outputs (e.g. `OpenEditionNFT` with `maxSupply` / `totalMinted`) compile and converge. |

### Audit

| Aspect | Finding |
|--------|---------|
| LNC-017 | Present in `audit_engine/audit_lint.py` (`_check_token_mint_supply_enforcement`) — **warning** if mint path lacks cap regex. |
| FT mint | No dedicated audit mode; would only be caught if user passes a mode with `mint` in body and `supply_mode: capped_mint` via semantic context (audit lint does not re-run full Phase 1 normalization on arbitrary uploads). |
| Minting authority | `MintingAuthorityEscapeDetector` (`anti_pattern_detectors.py`) + `capability_*` custody detectors (`capability_detectors.py`, audit profile in `AUDIT_CAPABILITY_DETECTOR_REGISTRY`). |

### Benchmarks

| Suite | FT mint? | Supply enforcement tested? |
|-------|----------|----------------------------|
| `benchmark/suites/cashtokens_ft.yaml` | **No** — all cases **pre-minted transfer** | N/A |
| `benchmark/suites/cashtokens.yaml` (`ct_ft_*`) | **No** | N/A |
| `benchmark/suites/cashtokens_nft_minting.yaml` | NFT mint | `minting_authority_custody`, optional `capability_minting`; not `maxSupply` as critical feature |
| `benchmark/suites/cashtokens_semantic.yaml` `semantic_006` | NFT capped mint (`semantic_capped_mint`) | `mint_cap_guard` mapped to `capability_retained` in `semantic_requirement_map.yaml` — **weak** proxy for numeric cap |

### Semantic verification

- `semantic_requirements.py` + `semantic_requirement_map.yaml`: `mint_cap_guard` → `capability_retained` (not `maxSupply` / `totalMinted` AST facts).
- `semantic_capabilities.py`: no dedicated `enforces_supply_cap` capability; supply inferred only via lint/heuristics.

### Evidence

- `src/services/pipeline.py` — `_FT_RAIL` (transfer), `_NFT_MINTING_RAIL` (mint + line 259 supply)
- `src/services/dsl_lint.py` — `_check_token_mint_supply_enforcement` (LNC-017)
- `src/services/semantic_normalization.py` — `supply_mode = "capped_mint"`
- `knowledge/golden/patterns/ft_transfer.cash` — transfer only
- `docs/cashtokens_generation.md` — “No FT genesis”
- `benchmark/suites/cashtokens_ft.yaml`
- `tests/cashtokens/test_generation_e2e.py` — FT **transfer** smoke test only

### Missing (to mark promise **FULLY IMPLEMENTED**)

1. **FT mint** intent routing, golden or rail, and benchmark cases (e.g. “mint capped fungible tokens to recipient”).
2. **Critical feature** / capability for `require(totalMinted + mintAmount <= maxSupply)` (or equivalent) in evaluator—not `capability_retained` alone.
3. **E2E test** that generated FT mint compiles and fails lint without cap.
4. Product/docs alignment: either narrow MVP wording to “NFT/authority mint with cap” or implement FT genesis.

### Risk (false confidence)

- **semantic_006** / minting family benchmarks can **converge** with custody + 0x02 while **numeric supply cap** is absent in generated code.
- LNC-017 is **warning** severity in `dsl_lint.py` (lines 860, 886)—does **not** block Phase 3 convergence.
- Equating **NFT mint authority** with **fungible token mint** overstates MVP completion.

---

## Promise 2: NFT mint + transfer

### Status: **MOSTLY IMPLEMENTED**

### Generation

| Path | Status |
|------|--------|
| **Transfer** | `nft_immutable` / `nft_transfer_immutable`, `_NFT_IMMUTABLE_RAIL`, golden `nft_transfer_immutable.cash`, family `cashtokens_nft_immutable.yaml`. |
| **Mint** | `nft_minting` / `nft_minting_authority`, `_NFT_MINTING_RAIL`, golden `nft_minting_authority.cash`, family `cashtokens_nft_minting.yaml`, semantic `semantic_006`. |
| **Mutable update** | `nft_mutable` / `nft_mutable_state_update` (state change, not “mint” in sense of new collection)—related but separate. |

Routing: `apply_cashtoken_intent_routing()` in `pipeline.py`; `pattern_profiles.py` per-mode knowledge + lint disables.

### Audit

- `validate_audit` + `AuditDSLLinter`: LNC-018 skipped for `nft_minting` / `token_ft` modes; immutable/mutable have NFT commitment rules.
- `tests/audit_engine/test_validate_audit_families.py` — immutable/mutable/hybrid samples pass without critical `capability_*`.
- `MintingAuthorityEscapeDetector` on generation TollGate; audit uses capability subset + audit detectors.

### Benchmarks

| Suite | Coverage |
|-------|----------|
| `cashtokens_nft_immutable.yaml` | 3 transfer cases |
| `cashtokens_nft_minting.yaml` | 3 mint + 1 failure (capability leak) |
| `cashtokens.yaml` | `ct_nft_imm_*`, `ct_minting_*` |
| `cashtokens_semantic.yaml` | soulbound, marketplace, capped mint, etc. |

Family reports (`docs/cashtokens_family_benchmark_report.md`): positive paths **100% compile/converge** for immutable, mutable, minting (except known negative probe drift).

### Semantic verification

- Evaluator `_cashtoken_alias_pool` for `nft_immutable`, `nft_mutable`, `nft_minting` (`benchmark/evaluator.py`).
- `semantic_requirement_map.yaml`: `nftcommitment_preservation`, `minting_authority_custody`, `capability_byte_match`.

### Evidence

- `knowledge/golden/patterns/nft_minting_authority.cash`, `nft_transfer_immutable.cash`
- `src/services/knowledge_structured/nft_minting_rules.yaml`, `nft_rules.yaml`
- `benchmark/evaluator.py` — pattern pools
- `tests/cashtokens/test_evaluator_pools.py`, `test_golden_registry.py`
- `tests/audit_engine/test_validate_audit_minting.py`

### Missing

1. **Single benchmark** that asserts both mint and transfer in one contract (usually separate contracts in BCH).
2. **Audit E2E** on freshly generated NFT family artifacts (only hand-crafted samples in audit tests).
3. **semantic_006** uses weak `mint_cap_guard` (see Promise 1).

### Risk

- Benchmark **converge** does not require `nftCommitment` on every mint child path—evaluator regex may pass with category + custody only.
- Prod historically used **fallback** contracts (fixed in `GenerationController` benchmark parity)—UI may still misreport success if `synthesis.converged` ignored.

---

## Promise 3: Token category validation

### Status: **MOSTLY IMPLEMENTED**

### Generation

- **DSL:** `_check_token_pair_completeness` (LNC-014) in `dsl_lint.py` — requires category **and** amount together when either appears.
- **TollGate:** `TokenPairValidationDetector` (`anti_pattern_detectors.py`, id `missing_token_amount_validation`) — AST `find_token_pair_violations()`.
- **Rails:** `_FT_RAIL`, `_NFT_*_RAIL`, `_HYBRID_RAIL` embed `tokenCategory` equalities.
- **Phase 3:** Detector runs unless disabled in `pattern_profiles.py` (minting disables `missing_token_amount_validation`).

### Audit

- **Audit lint:** LNC-014 in `audit_lint.py` (same logic family); hybrid profile disables LNC-014 in lint list.
- **Audit detectors:** `AUDIT_DETECTOR_REGISTRY` does **not** include `TokenPairValidationDetector` — category/amount pairing **not** enforced in `validate_audit` enforcer pass, only via lint rules.
- **Capabilities:** `preserves_token_category`, `token_category_constrained` in `semantic_capabilities.py`; `capability_token_continuity_break` in generation detectors only (excluded from `AUDIT_CAPABILITY_DETECTOR_REGISTRY`).

### Benchmarks

- Nearly all CashTokens YAML cases list `token_category_check` as required or critical.
- `benchmark/evaluator.py` `_cashtoken_alias_pool` — regex `tokenCategory ==` on inputs/outputs.
- `tests/cashtokens/test_evaluator_pools.py`

### Semantic verification

- `semantic_requirement_map.yaml` → `token_category_check` → `preserves_token_category` / `token_category_constrained` with regex fallback.

### Evidence

- `src/utils/cashscript_ast.py` — `validates_token_category`, `find_token_pair_violations`
- `src/services/dsl_lint.py` — LNC-014
- `src/services/anti_pattern_detectors.py` — `TokenPairValidationDetector`
- `benchmark/config/semantic_requirement_map.yaml`

### Missing

1. **Audit parity:** Add `TokenPairValidationDetector` (or equivalent) to audit path or document that audit relies on LNC-014 only.
2. **Strong capability:** `preserves_token_category` regex does not prove **correct** category—only that some equality exists.
3. **Per-output-index** category checks not verified by evaluator (only global regex).

### Risk

- **Benchmark pass** with category on input only and output only on **different** indices may still satisfy loose regex in `_cashtoken_alias_pool` (`cat_in and cat_out`).
- Minting profile **disables** `missing_token_amount_validation` at detector level—pairing enforced only by lint/rail, not Phase 3.

---

## Promise 4: Token amount validation

### Status: **MOSTLY IMPLEMENTED**

### Generation

- Same stack as Promise 3: LNC-014, `TokenPairValidationDetector`, rails requiring `tokenAmount` preservation or bounds (`_FT_RAIL` line 222: `<=` input amount).
- NFT immutable: `tokenAmount == 0` or preserve in rails/evaluator (`tokenAmount\s*==\s*0` in `nft_immutable` pool).
- Split FT case (`ct_ft_family_003`) critical `token_amount_check`.

### Audit

- LNC-014 via `audit_lint.py`.
- No `TokenPairValidationDetector` in audit enforcer registry (same gap as Promise 3).
- `capability_token_continuity_break` not in audit capability registry.

### Benchmarks

- `token_amount_check` in FT, hybrid, many immutable cases.
- Redeem/burn path: `benchmark/evaluator.py` `_redeemable_category_burn_validation` for `tokenCategory == 0x` (semantic_008).

### Semantic verification

- `token_validation` requirement → `preserves_token_amount` / `burns_output_tokens` in YAML map.
- Feature extractor flags `token_amount` in detected features.

### Evidence

- `src/services/dsl_lint.py` — LNC-014 (amount leg)
- `src/services/semantic_capabilities.py` — `preserves_token_amount`
- `benchmark/evaluator.py` — `amt_ok`, `expectedTokenAmount` heuristics
- `tests/cashtokens/test_evaluator_redeem_validation.py`

### Missing

1. **Conservation laws** for multi-output split (sum of outputs == input) not in evaluator—only in intent text and partial lint.
2. **Audit detector parity** for pair validation.
3. **FT mint amount** (new supply) not benchmarked.

### Risk

- Function validates `tokenAmount` on one output but **burns** or **inflates** on another—LNC-014 is per-function reference check, not global conservation.
- Evaluator `token_amount_check` can pass via `expectedTokenAmount` substring without output binding.

---

## Promise 5: Detection of invalid token logic

### Status: **PARTIALLY IMPLEMENTED**

### Generation (TollGate + lint)

| Mechanism | Role |
|-----------|------|
| `anti_pattern_detectors.py` | 23 detectors incl. `MintingAuthorityEscapeDetector`, `TokenPairValidationDetector`, `CovenantContinuationDetector`, etc. |
| `capability_detectors.py` | 7 Wave 1.5 detectors (auth on mutate, NFT transfer, mutable reanchor, continuity, burn, hybrid migration, payout). |
| `dsl_lint.py` | LNC-014, LNC-017, LNC-018, LNC-020–027, capability byte match LNC-022. |
| `pattern_profiles.py` | Mode-specific **disable** lists (reduces false positives, also **blind spots**). |

Phase 3 blocks on **critical** severity only (`pipeline.py` / `Phase3.validate`).

### Audit

- `audit_detectors.py` — 8 audit-specific detectors (index OOB, coupling, commitment length, etc.).
- `AUDIT_CAPABILITY_DETECTOR_REGISTRY` — 6 capability detectors.
- `AuditAgent` — downgrade non-exploitable HIGH; LLM semantic bucket separate.
- **No** `MintingAuthorityEscapeDetector` in `AUDIT_DETECTOR_REGISTRY` — mint leak detection in audit relies on `capability_*` + lint, not the same detector id.

### Benchmarks (negative / must-fail)

| Case | Intent |
|------|--------|
| `ct_mint_family_fail_001` / `ct_minting_fail_001` | Capability leak to buyer — `must_fail_capability_leak` |
| Evaluator logic | `must_fail_*` critical + `failure` tag forces non-converge unless leak **detected** (`benchmark/evaluator.py` lines 434–442) |

**No** dedicated negative suites for: wrong category only, wrong amount only, unrestricted burn, hybrid migration break, soulbound external transfer (as generation failure cases).

### Semantic verification

- Negative semantics mostly **not** in `semantic_capabilities`—evaluator uses alias pool `must_fail_capability_leak` inverse (`leak_fail = not custody_ok`).
- Trace artifacts in `benchmark/results/capability_traces/` — diagnostic only.

### Evidence

- `src/services/anti_pattern_detectors.py` — `MintingAuthorityEscapeDetector`, `DETECTOR_REGISTRY`
- `src/services/capability_detectors.py` — `CAPABILITY_DETECTOR_REGISTRY`
- `benchmark/suites/cashtokens_nft_minting.yaml` — `ct_mint_family_fail_001`
- `tests/cashtokens/test_capability_detectors.py` — smoke tests for continuity/burn
- `tests/cashtokens/test_generation_e2e.py` — `test_minting_failure_case_rejected_or_no_custody`

### Missing

1. **Corpus** of invalid-token `.cash` fixtures per failure mode (category break, amount break, leak, burn, migration).
2. **Audit regression** that asserts detectors fire on bad code and stay silent on good family codegen.
3. **must_fail** coverage beyond capability leak (only one CashTokens-negative benchmark).
4. **Generation-time rejection** of bad logic is not guaranteed—negative case often **fails to compile** rather than **converge with detected leak** (documented mint family fail drift).

### Risk

- **Single negative benchmark** creates illusion of “invalid logic detection” for whole MVP.
- **Disabling** detectors/lint per profile (`nft_minting` disables `missing_token_amount_validation`, etc.) can **miss** real bugs on edge layouts.
- **Regex fallback** in evaluator can mark `must_fail_capability_leak` satisfied without semantic understanding.

---

## Summary table

| Promise | Status | Confidence | Can claim complete? |
|---------|--------|------------|---------------------|
| 1. Fungible token mint (supply enforcement) | **PARTIALLY IMPLEMENTED** | **LOW** (FT mint) / **MEDIUM** (NFT mint + cap lint) | **No** — FT mint absent; cap not gating convergence |
| 2. NFT mint + transfer | **MOSTLY IMPLEMENTED** | **HIGH** | **Mostly yes** for separate mint & transfer contracts; not one combined product feature |
| 3. Token category validation | **MOSTLY IMPLEMENTED** | **MEDIUM** | **No** — audit enforcer gap; evaluator regex loose |
| 4. Token amount validation | **MOSTLY IMPLEMENTED** | **MEDIUM** | **No** — same gaps; multi-output conservation weak |
| 5. Detection of invalid token logic | **PARTIALLY IMPLEMENTED** | **MEDIUM** | **No** — one negative mint case; many failure modes untested |

---

## Overall MVP completion (honest)

| Metric | Estimate | Basis |
|--------|----------|--------|
| **Five-promise checklist** | **~68%** | Average of partial/mostly per row; Promise 1 and 5 drag score down |
| **Five pattern-class launch** (docs) | **~85%** | FT transfer, NFT imm/mut/mint, hybrid benchmarks + generation rails |
| **Production-ready CashTokens** | **Not claimed** | `cashtokens_generation.md`: not audited, not mainnet-ready by default |

Weighted by your **exact five bullets**, not pattern-class docs alone.

---

## Can BCH-1 CashTokens commitment be claimed today?

**No — not for the full five-bullet MVP as written.**

**Can be claimed with qualifications:**

- **BCH-1 (narrow):** “CashScript generation for five CashToken **pattern classes** with compile convergence benchmarks and shared semantic-capability infrastructure (Wave 1.5).”
- **Not BCH-1 (broad):** “Complete CashTokens MVP including **fungible mint**, full **invalid-logic** coverage, and **audit-equivalent** enforcement to generation.”

**Evidence-based blockers for a broad claim:**

1. Documented **no FT genesis** (`docs/cashtokens_generation.md`).
2. Audit **`AUDIT_DETECTOR_REGISTRY`** omits generation token-pair and minting-escape detectors.
3. Only **one** CashTokens negative benchmark (`must_fail_capability_leak`).
4. Supply cap **warning-only** (LNC-017), weak `mint_cap_guard` mapping.

---

## Recommended Wave 2 roadmap (by impact)

1. **MVP honesty pack** — Either implement **FT capped mint** (rail, golden, benchmarks, capabilities) or **revise public MVP** to “FT transfer + NFT mint/transfer”.
2. **Audit–generation parity** — Register token-pair + minting-escape checks in `validate_audit`; auto-set `effective_mode` from `intent_model` on audit API.
3. **Negative-token corpus** — 8–10 `.cash` fixtures + `validate_audit` + evaluator `must_fail_*` per failure mode.
4. **Supply cap as hard gate** — `enforces_supply_cap` capability, LNC-017 critical on `capped_mint`, semantic_006 critical on `maxSupply` regex.
5. **Evaluator tightening** — Reduce `fallback_regex_alias` in `semantic_requirement_map.yaml`; per-output-index category/amount in `semantic_capabilities`.
6. **Wave 2 expansion** (frozen today) — governance/streaming semantic cases, stablecoin/LP only after caps above.

---

## Minimum work to reach FULLY IMPLEMENTED (all five promises)

| Promise | Minimum work |
|---------|----------------|
| **1** | Add `ft_mint` / `capped_mint` mode: rail + golden + 2 benchmarks; LNC-017 → blocking for mint functions; capability `enforces_supply_cap`; drop or qualify “fungible” in docs if only NFT mint stays. |
| **2** | Audit E2E on generated family artifacts; optional combined doc for “collection = mint contract + transfer contract”. |
| **3** | Add `TokenPairValidationDetector` to audit path OR merge lint LNC-014 into critical audit score; tighten evaluator to same-index category checks. |
| **4** | Same as #3 + split-output sum conservation check in lint or detector for `ct_ft_family_003`. |
| **5** | Negative suite (≥6 cases); `tests/audit_engine/test_cashtokens_invalid_corpus.py`; generation tests asserting TollGate/capability fire; fix mint fail probe to **detect** leak when code compiles. |

---

## Verification commands (reproduce this audit)

```powershell
cd nexops-mcp
python scripts/validate_audit_sample.py
python -m pytest tests/cashtokens/ tests/audit_engine/test_validate_audit_*.py tests/cashtokens/test_capability_detectors.py -q
# Optional API benchmarks (OPENROUTER_API_KEY):
python scripts/run_family_benchmarks.py
python scripts/run_semantic_benchmark.py --all
```

---

## Code vs documentation disagreements (trust code)

| Doc claim | Code reality |
|-----------|----------------|
| “Five pattern classes” launch | **True** for generation/benchmarks. |
| Implied full CashTokens MVP including FT mint | **False** — no FT mint suite; “No FT genesis”. |
| Wave 1.5 unified verification | **True** for evaluator + capability detectors; **audit** registry is slimmer. |
| Semantic 8/8 converged (`cashtokens_semantic_runs.md`) | **Recorded**; does not prove all five MVP bullets. |

---

*This file should be updated after any FT mint implementation, audit registry change, or new negative benchmarks.*
