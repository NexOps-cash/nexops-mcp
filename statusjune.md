# NexOps Current State Report

**Role:** Principal Engineer assessment  
**Date:** 2026-06-07  
**Repository:** `nexops-mcp` (`origin`: `https://github.com/nishanthcr7777/nexops-mcp.git`)  
**Method:** Code inspection + artifacts already in-repo. **No new benchmarks were run.**

---

## 1. Branch and Release State

### Current branch

| Item | Value | Evidence |
|------|-------|----------|
| Active branch | `main` | `git status -sb` → `## main...origin/main` |
| Working tree | Clean (synced with `origin/main`) | Same command |
| Parent workspace | `d:\downloadds\nexmcp` is **not** a git root | `git` fails at workspace root |

### Unmerged branches

| Branch | Commits ahead of `main` | Commits behind `main` | Status |
|--------|-------------------------|----------------------|--------|
| `feat/pattern-convergence` | **0** | **95** | Stale; work landed via merge (see PR #4 below) |
| `benchmark` | 0 (checked) | — | No unique commits vs `main` |
| `auditenhancement` | — | — | Merged historically (PRs #5–#7) |
| `cashtokenupgrade` | — | — | Merged into `main` (PRs #8–#11) |

Remote branches still exist (`remotes/origin/feat/pattern-convergence`, etc.) but **`feat/pattern-convergence` has no commits that are not already on `main`.**

### Recent major PRs (merge commits on `main`)

| Merge | Branch | Headline change |
|-------|--------|-----------------|
| PR #11 | `cashtokenupgrade` | Investor demo suites, token validation hardening, Wave 2 completion docs |
| PR #10 | `cashtokenupgrade` | Benchmark synthesis parity, WebSocket alignment |
| PR #9 | `cashtokenupgrade` | Wave 1.5 invariant unification, capability-backed detectors |
| PR #8 | `cashtokenupgrade` | CashTokens benchmark / generation wave |
| PR #7–#6 | `auditenhancement` | Audit pipeline expansion |
| PR #4 | `feat/pattern-convergence` | 11-pattern benchmark suites, `pattern_profiles.py`, vault lint/evaluator work |

Latest commits on `main` (2026-06-07): `0d3ae39`, `1bb79ab` — `validate_audit` tests for CashTokens families.

### CashTokens Wave 2 merge status

**Fully merged into `main`.** Evidence:

- Merge commit `a6d0fb9` — *Merge pull request #11 from NexOps-cash/cashtokenupgrade*
- `docs/cashtokens_mvp_completion_report.md` — Wave 2 phase gates documented
- `benchmark/results/wave2_benchmark_summary.json` — `"all_gates_pass": true`, `"remaining_9_gates_pass": true` (generated 2026-06-06)

### TODO / FIXME markers

| Location | Marker | Notes |
|----------|--------|-------|
| `src/services/pipeline.py:1390` | `// TODO: Implement logic` | Intentional Phase 1 skeleton placeholder per `specs/phase1_spec.md` |
| `specs/phase1_spec.md` | Requires TODO in skeleton | By design |
| Widespread `SKIP` in lint | Mode-conditional skip lists | Not unfinished work — documented behavior in `dsl_lint.py` |

No project-wide `FIXME` backlog was found in application code.

### Disabled tests

- **No** `@pytest.mark.skip`, `@pytest.mark.xfail`, or `unittest.skip` usages under `tests/` (ripgrep scan).

### Skipped / partial benchmark coverage

| Item | Issue | Evidence |
|------|-------|----------|
| `benchmark/suites/vaults_real` | YAML content **without `.yaml` extension** | File exists; `BenchmarkRunner` expects a path ending in `.yaml` conventionally |
| `benchmark/run_11_pattern_diagnosis.py` | Diagnosis runner exists; **no** `diagnosis_11_patterns_*.json` in repo | Script writes to `benchmark/results/`; none committed |
| `NEXOPS_BENCH_MAX_CASES_PER_PATTERN` | Defaults to **2** in diagnosis runner | `run_11_pattern_diagnosis.py:86` |
| `scripts/run_semantic_benchmark.py` | Checkpoint skip messaging | Per-case `"skipped (checkpoint)"` path |
| Duplicate suite | `single_sig_transfer (1).yaml` duplicates `single_sig_transfer.yaml` | Both present (4 cases each) |

---

## 2. Generation Pipeline Architecture

### Execution flow (actual)

```
User intent
  → GuardedPipelineEngine.generate_guarded()          [pipeline_engine.py]
      Phase 1: Phase1.run()                           [pipeline.py]
          LLM intent JSON → IntentModel → ContractIR
          Deterministic enrichment (escrow tags, CashToken routing, golden type normalization)
      Phase 2 loop (max 2–3 gen attempts):
          Phase2.run() → golden adaptation OR free synthesis
          LanguageGuard.validate()
          DSL lint loop (max 4) → optional Phase2 rerun with violations
          Structural integrity gate (diagnose_structure / is_structurally_valid)
          Compile gate (cashc, max 3 LLM syntax fixes + deterministic micro-fixes)
      Phase 3: Phase3.validate() → AntiPatternEnforcer + invariant engine
      Phase 4: SanityChecker.validate()               [sanity_checker.py]
      On exhaustion: secure fallback .cash (unless disable_fallbacks=True)
  → BenchmarkEvaluator wraps same engine with disable_fallbacks=True, 300s timeout
```

### Phase 1 — Intent parsing

| Attribute | Detail |
|-----------|--------|
| **Source** | `src/services/pipeline.py` — `Phase1`, `_build_phase1_prompt`, `_parse_phase1_response`, `apply_cashtoken_intent_routing` |
| **Responsibilities** | LLM → `IntentModel`; deterministic feature enrichment; escrow keyword heuristics; golden type upgrades; CashToken class routing; semantic normalization hooks |
| **Retry logic** | None at Phase 1; failure returns error to engine |
| **Known weaknesses** | `timeout_days` list/range parse instability (coercion added on `feat/pattern-convergence` branch work, now on `main` via merge); mixed CashToken + BCH escrow → `semantic_unsupported` guard |
| **Recent modifications** | CashToken routing (`apply_cashtoken_intent_routing`); Wave 1.5 semantic fields on `IntentModel`; merged via PRs #9–#11 |

### Phase 2 — Constrained generation

| Attribute | Detail |
|-----------|--------|
| **Source** | `src/services/pipeline.py` — `Phase2`, `_free_phase2`, `_golden_phase2`, `build_pattern_rails`, `build_unified_dsl_rules` |
| **Responsibilities** | Load structured YAML knowledge via `pattern_profiles.py`; inject pattern rails (`_SPLIT_RAIL`, `_ESCROW_RAIL`, `_SWAP_RAIL`, `_VAULT_RAIL`, CashToken rails); golden template adaptation for mapped types in `_GOLDEN_TYPE_MAP` |
| **Retry logic** | Outer gen loop (2–3); inner lint loop (4) with stuck-lint breaker; compile fix loop (3); Phase2 re-invoked with `previous_violations` from Phase 3 |
| **Known weaknesses** | Golden path only for subset of patterns; free synthesis still LLM-variable; lint stuck-breaker can proceed to compile with unresolved lint |
| **Recent modifications** | `_FT_MINT_RAIL`, capability/invariant integration, vault treasury rail, pattern profile YAML loading |

Supporting files: `src/services/language_guard.py`, `src/services/structural_integrity.py`, `src/services/compiler.py`, `knowledge/golden/*`.

### Phase 3 — Toll Gate

| Attribute | Detail |
|-----------|--------|
| **Source** | `src/services/pipeline.py` — `Phase3`; `src/services/anti_pattern_enforcer.py`; `src/services/invariant_engine_core.py` |
| **Responsibilities** | AST-backed detectors; pattern-profile `disable_detectors`; **critical-only** blocking (`severity == "critical"`) |
| **Retry logic** | Violations fed back to Phase 2 on next gen attempt |
| **Known weaknesses** | Comment in `Phase3` still says "all 11 detectors" but registry has **32**; non-critical violations reported but do not block; cross-pattern false positives documented in roadmap/plan transcripts |
| **Recent modifications** | Wave 2B CashTokens invalid-logic detectors appended to generation registry; unified invariant profiles (Wave 1.5) |

### Phase 4 — Sanity check

| Attribute | Detail |
|-----------|--------|
| **Source** | `src/services/sanity_checker.py` |
| **Responsibilities** | Regex/feature evidence vs `IntentModel`; multisig accountancy; pattern-specific checks (vault/covenant anchor, split sum, decay elapsed arithmetic) |
| **Retry logic** | On failure at `security_level=high`, triggers full regeneration (violations cleared) |
| **Known weaknesses** | Regex-based; can disagree with benchmark `FeatureExtractor` / capability layer (documented vault alignment work) |
| **Recent modifications** | CashTokens covenant modes skip multisig accountancy; decay/streaming elapsed checks |

Orchestration: `src/services/pipeline_engine.py` — `GuardedPipelineEngine`.

---

## 3. Pattern Coverage Inventory

Legend: **Golden** = registered in `_GOLDEN_TYPE_MAP` / golden adaptation path (`pipeline.py:60–74`). **Template** = file under `knowledge/templates/` only.

| Pattern | Benchmark suite | Golden template | Dedicated rail | Pattern profile | Evaluator support | Audit profile |
|---------|-----------------|-----------------|----------------|-----------------|---------------|
| **single_sig_transfer** | Y — `benchmark/suites/single_sig_transfer.yaml` (4) | N | N | Y — `single_sig_transfer_rules.yaml` | Y — suite + `FeatureExtractor` | Y — LNC-008/016 disabled |
| **timelock** | Y — `timelock.yaml` (5) | N | N | Y | Y | Y |
| **hashlock** | Y — `hashlock.yaml` (5) | N | Partial — `_SWAP_RAIL` if `swap`/`htlc` tags | Y | Y | Y — no lint/detector disables |
| **multisig** | Y — `multisig.yaml` (6) | N | N | Y | Y | Y |
| **escrow** | Y — `escrow.yaml` (6), `escrow_suite.yaml` (10) | Y — `escrow_2of3.cash` / `escrow_2of3_nft` | Y — `_ESCROW_RAIL` | Y | Y | Y — strict (no disables) |
| **refundable_payment** | Y — `refundable_payment.yaml` (6) | Y — `refundable_crowdfund` → `crowdfunding_refundable.cash` | N | Y | Y | Y |
| **split_payment** | Y — `split_payment.yaml` (6) | N | Y — `_SPLIT_RAIL` if `split` in features | Y | Y | Y |
| **vault** | Y — `vaults.yaml` (8), `vault_debug.yaml` (2); **`vaults_real` (24 cases, no `.yaml`)** | Template only — `vault_2step.cash` (**not** in `_GOLDEN_TYPE_MAP`) | Y — `_VAULT_RAIL` | Y | Y — vault-specific evaluator relaxations | Y — multiple detectors disabled |
| **covenant** | Y — `covenant.yaml` (3), `stateful_suite.yaml` (3) | N | N | Y | Y | Y |
| **conditional_spend** | Y — `conditional_spend.yaml` (5) | N | Partial — `_SWAP_RAIL` via `swap` routing | Y | Y | Y |
| **decay** | Y — `decay.yaml` (3), `vesting.yaml` (10) | Y — `dutch_auction`, `linear_vesting` | N | Y — `decay_rules.yaml` | Y | Y |

**Core 11-pattern canonical cases (deduplicated):** 57  
**All YAML suites in `benchmark/suites/`:** 35 files, **179** total cases (includes CashTokens, investor demo, test harnesses).

Profiles: `src/services/pattern_profiles.py` — all 11 patterns have entries (lines 40–209).

---

## 4. Convergence Evidence

**Sources scanned:** 164 files matching `benchmark/results/bench_*.json`, plus `regression_results.json`, `regression_results_run2.json`, `coverage_stability_results.json`, `wave2_benchmark_summary.json`, `investor_demo_summary.json`.

**Classification rule (evidence-only):**

- **GREEN:** Latest dedicated-suite run with **n ≥ 3** cases: convergence ≥ 85% **and** compile ≥ 85%
- **YELLOW:** Some benchmark evidence but below GREEN threshold, small n, or conflicting secondary evidence
- **RED:** Latest run convergence < 50%, or **no** benchmark JSON evidence

Alias mapping used (same as `pattern_profiles.canonical_pattern`): `distribution` → `single_sig_transfer`, `vesting` → `decay`, `stateful` → `covenant`, `swap` → `conditional_spend`.

### Per-pattern summary

| Pattern | Total case-results (all runs) | Runs | Aggregate compile | Aggregate conv | Aggregate intent | Latest run (id / n) | Latest compile | Latest conv | Latest intent | Top failure layer (non-converged) | Class |
|---------|------------------------------|------|-------------------|----------------|--------------|---------------------|----------------|-------------|---------------|-----------------------------------|-------|
| single_sig_transfer | 14 | 4 | 78.6% | 78.6% | 0.357 | `bench_20260331_2116_9751` / 2 | 100% | 100% | 0.50 | Compile (3 aggregate) | **YELLOW** (n=2 latest) |
| timelock | 7 | 2 | 100% | 100% | 0.571 | `bench_20260331_2117_108e` / 2 | 100% | 100% | 0.58 | — | **YELLOW** (n=2 latest) |
| hashlock | 7 | 2 | 85.7% | 85.7% | 0.190 | `bench_20260331_2117_fd6a` / 5 | 80% | 80% | 0.13 | Compile | **YELLOW** |
| multisig | 8 | 2 | 100% | 100% | 0.677 | `bench_20260331_2118_ff90` / 6 | 100% | 100% | 0.74 | — | **GREEN** |
| escrow | 43 | 7 | 100% | 100% | 0.886 | `bench_20260331_2120_3d04` / 6 | 100% | 100% | 0.48 | — | **GREEN**† |
| refundable_payment | 8 | 2 | 75.0% | 75.0% | 0.556 | `bench_20260331_2121_6f05` / 6 | 67% | 67% | 0.52 | Compile | **YELLOW** |
| split_payment | 8 | 2 | 50.0% | 50.0% | 0.156 | `bench_20260331_2125_2cb6` / 6 | 50% | 50% | 0.17 | Compile (4/8) | **RED** |
| vault | 175 | 23 | 78.9% | 58.9% | 0.666 | `bench_20260401_2119_3456` / 24 | 92% | 67% | 0.86 | None (35), Compile (27), `unified_rules` NameError (6), Timeout (3) | **YELLOW** |
| covenant | 10 | 5 | 80.0% | 60.0% | 0.233 | `bench_20260331_2131_2a04` / 3 | 100% | 100% | 0.22 | None, Compile | **YELLOW** (intent 0.22) |
| conditional_spend | 7 | 2 | 71.4% | 71.4% | 0.583 | `bench_20260331_2132_4ce4` / 5 | 60% | 60% | 0.48 | Compile | **YELLOW** |
| decay | 101 | 24 | 64.4% | 60.4% | 0.563 | `bench_20260331_2135_1b7f` / 3‡ | 100% | 100% | 0.50 | LLM fallback exhausted (24 aggregate) | **YELLOW** |

† **Escrow conflict:** `regression_results.json` and `regression_results_run2.json` both show `"2_escrow": "FAILED: Guarded pipeline failed to converge"` with `compile_exhausted: yes`, while benchmark JSONs show 100% convergence. Different harness, model, and fallback settings — treat escrow as **not fully verified**.

‡ Latest run for `decay.yaml` only (3 cases). Aggregate includes **`vesting.yaml`** runs (same alias `decay`) with heavy LLM exhaustion failures.

### Key benchmark artifacts (by pattern)

| Pattern | Notable artifact |
|---------|------------------|
| vault | `benchmark/results/bench_20260401_2119_3456.json` — full `vaults_real` run: 24 cases, 66.7% conv (also cited in agent session) |
| escrow | `benchmark/results/bench_20260331_2120_3d04.json` — 6/6 converged |
| split | `benchmark/results/bench_20260331_2125_2cb6.json` — 3/6 converged |
| decay (vesting) | Multiple `bench_20260522_*` semantic runs; aggregate LLM provider exhaustion |

### Secondary evidence (non-suite)

| File | Finding |
|------|---------|
| `coverage_stability_results.json` | `B_timelock` SUCCESS (lint LNC-008 warnings); `A_split_multisig` FAILED compile |
| `regression_results.json` | `1_multisig` SUCCESS; `2_escrow` FAILED; `3_vesting` SUCCESS |

---

## 5. Known Failure Families

Grouped from `failure_layer` fields across 164 benchmark JSONs + regression/stability artifacts.

| Family | Approx. frequency (vault-weighted) | Patterns affected | Root cause (evidence) |
|--------|-------------------------------------|-------------------|------------------------|
| **Compile failures** | High — 27 vault, 5 decay, 4 split, scattered elsewhere | split_payment, vault, decay, hashlock, conditional_spend, covenant | `cashc` syntax errors; compile fix loop exhaustion (`pipeline_engine.py` max 3 fixes) |
| **LLM provider / retry exhaustion** | 24+ decay aggregate hits | decay (vesting runs) | `failure_layer`: `"All 1 LLM fallbacks exhausted..."` / OpenRouter / Groq errors |
| **Benchmark timeout** | 3 vault | vault (`vr_010`, `vr_023` in `bench_20260401_2119_3456`) | `asyncio.wait_for(..., 300)` in `benchmark/evaluator.py:286–293` |
| **Evaluator / semantic mismatch** | 35 vault `None` failure_layer with non-converged | vault, covenant | Code compiles; `converged=false` despite high intent — `semantic_pass` / feature alias gaps (documented in vault alignment commits) |
| **Lint false positives (LNC-008 / LNC-003)** | Historical vault blocker; partially patched | vault, timelock | Terminal paths incorrectly required self-anchor; staged split not recognized (`dsl_lint.py` vault-aware patches) |
| **Runtime errors in pipeline** | 6 vault | vault | `failure_layer`: `"Error: name 'unified_rules' is not defined"` |
| **Low intent coverage despite compile** | Widespread low aggregate intent | hashlock (0.19), split (0.16), covenant (0.23) | Benchmark feature detection / alias pools not aligned with generated code shapes |
| **Routing / Phase 1** | Regression escrow | escrow | Intent → type mismatch; golden vs free synthesis path selection |
| **Toll gate violations** | regression multisig: 4 violations yet SUCCESS | multisig, escrow | Non-critical violations may not block; escrow still failed at compile |
| **Syntax repair / structural corruption** | vault compile aborts | vault | `structural_integrity.py` aborts fix loop when braces unbalanced |
| **Audit mismatch (CashTokens)** | investor demo partial | token category, token amount | `investor_demo_summary.json` — 2/3 on categories 3 & 4 |

---

## 6. Detector Inventory

### DSL lint (generation path)

| Metric | Count | Source |
|--------|-------|--------|
| Active check functions in linter pipeline | **27** | `dsl_lint.py` registry ~lines 1276–1300 |
| Distinct rule IDs | **LNC-001 – LNC-027** (plus sub-ids e.g. LNC-001a) | Same file |
| Mode-conditional rules | LNC-008, LNC-012, LNC-013, LNC-014, LNC-017–025 | `contract_mode` parameter |

Hard-blocking lint severities feed Phase 2 retry; LNC-012, LNC-017, LNC-021–022, LNC-024–025 documented as **warning/soft** in places.

### Toll Gate (generation) — `generation_detector_registry()`

| Layer | Count |
|-------|-------|
| Base anti-pattern detectors | **24** — `DETECTOR_REGISTRY` in `anti_pattern_detectors.py:965–989` |
| CashTokens invalid-logic detectors | **8** — `CASHTOKENS_INVALID_DETECTOR_REGISTRY` |
| **Total generation Toll Gate** | **32** (verified via import) |
| Capability-backed detectors (added in invariant profile) | **7** — `CAPABILITY_DETECTOR_REGISTRY` in `capability_detectors.py:236–243` |

Generation profile: `build_generation_profile()` attaches capability detectors to base registry (`invariant_engine_core.py:150–158`).

### Audit Toll Gate — `audit_detector_registry()`

| Layer | Count |
|-------|-------|
| Audit-native AST detectors | **8** — `AUDIT_DETECTOR_REGISTRY` in `audit_detectors.py:469–477` |
| Shared generation detectors (parity) | **3** — `TokenPairValidation`, `MintingAuthorityEscape`, `UnboundedMint` |
| CashTokens invalid-logic | **8** (same registry as generation) |
| **Total audit registry** | **19** (verified via import) |
| Audit capability detectors | **7** — `AUDIT_CAPABILITY_DETECTOR_REGISTRY` |

Audit lint mirror: **~18** `_check_*` functions in `audit_engine/audit_lint.py` (subset of generation lint; missing LNC-020–025 family).

### Overlap and drift

| Drift type | Evidence |
|------------|----------|
| **Duplicate detector implementations** | `IndexUnderflowDetector`, `OutputBindingDetector`, etc. exist in both `anti_pattern_detectors.py` and `audit_detectors.py` with separate classes |
| **Registry size mismatch** | `Phase3` comment says "11 detectors"; actual generation registry = 32 |
| **Lint parity gap** | Generation `dsl_lint.py` has LNC-020–027; audit `audit_lint.py` stops earlier (no five-point covenant LNC-025 in audit grep) |
| **Pattern-specific disables** | `pattern_profiles.py` disables detectors for vault/ft_mint/etc. in generation; audit profile uses separate disable set via invariant engine |
| **Documentation vs enforcement** | Anti-pattern `.cash` files loaded for documentation; enforcement is detector-driven (`anti_pattern_enforcer.py:74–75`) |

---

## 7. CashTokens State

### Supported token families (generation)

| Family | Routing / mode | Golden / rail |
|--------|----------------|---------------|
| FT transfer | `token_ft`, `ft_transfer` | Golden + `_FT_RAIL` |
| FT mint | `ft_mint`, `ft_mint_authority` | Golden + `_FT_MINT_RAIL` (Wave 2A) |
| NFT immutable | `nft_immutable`, `nft_transfer_immutable` | Golden + `_NFT_IMMUTABLE_RAIL` |
| NFT mutable | `nft_mutable`, `nft_mutable_state_update` | Golden + `_NFT_MUTABLE_RAIL` |
| NFT minting authority | `nft_minting`, `nft_minting_authority` | Golden + `_NFT_MINTING_RAIL` |
| Hybrid / sidecar | `hybrid_token`, `stablecoin_minter_sidecar` | Golden + `_HYBRID_RAIL` |

Source: `pipeline.py` `_GOLDEN_TYPE_MAP`, `docs/cashtokens_generation.md`.

### Benchmark status

| Suite / report | Result | Artifact |
|--------------|--------|----------|
| Wave 2 gate summary | **PASS** — 7/7 positive converged, 12/12 negative non-converged | `benchmark/results/wave2_benchmark_summary.json` |
| Family benchmarks (2026-05-23) | FT / immutable / mutable **100%** conv; minting **75%**; hybrid **100%** | `docs/cashtokens_family_benchmark_report.md` |
| Post-upgrade 15-case suite | Avg score **0.930**, 11 newly passing | `docs/cashtokens_benchmark.md` |
| Investor demo (2026-06-07) | **10/12** positive converged; categories 3–5 **PARTIAL** | `benchmark/results/investor_demo_summary.json` |

### Convergence status

- **Deterministic tests / corpus:** Wave 2 completion report claims **FULLY** for all five MVP bullets with pytest + detector metrics gates.
- **API benchmarks:** Still LLM-variable; require `OPENROUTER_API_KEY` (`cashtokens_mvp_completion_report.md` caveats).

### Open defects (documented in-repo)

| Defect | Source |
|--------|--------|
| Investor demo token category / amount cases fail (`demo_cat_voucher_003`, `demo_amt_payroll_003`) | `investor_demo_summary.json` |
| Negative demo case blocked by OpenRouter 402 | Same file |
| `cashtokenmvpstatus.md` predates Wave 2 — superseded but still present | Points readers to completion report |
| LLM synthesis variance on API benchmarks | Completion report "Remaining risks" |

### Wave 2 completeness

**Code and gates on `main` indicate Wave 2 is complete and merged** (PR #11, completion report, `wave2_benchmark_summary.json all_gates_pass: true`). Remaining work is **demo polish and API benchmark variance**, not missing Wave 2 phases.

---

## 8. Benchmark Infrastructure

### Suites (35 YAML files, 179 cases)

**Core BCH patterns:** `single_sig_transfer.yaml`, `timelock.yaml`, `hashlock.yaml`, `multisig.yaml`, `escrow.yaml`, `escrow_suite.yaml`, `refundable_payment.yaml`, `split_payment.yaml`, `vaults.yaml`, `vault_debug.yaml`, `covenant.yaml`, `stateful_suite.yaml`, `conditional_spend.yaml`, `decay.yaml`, `vesting.yaml`.

**CashTokens:** `cashtokens*.yaml` (11 files), investor demo suites (5 files).

**Harness / meta:** `test1.yaml`, `test2.yaml`, `test_linear.yaml`.

**Non-standard:** `benchmark/suites/vaults_real` — 24 cases, **missing `.yaml` extension**.

### Diagnosis & reporting tools

| Tool | Path | Purpose |
|------|------|---------|
| Runner | `benchmark/runner.py` | CLI entry; `--use-golden`, `--ids`, `--tags` |
| Evaluator | `benchmark/evaluator.py` | Capability-first scoring, 300s timeout, `disable_fallbacks=True` |
| Feature extractor | `benchmark/feature_extractor.py` | Regex/function-role feature detection |
| Semantic requirements | `benchmark/semantic_requirements.py` + `config/semantic_requirement_map.yaml` | Declarative requirement satisfaction |
| Reporter / compare | `benchmark/reporter.py`, `benchmark/compare.py` | Summaries + before/after MD |
| 11-pattern diagnosis | `benchmark/run_11_pattern_diagnosis.py` | **Not yet producing committed artifacts** |
| Family runner | `scripts/run_family_benchmarks.py` | CashTokens families → MD report |
| Wave 2 runner | `scripts/run_wave2_benchmarks.py` | 2A–2D suites |
| Investor subset | `scripts/run_investor_demo*.py` (referenced in commits) | Partial demo runs |

### Evaluator architecture

1. `GuardedPipelineEngine.generate_guarded(disable_fallbacks=True)`
2. `FeatureExtractor` + `extract_semantic_capabilities`
3. `satisfies_requirement()` against YAML map
4. Convergence = compile + critical features + intent coverage threshold + semantic_pass / pattern relaxations (vault token paths)
5. Persist to `benchmark/results/bench_*.json` (**164 files** present)

### Blind spots

| Blind spot | Impact |
|------------|--------|
| No committed 11-pattern diagnosis JSON | Cannot track phase-level failure taxonomy over time |
| `vaults_real` filename | Easy to omit from standard suite runs |
| Duplicate `single_sig_transfer (1).yaml` | Inflated / confusing case counts |
| Aggregate metrics mix partial runs | Escrow 100% aggregate vs regression failure |
| Intent coverage decoupled from convergence | covenant 100% conv at 0.22 intent |
| Test suites (`test1`, `test2`) mixed into suite directory | Non-production cases alongside pattern suites |
| Benchmark defaults `disable_golden=True` | Golden path convergence not continuously measured |

---

## 9. Production Readiness Assessment

Scores are **0–10** based solely on in-repo evidence. **10 = production-ready for stated claims; 0 = missing or broken.**

| Subsystem | Score | Justification |
|-----------|-------|---------------|
| **Generation** | **6** | Full 4-phase pipeline on `main`; pattern profiles + rails for subset; LLM variance; escrow regression failure; split 50% latest conv |
| **Compilation** | **7** | `cashc` gate + structural integrity + micro-fixes; compile still dominant failure layer for weak patterns |
| **Toll Gate** | **7** | 32 detectors + invariant engine; critical-only gating; documented false positives; registry/docs drift |
| **Audit** | **7** | Live `/api/audit`; 19 detectors + audit lint; Wave 2C parity tests; separate implementation from generation |
| **Benchmarking** | **8** | 164 result artifacts, capability-first evaluator, Wave 2 + investor demo harnesses; blind spots on 11-pattern tracking |
| **CashTokens** | **8** | Wave 2 merged, family suites largely 100%, deterministic test gates; investor demo partial; API variance |

**Deployment / wallet (out of scope but referenced in README):**

- README describes deployment gate (score ≥ 75, det ≥ 50) — scoring exists in audit agent.
- **No wallet connection implementation** found in `src/server.py` (generation WS + audit/repair/edit REST only).
- **BCH / CashScript only** — no multi-chain evidence in pipeline code.

---

## 10. Next Highest ROI Work

Ranked by **evidence of pain × existing infrastructure** (not invented scope).

| Rank | Task | Impact | Effort | Risk | Why now |
|------|------|--------|--------|------|---------|
| 1 | **Split payment convergence** — compile failures dominate (`bench_20260331_2125_2cb6`: 50%) | High — investor checklist gap | Medium | Low | Worst latest-run core pattern; `_SPLIT_RAIL` exists but insufficient |
| 2 | **Vault evaluator alignment on `vaults_real`** — 67% latest conv, 35× `None` failure_layer | High — most benchmark investment | Medium | Medium | Generation semantically strong per session notes; scoring blocks convergence |
| 3 | **Publish 11-pattern diagnosis run** — commit JSON from `run_11_pattern_diagnosis.py` | High — roadmap visibility | Low | Low | Runner exists; artifact never committed; plan todo still pending |
| 4 | **Fix `vaults_real` suite path** — rename to `.yaml` | Medium | Trivial | None | 24 cases currently easy to skip |
| 5 | **Resolve escrow regression vs benchmark divergence** | Medium | Medium | Medium | `regression_results.json` FAILED vs benchmark 100% |
| 6 | **Decay / vesting LLM exhaustion** — 24 aggregate fallback failures | Medium | Medium | Low | Clear `failure_layer` signature in JSONs |
| 7 | **Investor demo failures** — category/amount/payroll cases | Medium | Medium | Low | `investor_demo_summary.json` PARTIAL gates |
| 8 | **Remove/fix `unified_rules` NameError** — 6 vault failures | Medium | Low | Low | Explicit runtime error in benchmark layers |
| 9 | **Intent scoring alignment** — hashlock/covenant low intent at convergence | Medium | Medium | Medium | Misleading GREEN classifications |
| 10 | **Audit/generation lint parity** — close LNC-020–027 audit gap | Medium | High | Medium | Documented drift in Section 6 |

---

## 11. Executive Summary

### Where we are

NexOps on `main` is a ** mature BCH CashScript generation and audit platform** with a **completed CashTokens Wave 2** merge (PR #11). Infrastructure for all **11 core BCH patterns** exists (suites, YAML rules, pattern profiles). **Benchmark evidence is uneven:** multisig and benchmark-escrow suites score well; **split payment is red**; **vault** has extensive runs but **~67% convergence** on real-world suite; **decay** aggregate is dragged down by vesting/LLM failures despite a clean 3-case `decay.yaml` latest run.

CashTokens deterministic gates pass; **investor demo and API benchmarks still show partial failures.**

### If we had 30 engineering days

Recommended allocation based on measured gaps (percentages sum to 100%):

| Share | Focus |
|-------|-------|
| **25%** | Split payment + conditional spend compile/convergence (shared payout/split mechanics) |
| **20%** | Vault evaluator + `vaults_real` integration (lint LNC-008/003 already partially addressed) |
| **15%** | 11-pattern diagnosis baseline + CI tracking (commit artifacts, fix suite blind spots) |
| **10%** | Escrow regression reconciliation (align regression harness with benchmark flags) |
| **10%** | Decay/vesting provider stability + retry policy |
| **8%** | Investor demo failing cases (token category / amount) |
| **7%** | Runtime bugs (`unified_rules` NameError) + benchmark timeout tuning |
| **5%** | Audit/generation lint parity (LNC-020+) |

### Bottom line

**Spend the next month primarily on core BCH pattern convergence (split → vault → measurement), not on new CashTokens features.** Wave 2 CashTokens is merged; remaining CashTokens work is **demo hardening and benchmark variance**, which is smaller ROI than closing the **split/vault** gaps visible in committed JSON evidence.

---

*Report generated from repository state at commit `0d3ae39` on branch `main`. Benchmark aggregates computed from 164 `benchmark/results/bench_*.json` files via in-repo analysis script (not committed).*
