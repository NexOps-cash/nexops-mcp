# Generation Failure Corpus — NexOps Phase 2 Composition Research

**Sprint:** Phase 2 Composition Research  
**Date:** 2026-06-20  
**Scope:** Research catalog only — no code changes  
**Sources:** [`statusjune.md`](../statusjune.md) §5 failure families; [`vault_generation_rca.md`](vault_generation_rca.md); [`refundable_generation_rca.md`](refundable_generation_rca.md); [`conditional_spend_phase1b_rca.md`](conditional_spend_phase1b_rca.md); [`structural_failure_analysis_split.md`](structural_failure_analysis_split.md); layer diagnosis docs; benchmark JSON artifacts cited in status report.

**Audit false positives:** Cross-reference [`false_positive_playbook.md`](false_positive_playbook.md) when generation failures overlap with audit classification mistakes (e.g., treasury prefunding, auth hallucination).

---

## Taxonomy

| Layer | Definition | Typical `failure_layer` label |
|-------|------------|-------------------------------|
| **routing** | Phase 1 intent → wrong `contract_type`, profile, or knowledge overlay | `routing`, implicit in retry exhaustion |
| **rail** | Missing or mis-injected pattern rail (`_SPLIT_RAIL`, `_VAULT_RAIL`, etc.) | Rare as first failure; secondary |
| **sanity** | Phase 4 regex/feature mismatch vs `IntentModel` | `Sanity`, triggers regen at `security_level=high` |
| **lint** | DSLLint LNC-* blocking violation | `Lint`, often mapped to `Compile` after exhaustion |
| **compile** | `cashc` failure or compile-fix loop exhaustion | `Compile` |
| **evaluator** | Code compiles; convergence blocked by feature/critical mismatch | `None` (35 vault cases), low intent |
| **timeout** | 300s `asyncio.wait_for` in benchmark evaluator | `Timeout` |
| **benchmark** | Suite spec, harness divergence, or infrastructure blind spot | Misleading GREEN/RED, checkpoint skip |

**Composition-blocking:** `yes` if pattern is RED on scorecard or explicitly blocks pairwise composition per [`composition_readiness_scorecard.md`](composition_readiness_scorecard.md).

---

## Corpus Statistics

| Layer | Entry count | Composition-blocking |
|-------|-------------|----------------------|
| lint | 28 | 12 |
| compile | 22 | 14 |
| evaluator | 18 | 4 |
| routing | 12 | 8 |
| timeout | 4 | 2 |
| benchmark | 8 | 3 |
| sanity | 4 | 2 |
| rail | 2 | 1 |
| **Total** | **98** | **32** |

---

## Split Payment (GF-001 – GF-012)

| ID | Pattern(s) | Layer | Root cause | Fix | Benchmark impact | Lessons learned | Composition-blocking |
|----|------------|-------|------------|-----|------------------|-----------------|----------------------|
| GF-001 | split_payment | lint | `canonical_pattern("split")` did not map to `split_payment` → `split_rules.yaml` never loaded | Profile alias fix (Phase 1A) | Pre-1A: 0% rules loaded | Routing alias must precede rail injection | yes |
| GF-002 | split_payment | lint | LNC-004 blocking on N-output conservation before alias fix | Load split_rules + LNC mode overrides | `bench_20260607_2109_cdbc` 0/2 compile | Rules and rails are independent gates | yes |
| GF-003 | split_payment | lint | LNC-015 multisig distribution shape rejected pre-1A | Split profile + multisig overlay | split_003 first failure Rules/Lint | Composite intents need dual profile | yes |
| GF-004 | split_payment | lint | LNC-005 implicit fee arithmetic on `input - payout` splits | Use param amounts or sum conservation `require()` | split_004 revenue share | Avoid subtraction in lint-strict modes | yes |
| GF-005 | split_payment | compile | `_dangling_require()` false positive on multiline `require()` — see [`structural_failure_analysis_split.md`](structural_failure_analysis_split.md) | Parenthesis-balanced `require()` scanner in `structural_integrity.py` | `bench_20260611_1344_cb95` 0/4 compile; post-hoc cashc 4/4 pass | Structural gate can block valid lint-passing code | yes |
| GF-006 | split_payment | compile | Compile never attempted after structural_integrity_post_lint skip | Same as GF-005 | 50% aggregate conv in statusjune; latest 3/6 | Dominant split failure is checker bug not LLM | yes |
| GF-007 | split_payment | compile | N-output conservation hardcoded for 2 outputs only | Extend `_SPLIT_RAIL` for 3–4 output treasury/payroll | `coverage_stability_results.json` `A_split_multisig` FAILED | Composition with multisig blocked at compile | yes |
| GF-008 | split_payment | routing | Token payroll routed to `ft_transfer` not split mode | Tag overlay for `split`+`cashtokens` intents | split_002 pre-overlay rules fail | CashToken splits need explicit mode | yes |
| GF-009 | split_payment | evaluator | split_004 missing `checkSig` in draft — auth not enforced | Prompt/rail owner signature requirement | Low intent 0.16 aggregate | Distribution without auth is compositional risk | yes |
| GF-010 | split_payment | benchmark | Low intent coverage (0.16) despite partial compile | Align `FeatureExtractor` with N-output shapes | Misleading YELLOW classification | Intent decoupled from compile in statusjune | yes |
| GF-011 | split_payment | lint | LNC-021 warning on BCH-only splits (non-blocking) | Document as warning-only | Does not block compile post-1B | Warning vs blocking severity matters | no |
| GF-012 | split_payment | rail | `_SPLIT_RAIL` exists but insufficient for 3+ output cases | Expand rail templates for treasury/payroll | Rail loaded=true yet compile fails | Rail presence ≠ convergence | yes |

---

## Vault (GF-013 – GF-038)

| ID | Pattern(s) | Layer | Root cause | Fix | Benchmark impact | Lessons learned | Composition-blocking |
|----|------------|-------|------------|-----|------------------|-----------------|----------------------|
| GF-013 | vault | lint | LNC-003 on tiered claim bodies without value anchor (`v_005`) | Golden multi-tier template; require `outputs[0].value == input.value` on claim paths | 60% compile rate v_005; vaults.yaml | Tiered vaults need explicit anchor per claim fn | no |
| GF-014 | vault | lint | LNC-016 on 2-output announce without value conservation (`v_008` vulnerable shape) | Adversarial synthesis mode (deferred) | Safe code emitted instead — AdversarialIntentNotMet | Pipeline refuses vulnerable vault by design | no |
| GF-015 | vault | timeout | 300s wall clock, 3 retries, `code: null` (`vr_010`) | Golden announce→delay→claim+cancel template | 50% timeout rate vr_010 | Success template exists; LLM over-explores | no |
| GF-016 | vault | timeout | Same timeout signature (`vr_023` founder treasury) | Golden founder-treasury: instantSpend + staged large + emergencyRecover | 17% timeout rate | Flaky not structural | no |
| GF-017 | vault | compile | Retry exhaustion before converged tiered artifact (`v_005`) | Phase 2 golden for 3-tier paths | Mapped to `Compile` in JSON | Coarse failure_layer hides lint-first | no |
| GF-018 | vault | compile | `unified_rules` NameError in pipeline runtime | Fix undefined symbol in synthesis path | 6 vault failures statusjune | Runtime errors masquerade as generation | no |
| GF-019 | vault | evaluator | `time_validation` not credited despite `this.age >= delay` (`v_001–v_005`) | Semantic map alias for vault staged delays | vaults.yaml avg 0.10 despite compile | Measurement-limited on canonical suite | no |
| GF-020 | vault | evaluator | `output_value_validation` miss on staged splits (`v_002`, `v_005`) | FeatureExtractor staged-split patterns | 7/8 vaults.yaml evaluator-first | Code correct; scorer wrong | no |
| GF-021 | vault | evaluator | Spurious `token_validation` on BCH-only vaults | Disable or scope token checks to token modes | Widespread vaults.yaml penalty | Same class as refundable FP | no |
| GF-022 | vault | evaluator | `multisig` feature miss (`vr_006`) | Map `checkMultiSig` recovery paths | vr_006 post-1A fix target | Vault+multisig composition almost-ready | no |
| GF-023 | vault | evaluator | `semantic_pass` false negative (`vr_009`) | Vault evaluator relaxations / capability layer | 1 case blocks 95% gate margin | Evaluator not generation for most vaults_real | no |
| GF-024 | vault | evaluator | `cancellation_path` when only `emergencyRecover` present (`vr_024`) | Prompt steer: require `cancel` naming | 86% conv vr_024; edge case | Naming conventions affect criticals | no |
| GF-025 | vault | evaluator | AdversarialIntentNotMet on safe staged code (`vr_020`) | Adversarial mode or accept safe emission | Failure case by design | Security-negative cases ≠ positive conv | no |
| GF-026 | vault | evaluator | 35× `failure_layer: None` with non-converged | Align evaluator with compiled code shapes | Dominant statusjune vault gap | None label = evaluator not compile | no |
| GF-027 | vault | lint | Historical LNC-008 terminal path false positive | Vault-aware LNC-008 patch in dsl_lint | Partially patched statusjune | Terminal path lint is vault-specific | no |
| GF-028 | vault | lint | Historical LNC-003 staged split not recognized | Vault profile disables LNC-005; staged splits allowed | Post-patch lint pass on success shapes | Profile-specific lint disable is intentional | no |
| GF-029 | vault | benchmark | `vaults_real` missing `.yaml` extension | Rename to `vaults_real.yaml` | 24 cases easy to skip | Infrastructure blind spot | no |
| GF-030 | vault | compile | Structural integrity abort on unbalanced braces during fix loop | Improve syntax repair loop | vault compile aborts statusjune | Repair loop can corrupt drafts | no |
| GF-031 | vault | routing | Escrow co-tag on vault intents (`v_003`, `vr_003`) | Informational — routing still lands vault | No first-failure impact | Feature enrichment side effects | no |
| GF-032 | vault | evaluator | `must_fail_permanent_covenant` unwired (`v_006`) | Failure-case critical wiring | Security-negative bucket | Same as esc_006 class | no |
| GF-033 | vault | compile | Unused variable on minimal drafts (`v_008`) | Compile micro-fix loop | Rare on adversarial case | Minor compile noise | no |
| GF-034 | vault | benchmark | 67% latest conv on vaults_real vs 92% compile | P0 timeout fix + evaluator alignment | Primary ROI per statusjune | Generation strong; measurement weak | no |
| GF-035 | vault | lint | LNC-003 on `claimMedium` missing value anchor (retry draft) | See GF-013 golden | Representative failing draft in RCA | LLM omits anchor on medium tier | no |
| GF-036 | vault | compile | `synthesis_failed_no_fallback` after lint retries | Propagate `last_failure_layer` to benchmark | Mislabeled as Compile | Observability gap | no |
| GF-037 | vault | evaluator | Partial score on multisig recovery (`v_007`) | Multisig feature aliases | score 0.20 | Composite vault+multisig needs eval fix | no |
| GF-038 | vault | benchmark | Diagnosis runner never committed JSON | Run `run_11_pattern_diagnosis.py` + commit | No phase-level taxonomy tracking | Measurement debt | no |

---

## Refundable Payment & Subscription (GF-039 – GF-052)

| ID | Pattern(s) | Layer | Root cause | Fix | Benchmark impact | Lessons learned | Composition-blocking |
|----|------------|-------|------------|-----|------------------|-----------------|----------------------|
| GF-039 | refundable_payment | lint | LNC-005 on covenant remainder `input.value - payoutAmount` (`rp_003`) | Canonical `refundable_subscription_escrow.cash` | 0% compile pre-1B | Simple dual-path passes all gates | yes |
| GF-040 | refundable_payment | lint | LNC-016 self-anchor at `outputs[2]` without conservation (`rp_004`) | Dual-path gradual release template | 0% compile pre-1B | 3-output covenant rejected | yes |
| GF-041 | refundable_payment | lint | LNC-010 nested `tx.time`; LNC-011 unguarded `/ duration` (`rp_004` formula) | Standalone `require(tx.time >= periodEnd)` paths | Formula vesting fails lint | Avoid proportional formulas in lint-strict gen | yes |
| GF-042 | refundable_payment | routing | 5/6 cases never load `refundable_payment_rules.yaml` | Routing overlay post-LLM normalization | Rules mismatch not first blocker | Benchmark pattern ≠ pipeline canonical | yes |
| GF-043 | refundable_payment | routing | rp_003 → `escrow`; rp_004 → `linear_vesting`/`decay` | Canonical templates bypass route | Secondary to lint | Templates decouple from route | yes |
| GF-044 | refundable_payment | sanity | Strict sanity blocked canonical templates (elapsed arithmetic) | Exemption for dual-path claim/cancel/refund | Phase 1B sanity fix shipped | Sanity can block good templates | yes |
| GF-045 | refundable_payment | evaluator | Spurious `token_validation` on BCH-only (`rp_001`, `rp_002`) | Phase 1A evaluator fix | avg score 0.064 pre-1A | Measurement not generation on positives | yes |
| GF-046 | refundable_payment | evaluator | `sha256_check` critical vs `hash160` codegen (`rp_002`) | Change critical to `ripemd160_check` | score 0.20 despite coverage 1.0 | BCH HTLC convention mismatch — see GF-067 | yes |
| GF-047 | refundable_payment | evaluator | `must_fail_wrong_time_field` on safe `tx.time` code (`rp_005`) | Adversarial generation mode | Safe code by design | Pipeline safety vs failure intents | no |
| GF-048 | refundable_payment | evaluator | Historical `output_value_validation` miss (`rp_006`) | Phase 1A re-score → 1.0 | Golden crowdfund path | Golden path converges when measured correctly | no |
| GF-049 | subscription | routing | No Phase 1 routing to subscription profile | Add subscription contract_type | Gen 25% inferred scorecard | Not first-class pattern | yes |
| GF-050 | subscription | lint | Inherits rp_003 escrow lint failures pre-canonical | Same as GF-039 | rp_003 variant only | Subscription blocked via refundable proxy | yes |
| GF-051 | subscription | benchmark | No dedicated generation YAML suite | Add subscription suite | 35% benchmarks scorecard | Doc-only audit profile | yes |
| GF-052 | refundable_payment | routing | rp_002 → `swap`/`conditional_spend` without `_SWAP_RAIL` | Tag `htlc`/`swap` in features | HTLC shape generates anyway | Rail omission non-blocking for compile | yes |

---

## Conditional Spend & Hashlock (GF-053 – GF-072)

| ID | Pattern(s) | Layer | Root cause | Fix | Benchmark impact | Lessons learned | Composition-blocking |
|----|------------|-------|------------|-----|------------------|-----------------|----------------------|
| GF-053 | conditional_spend | lint | LNC-010 on `tx.time <= deadline` inverted comparisons (`cs_004`) | Canonical dual-path: `spendFull` + `spendHalf` with `tx.time >= deadline` | Historical 0% compile cs_004 | LLM-natural time shapes fail lint | no |
| GF-054 | conditional_spend | lint | LNC-005 on `input.value - input.value/2` half path (`cs_004`) | Param `halfPayout` with `halfPayout * 2 == input.value` | Half-subtraction draft fails | Avoid fee-style subtraction | no |
| GF-055 | conditional_spend | lint | LNC-003 on half path under conditional_spend lint mode | Use full-input anchor or timelock mode template | lint_safe fails CS mode | Lint mode changes blocking rules | no |
| GF-056 | conditional_spend | routing | 4/5 cs_* cases route to timelock/covenant not conditional_spend | Phase 1 keyword overlay F2 | conditional_spend_rules never loaded | Profile exists but unused | no |
| GF-057 | conditional_spend | routing | cs_005 FAILURE CASE hijacked to `nft_minting_failure` | Skip CashToken failure router for CS signals F1 | 0% compile cs_005 | `"failure case"` string is dangerous | no |
| GF-058 | conditional_spend | compile | NFT minting failure drafts exhaust retries (`cs_005`) | Routing fix unblocks domain | Wrong contract family generated | Routing hijack dominates synthesis | no |
| GF-059 | conditional_spend | evaluator | Low score despite coverage 1.0 (`cs_001`) | Evaluator path scoring | 0.20 on valid dual-path | Scoring not just coverage | no |
| GF-060 | conditional_spend | evaluator | `this.age` vs `tx.time` mapping (`cs_002`) | Timelock alias in semantic map | time_validation miss | Relative vs absolute time confusion | no |
| GF-061 | conditional_spend | evaluator | Dual `checkSig` without `checkMultiSig` (`cs_003`) | Multisig feature detection | score 0.15 | Path isolation ≠ multisig | no |
| GF-062 | hashlock | routing | `swap` → `conditional_spend`; `hashlock_rules.yaml` not loaded | Optional hashlock overlay | Secondary debt | Compile succeeds without hashlock rules | no |
| GF-063 | hashlock | rail | `_SWAP_RAIL` not injected — features omit `htlc`/`swap` | Auto-tag HTLC intents | swap_rail_loaded false | Rail informational for hl_001–003 | no |
| GF-064 | hashlock | evaluator | `hash_verification`/`preimage_validation` miss pre-1A | Phase 1A hash aliases | hl_001–003 score ≈ 0 with valid hash | Fixed post-1A for validation subset | no |
| GF-065 | hashlock | compile | hl_004 compile failure historical | Free synthesis variance | 1/5 hashlock.yaml | Single compile failure in family | no |
| GF-066 | hashlock | evaluator | hl_005 safe code vs `must_fail_missing_token_validation` | Failure intent policy | Adversarial bucket | Safe emission expected | no |
| GF-067 | hashlock, refundable_payment | evaluator | `sha256_check` critical when intent unspecified (`rp_002`) | ripemd160_check or hash-agnostic critical | HTLC compositional blocker | BCH payment hash = hash160 | yes |
| GF-068 | hashlock | benchmark | Aggregate intent 0.19 despite 80% compile | Intent/feature alignment | YELLOW not GREEN | Low intent misleading | no |
| GF-069 | conditional_spend | compile | Retry exhaustion maps to Compile (`cs_004` historical) | Canonical template F3 | 60% suite conv | Flaky live can converge | no |
| GF-070 | conditional_spend | benchmark | cs_005 `must_fail_path_isolation` never reached | Fix routing then scope helper F6 | Failure case unmeasurable | Benchmark broken not just gen | no |
| GF-071 | hashlock | evaluator | `locktime_check` miss on hl_002 historical | Semantic requirement map | Post-1A pass | HTLC timeout path detection | no |
| GF-072 | conditional_spend | routing | cs_001 timelock + escrow incidental co-tag | Overlay to conditional_spend | Positives compile via timelock | Wrong knowledge still compiles | no |

---

## Escrow & Multisig (GF-073 – GF-082)

| ID | Pattern(s) | Layer | Root cause | Fix | Benchmark impact | Lessons learned | Composition-blocking |
|----|------------|-------|------------|-----|------------------|-----------------|----------------------|
| GF-073 | escrow | routing | esc_005/esc_006 diagnostics → `nft_minting` under disable_golden | Fix failure-case router for escrow | Benchmark still tagged escrow | Diagnostic vs benchmark divergence | no |
| GF-074 | escrow | evaluator | Missing `multisig`, `token_validation` on compiling esc_001–003 | Phase 1A feature aliases | All 6 esc.yaml compile; eval fail | Generation GREEN; eval YELLOW | no |
| GF-075 | escrow | compile | `regression_results.json` escrow FAILED compile_exhausted | Align regression harness flags | Conflicts with bench 100% conv | Harness divergence — statusjune † | no |
| GF-076 | escrow | routing | Phase 1 intent → type mismatch golden vs free synthesis | Document harness settings | Regression escrow failure family | Routing affects path selection | no |
| GF-077 | escrow | evaluator | esc_004 single-path code vs dual-destination intent | Generation quality improvement | cov 0.75 | Compile pass ≠ intent satisfaction | no |
| GF-078 | escrow | evaluator | esc_006 permanent covenant not scored as failure pass | Wire `must_fail_permanent_covenant` | Generation produced adversarial shape | Evaluator gap on negative cases | no |
| GF-079 | escrow | benchmark | escrow_suite.yaml 10/10 pass vs escrow.yaml eval fails | Role-based required features align | 95% benchmarks scorecard | Suite design matters more than rail | no |
| GF-080 | multisig | evaluator | Toll gate violations non-blocking (4 violations, SUCCESS) | Critical-only gating by design | regression multisig SUCCESS | Non-critical does not block | no |
| GF-081 | multisig | benchmark | Spurious `token_validation` on BCH-only multisig | Scope token checks | GREEN 100% conv | Audit FP class — see FP playbook | no |
| GF-082 | escrow, multisig | routing | `A_split_multisig` stability test FAILED compile | Fix split structural + N-output | Composition escrow+multisig+split blocked | Cross-pattern stability failure | yes |

---

## Timelock, Decay, Covenant (GF-083 – GF-092)

| ID | Pattern(s) | Layer | Root cause | Fix | Benchmark impact | Lessons learned | Composition-blocking |
|----|------------|-------|------------|-----|------------------|-----------------|----------------------|
| GF-083 | timelock | evaluator | `timestamp_based` not mapped (`tl_002`) | Semantic map CLTV vs timestamp | Validation subset 1 eval fail | Timelock almost-ready blocker | no |
| GF-084 | timelock | evaluator | `signature_verification` miss when no checkSig (`tl_001` historical) | Suite expects sig where intent omits | Historical eval fail | Unsigned timelock is eval not gen | no |
| GF-085 | timelock | evaluator | `block_height_based` miss (`tl_003`) | Height vs time feature aliases | Historical | Block height rare in gen | no |
| GF-086 | timelock | evaluator | `must_fail_wrong_time_field` on safe code (`tl_004`) | Adversarial mode | Failure bucket | Pipeline emits correct `tx.time` | no |
| GF-087 | timelock | lint | Historical LNC-008 on timelock terminal paths | Mode-conditional LNC-008 skip | Partially patched | Shared with vault FP class | no |
| GF-088 | decay | compile | LLM provider exhaustion / fallback exhausted | Retry policy + provider stability | 24+ aggregate decay hits | `failure_layer` explicit provider errors | no |
| GF-089 | decay | benchmark | vesting.yaml mixed into decay alias — heavy failures | Separate vesting metrics | Aggregate 64% compile decay | Alias pooling distorts RED/YELLOW | no |
| GF-090 | decay | routing | Complex vesting intents routed to linear_vesting | Canonical templates like refundable | rp_004 class overlap | Shared lint failures across patterns | yes |
| GF-091 | covenant | compile | Scattered compile failures in covenant suite | Compile fix loop + templates | 80% aggregate compile | Secondary to intent gap | no |
| GF-092 | covenant | evaluator | 100% compile at 0.22 intent coverage | FeatureExtractor covenant continuation | YELLOW classification | Intent decoupled — statusjune | no |

---

## CashTokens & Cross-Cutting (GF-093 – GF-098)

| ID | Pattern(s) | Layer | Root cause | Fix | Benchmark impact | Lessons learned | Composition-blocking |
|----|------------|-------|------------|-----|------------------|-----------------|----------------------|
| GF-093 | cashtokens_ft | benchmark | Investor demo `demo_cat_voucher_003` category fail | Token validation hardening | 10/12 investor demo | Wave 2 merged; demo polish remains | no |
| GF-094 | cashtokens_ft | benchmark | `demo_amt_payroll_003` amount fail | Amount detector alignment | PARTIAL categories 3–5 | API benchmark variance | no |
| GF-095 | cashtokens_nft | lint | Minting authority patterns — historical lint/toll | Wave 2 rails + detectors | minting 75% family bench | Lowest CashToken family conv | no |
| GF-096 | cashtokens_nft | routing | cs_005-style failure hijack to nft_minting_failure | Pattern-specific router guards | Cross-pattern contamination | CashToken router is global hazard | no |
| GF-097 | hybrid | benchmark | stablecoin_minter_sidecar — hybrid 100% conv | Golden + `_HYBRID_RAIL` | bench_realworld_011 | Composition-ready with escrow NFT | no |
| GF-098 | *all* | benchmark | `NEXOPS_BENCH_MAX_CASES_PER_PATTERN` defaults to 2 | Raise for diagnosis runs | Under-sampled patterns | Diagnosis runner blind spot | no |

---

## Audit Overlap & False Positive Cross-Links

Generation failures that mirror **audit** misclassification — consult [`false_positive_playbook.md`](false_positive_playbook.md):

| Corpus ID | FP entry | Symptom overlap |
|-----------|----------|-----------------|
| GF-021, GF-045, GF-081 | FP-004 | Spurious missing auth / token_validation on valid BCH-only code |
| GF-009, GF-082 | FP-002 | Unconstrained output flagged — split/payroll redirect class |
| GF-047, GF-025 | FP-003 | Safe code scored as failure — destruction/locking without attacker gain |
| GF-073, GF-057 | — | Failure-case routing hijack (generation-specific; no direct FP) |

When composing patterns, treat **evaluator false negatives** (GF-019–GF-026) separately from **audit FPs** — generation code may be correct while both benchmark and audit layers disagree.

---

## Composition-Blocking Summary

**Block composition (32 entries, `yes`):** All split_payment GF-001–GF-010, GF-012; refundable GF-039–GF-046, GF-049–GF-052; subscription GF-049–GF-051; hashlock/refundable GF-067; cross-pattern GF-082; decay/routing GF-090.

**Do not block (66 entries, `no`):** Vault timeout/evaluator class; escrow benchmark-green; CashTokens Wave 2; conditional spend after routing fix; timelock evaluator-only gaps.

**Executive alignment:** Matches [`composition_readiness_scorecard.md`](composition_readiness_scorecard.md) — Split RED, Refundable/Subscription No, Escrow/Multisig/FT/NFT Yes.

---

## Related Documents

- [`composition_readiness_scorecard.md`](composition_readiness_scorecard.md) — per-pattern composite readiness
- [`pattern_maturity_heatmap.md`](pattern_maturity_heatmap.md) — dimensional maturity scores
- [`false_positive_playbook.md`](false_positive_playbook.md) — audit FP institutional memory
- [`statusjune.md`](../statusjune.md) — generation convergence source of truth
