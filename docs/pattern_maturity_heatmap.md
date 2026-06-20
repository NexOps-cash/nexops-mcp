# Pattern Maturity Heatmap — NexOps Phase 2 Composition Research

**Sprint:** Phase 2 Composition Research  
**Date:** 2026-06-20  
**Purpose:** 12 patterns × 10 pipeline dimensions with 0–5 scores and traffic-light readiness  
**Executive summary:** See [`composition_readiness_scorecard.md`](composition_readiness_scorecard.md) — this document expands dimensional evidence from [`statusjune.md`](../statusjune.md) §3–§4.

**Scoring:** 0 = absent/broken; 5 = production-ready with committed benchmark evidence.  
**Traffic light:** **GREEN** ≥4.0 weighted avg & no composition blocker; **YELLOW** 2.5–3.9 or partial blocker; **RED** <2.5 or explicit composition block.

---

## Dimension Definitions

| Dimension | Measures | Primary evidence |
|-----------|----------|------------------|
| **Routing** | Phase 1 intent → correct `contract_type`, profile, knowledge overlay | Layer diagnosis docs; RCAs |
| **Knowledge** | Pattern rules YAML loaded (`*_rules.yaml`) | `pattern_profiles.py`, diagnostics JSON |
| **Rail** | Dedicated synthesis rail injected | `_SPLIT_RAIL`, `_ESCROW_RAIL`, etc. |
| **Sanity** | Phase 4 regex checks aligned with generated shapes | `sanity_checker.py`, refundable 1B fix |
| **Lint** | DSLLint pass rate on representative drafts | structural_failure_analysis, RCAs |
| **Compile** | `cashc` convergence from latest dedicated suite | statusjune §4 |
| **Evaluator** | Feature/critical satisfaction post-compile | Layer diagnosis first-failure counts |
| **Benchmark** | YAML suite + registry materialization completeness | scorecard Benchmarks % |
| **Security** | Adversarial/failure-case handling + toll gate coverage | security_patterns/, Wave 2 gates |
| **Audit KB** | Executable audit fixtures + detector coverage | coverage_gap_analysis, registry |

---

## Heatmap Matrix

| Pattern | Routing | Knowledge | Rail | Sanity | Lint | Compile | Evaluator | Benchmark | Security | Audit KB | **Avg** | **Light** |
|---------|:-------:|:---------:|:----:|:------:|:----:|:-------:|:---------:|:---------:|:--------:|:--------:|:-------:|:---------:|
| **Split Payment** | 2 | 3 | 4 | 3 | 2 | 1 | 2 | 3 | 3 | 4 | **2.7** | **RED** |
| **Escrow** | 5 | 5 | 4 | 5 | 5 | 5 | 3 | 5 | 4 | 5 | **4.6** | **GREEN** |
| **Multisig** | 5 | 5 | 3 | 5 | 5 | 5 | 4 | 4 | 4 | 5 | **4.5** | **GREEN** |
| **Timelock** | 5 | 4 | 2 | 5 | 4 | 5 | 3 | 3 | 3 | 4 | **3.8** | **YELLOW** |
| **Hashlock** | 3 | 3 | 2 | 5 | 5 | 4 | 3 | 3 | 3 | 3 | **3.4** | **YELLOW** |
| **Vault** | 5 | 5 | 5 | 4 | 4 | 4 | 2 | 5 | 4 | 4 | **4.2** | **YELLOW** |
| **Refundable Payment** | 2 | 2 | 3 | 3 | 3 | 3 | 3 | 3 | 3 | 4 | **2.9** | **RED** |
| **Subscription** | 1 | 1 | 1 | 2 | 2 | 1 | 1 | 2 | 2 | 2 | **1.5** | **RED** |
| **Conditional Spend** | 2 | 2 | 2 | 4 | 3 | 3 | 3 | 3 | 3 | 4 | **2.9** | **YELLOW** |
| **Covenant** | 3 | 4 | 2 | 4 | 4 | 4 | 2 | 3 | 3 | 4 | **3.3** | **YELLOW** |
| **CashTokens FT** | 5 | 5 | 5 | 5 | 5 | 5 | 5 | 5 | 5 | 5 | **5.0** | **GREEN** |
| **CashTokens NFT** | 5 | 5 | 5 | 5 | 5 | 4 | 4 | 4 | 5 | 5 | **4.7** | **GREEN** |

**Scorecard consistency check:**

| Pattern | Scorecard Composite | Heatmap Light | Aligned |
|---------|--------------------|--------------|---------|
| Split Payment | **No** (RED 50% conv) | RED | ✓ |
| Escrow | **Yes** (100%†) | GREEN | ✓ |
| Multisig | **Yes** | GREEN | ✓ |
| Timelock | Almost | YELLOW | ✓ |
| Hashlock | Almost | YELLOW | ✓ |
| Vault | Almost (67% conv) | YELLOW | ✓ |
| Refundable | **No** | RED | ✓ |
| Subscription | **No** | RED | ✓ |
| Conditional Spend | Partial | YELLOW | ✓ |
| Covenant | Partial | YELLOW | ✓ |
| CashTokens FT | **Yes** | GREEN | ✓ |
| CashTokens NFT | **Yes** | GREEN | ✓ |

---

## Per-Pattern Evidence (statusjune.md)

### Split Payment — RED (Avg 2.7)

| Dimension | Score | Evidence | Label |
|-----------|-------|----------|-------|
| Routing | 2 | Alias fix landed; token payroll still mis-routes to `ft_transfer` | MEASURED |
| Knowledge | 3 | `split_rules.yaml` loads post-1A; pre-1A fail | MEASURED |
| Rail | 4 | `_SPLIT_RAIL` injected when `split` in features | MEASURED |
| Sanity | 3 | Multisig split sanity partial | INFERRED |
| Lint | 2 | LNC-004/005/015 historical; structural FP dominates | MEASURED |
| Compile | 1 | Latest 50% conv `bench_20260331_2125_2cb6` | MEASURED |
| Evaluator | 2 | Intent 0.16; N-output feature gaps | MEASURED |
| Benchmark | 3 | 6 YAML cases; no composite gen bench | MEASURED |
| Security | 3 | Payroll audit fixtures exist | MEASURED |
| Audit KB | 4 | 88% audit scorecard; payroll.md | MEASURED |

**Blocker:** N-output conservation + structural_integrity FP — [`generation_failure_corpus.md`](generation_failure_corpus.md) GF-005–GF-007.

---

### Escrow — GREEN (Avg 4.6)

| Dimension | Score | Evidence | Label |
|-----------|-------|----------|-------|
| Routing | 5 | 6/6 esc.yaml route correctly | MEASURED |
| Knowledge | 5 | `escrow_rules.yaml` always loaded | MEASURED |
| Rail | 4 | `_ESCROW_RAIL` on timelock composites; not always required | MEASURED |
| Sanity | 5 | No sanity failures on converged runs | MEASURED |
| Lint | 5 | No blocking lint on suite | MEASURED |
| Compile | 5 | 100% latest `bench_20260331_2120_3d04` | MEASURED |
| Evaluator | 3 | esc.yaml eval fails; escrow_suite 10/10 pass | MEASURED |
| Benchmark | 5 | 16 YAML + registry 95% | MEASURED |
| Security | 4 | esc_005/006 adversarial partial | MEASURED |
| Audit KB | 5 | 92% audit; 6 fixtures | MEASURED |

**Caveat:** Regression harness FAILED — scorecard † — does not downgrade GREEN compile evidence.

---

### Multisig — GREEN (Avg 4.5)

| Dimension | Score | Evidence | Label |
|-----------|-------|----------|-------|
| Routing | 5 | Stable Phase 1 multisig enum | MEASURED |
| Knowledge | 5 | `multisig_rules.yaml` loaded | MEASURED |
| Rail | 3 | No dedicated multisig rail; not needed | INFERRED |
| Sanity | 5 | Multisig accountancy passes | MEASURED |
| Lint | 5 | No dominant lint failures | MEASURED |
| Compile | 5 | 100% `bench_20260331_2118_ff90` | MEASURED |
| Evaluator | 4 | 0.74 intent; distinctness detectors | MEASURED |
| Benchmark | 4 | 6 YAML cases | MEASURED |
| Security | 4 | ms_004/ms_005 failure bucket | MEASURED |
| Audit KB | 5 | 90% audit scorecard | MEASURED |

---

### Timelock — YELLOW (Avg 3.8)

| Dimension | Score | Evidence | Label |
|-----------|-------|----------|-------|
| Routing | 5 | All tl_* route to timelock | MEASURED |
| Knowledge | 4 | `timelock_rules.yaml`; no timelock-only executable fixture | INFERRED |
| Rail | 2 | No `[RAIL: TIMELOCK MODE]` exists | MEASURED |
| Sanity | 5 | No sanity blocks | MEASURED |
| Lint | 4 | LNC-008 historical FP patched | MEASURED |
| Compile | 5 | 100% latest compile | MEASURED |
| Evaluator | 3 | `timestamp_based` gap tl_002 | MEASURED |
| Benchmark | 3 | 5 YAML; 70% scorecard | INFERRED |
| Security | 3 | tl_004 failure case | MEASURED |
| Audit KB | 4 | 75% audit scorecard | INFERRED |

**Almost-ready:** Evaluator mapping is sole gap to composite Yes.

---

### Hashlock — YELLOW (Avg 3.4)

| Dimension | Score | Evidence | Label |
|-----------|-------|----------|-------|
| Routing | 3 | swap→conditional_spend acceptable coarse route | MEASURED |
| Knowledge | 3 | `hashlock_rules.yaml` never loaded | MEASURED |
| Rail | 2 | `_SWAP_RAIL` not injected without htlc tag | MEASURED |
| Sanity | 5 | No sanity blocks hl_001–003 | MEASURED |
| Lint | 5 | No lint-first failures | MEASURED |
| Compile | 4 | 80% latest; hl_004 compile fail | MEASURED |
| Evaluator | 3 | Post-1A pass hl_001–003; pre-1A score ≈0 | MEASURED |
| Benchmark | 3 | 5 YAML; 65% scorecard | MEASURED |
| Security | 3 | No hashlock-specific detector | MEASURED |
| Audit KB | 3 | 55% audit; 3 fixtures | MEASURED |

---

### Vault — YELLOW (Avg 4.2)

| Dimension | Score | Evidence | Label |
|-----------|-------|----------|-------|
| Routing | 5 | All diagnostics pass vault profile | MEASURED |
| Knowledge | 5 | `vault_rules.yaml` + VLT-* rules | MEASURED |
| Rail | 5 | `_VAULT_RAIL` always attached | MEASURED |
| Sanity | 4 | Regex disagreements with capability layer | MEASURED |
| Lint | 4 | LNC-003/008 patched; tiered retries remain | MEASURED |
| Compile | 4 | 92% vaults_real compile; 67% conv | MEASURED |
| Evaluator | 2 | 35× None failure_layer; vaults.yaml avg 0.10 | MEASURED |
| Benchmark | 5 | 34 cases; vaults_real 90% | MEASURED |
| Security | 4 | Staged spending; adversarial cases tracked | MEASURED |
| Audit KB | 4 | 85% audit; detectors partially disabled | INFERRED |

**Note:** High dimensional scores except Evaluator — matches "Almost" on scorecard.

---

### Refundable Payment — RED (Avg 2.9)

| Dimension | Score | Evidence | Label |
|-----------|-------|----------|-------|
| Routing | 2 | 5/6 mismatch benchmark pattern | MEASURED |
| Knowledge | 2 | Only rp_006 loads refundable_rules | MEASURED |
| Rail | 3 | Escrow/swap partial | MEASURED |
| Sanity | 3 | Phase 1B sanity fix for canonical | MEASURED |
| Lint | 3 | rp_003/004 lint blocked pre-1B; canonical shipped | MEASURED |
| Compile | 3 | 67% latest; rp_002 partial | MEASURED |
| Evaluator | 3 | Post-1A positives; rp_002 sha256 mismatch | MEASURED |
| Benchmark | 3 | 6 YAML; golden crowdfund | MEASURED |
| Security | 3 | rp_005 adversarial | MEASURED |
| Audit KB | 4 | 82% audit | MEASURED |

---

### Subscription — RED (Avg 1.5)

| Dimension | Score | Evidence | Label |
|-----------|-------|----------|-------|
| Routing | 1 | No Phase 1 subscription type | INFERRED |
| Knowledge | 1 | Doc-only `subscription.md` | INFERRED |
| Rail | 1 | None | INFERRED |
| Sanity | 2 | Inherits refundable issues | INFERRED |
| Lint | 2 | rp_003 proxy only | INFERRED |
| Compile | 1 | 25% gen scorecard | INFERRED |
| Evaluator | 1 | No suite | INFERRED |
| Benchmark | 2 | `subscription_secure.cash` fixture only | MEASURED |
| Security | 2 | Not in generation registry | INFERRED |
| Audit KB | 2 | 40% audit scorecard | INFERRED |

---

### Conditional Spend — YELLOW (Avg 2.9)

| Dimension | Score | Evidence | Label |
|-----------|-------|----------|-------|
| Routing | 2 | 4/5 cs_* wrong profile | MEASURED |
| Knowledge | 2 | conditional_spend_rules unused on cs_* | MEASURED |
| Rail | 2 | No CS rail; swap rail N/A | MEASURED |
| Sanity | 4 | Pass on compiling positives | MEASURED |
| Lint | 3 | cs_004 LNC-010 primary | MEASURED |
| Compile | 3 | 60% latest suite | MEASURED |
| Evaluator | 3 | Post-1A positives 1.0; historical 0.083 avg | MEASURED |
| Benchmark | 3 | 5 YAML | MEASURED |
| Security | 3 | cs_005 unmeasurable pre-routing fix | MEASURED |
| Audit KB | 4 | 70% audit; 4 cs fixtures | MEASURED |

---

### Covenant — YELLOW (Avg 3.3)

| Dimension | Score | Evidence | Label |
|-----------|-------|----------|-------|
| Routing | 3 | cs_003 routes covenant incidental | MEASURED |
| Knowledge | 4 | `covenant_rules.yaml` available | MEASURED |
| Rail | 2 | No covenant rail | INFERRED |
| Sanity | 4 | Generally passes | MEASURED |
| Lint | 4 | LNC-025 family generation-only | MEASURED |
| Compile | 4 | 100% latest 3/3 decay.yaml adjacency | MEASURED |
| Evaluator | 2 | Intent 0.22 at convergence | MEASURED |
| Benchmark | 3 | 6 YAML; 55% scorecard | MEASURED |
| Security | 3 | Continuation partial | INFERRED |
| Audit KB | 4 | 72% audit | INFERRED |

---

### CashTokens FT — GREEN (Avg 5.0)

| Dimension | Score | Evidence | Label |
|-----------|-------|----------|-------|
| All dimensions | 5 | Wave 2 gates pass; 100% family conv; 11 YAML suites | MEASURED |

Source: statusjune §7; `wave2_benchmark_summary.json` `all_gates_pass: true`.

---

### CashTokens NFT — GREEN (Avg 4.7)

| Dimension | Score | Evidence | Label |
|-----------|-------|----------|-------|
| Routing–Lint | 5 | Full rail stack | MEASURED |
| Compile | 4 | Minting 75%; immutable/mutable 100% | MEASURED |
| Evaluator | 4 | Commitment loss detector | MEASURED |
| Benchmark | 4 | NFT family suites 88% | MEASURED |
| Security | 5 | authority_leak fixtures | MEASURED |
| Audit KB | 5 | 92% audit | MEASURED |

---

## Composition Priority Matrix

Derived from heatmap × scorecard composite readiness:

```
HIGH (compose today):     Escrow, Multisig, CashTokens FT, CashTokens NFT
MEDIUM (golden-only):     Vault, Timelock, Hashlock, Conditional Spend, Covenant
LOW (blocked):            Split Payment, Refundable, Subscription
```

**Pairwise guidance:** See [`composition_matrix.md`](composition_matrix.md). Do not use Split as primary distribution layer until Compile ≥4 and structural_integrity fix lands.

---

## Dimensional Gap Ranking (Phase 2 ROI)

| Rank | Dimension | Weakest patterns | Recommended sprint focus |
|------|-----------|------------------|--------------------------|
| 1 | Compile | Split, Subscription | structural_integrity P0 |
| 2 | Routing | Subscription, Refundable, Conditional Spend | Phase 1 overlay normalization |
| 3 | Evaluator | Vault, Covenant, Timelock | Semantic map + critical aliases |
| 4 | Knowledge | Subscription, Hashlock | Load correct rules YAML |
| 5 | Rail | Timelock, Hashlock, Covenant | Optional — lower ROI per statusjune |

---

## Related Documents

- [`composition_readiness_scorecard.md`](composition_readiness_scorecard.md) — **executive summary** (Gen/Audit/Benchmarks/Composite Ready)
- [`generation_failure_corpus.md`](generation_failure_corpus.md) — 98 cataloged failure cases
- [`composition_matrix.md`](composition_matrix.md) — pairwise interaction matrix
- [`statusjune.md`](../statusjune.md) — convergence evidence §4
- [`false_positive_playbook.md`](false_positive_playbook.md) — Audit KB dimension cross-link
