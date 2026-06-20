# BCH Contract Ecosystem Survey — Composition Strategy Input

**Sprint:** Phase 2 Composition Research  
**Date:** 2026-06-20  
**Scope:** Research survey — no code changes  
**Corpus:** [`audit_benchmark_realworld/`](../audit_benchmark_realworld/) (28 indexed contracts); [`BCH_Knowledge_Base-main`](../BCH_Knowledge_Base-main/) production patterns; NexOps golden/antipattern artifacts.

**Epistemic labels:** **MEASURED** = counted from repo artifacts; **INFERRED** = reasoned from partial evidence; **PROJECTED** = forward-looking composition implication.

---

## Executive Summary

The BCH/CashScript ecosystem visible in NexOps artifacts clusters around **UTXO-native multi-path contracts**: each `function` is an independent spending entry point with explicit `require()` guards on inputs, outputs, time, and (post-2023) CashTokens categories. **MEASURED:** 28 real-world audit benchmark slots span 11 families with 10 safe, 8 unsafe, 10 unknown classifications. **INFERRED:** Production patterns from BCH Knowledge Base emphasize DeFi AMMs, lending with oracle datasigs, NFT marketplaces, payroll/treasury splits, HTLC atomic swaps, and covenant-style state machines — all composable only where NexOps generation maturity is GREEN/YELLOW per [`composition_readiness_scorecard.md`](composition_readiness_scorecard.md). **PROJECTED:** Phase 2 composition should anchor on **Escrow + Multisig + CashTokens** (proven convergence) and defer **Split + Subscription** compositions until structural and routing debt clears.

---

## Corpus Overview — audit_benchmark_realworld/

Source: [`audit_benchmark_realworld/index.json`](../audit_benchmark_realworld/index.json)

| Metric | Value | Label |
|--------|-------|-------|
| Total indexed contracts | 28 | MEASURED |
| Safe | 10 | MEASURED |
| Unsafe | 8 | MEASURED |
| Unknown | 10 | MEASURED |
| Materialized `.cash` in corpus dir | Partial — provenance refs only | MEASURED (README) |
| Audited v2.1 | 8 entries | MEASURED |

### Family Distribution

| Family | Count | Safe | Unsafe | Unknown | Representative IDs |
|--------|-------|------|--------|---------|-------------------|
| escrow | 2 | 1 | 0 | 1 | rw_golden_escrow_001, rw_bench_escrow_001 |
| refundable_payment | 1 | 1 | 0 | 0 | rw_golden_refundable_001 |
| decay | 1 | 1 | 0 | 0 | rw_golden_vesting_001 |
| cashtokens_ft | 2 | 0 | 1 | 1 | rw_golden_ft_001, rw_fixture_cat_drift_vuln |
| cashtokens_nft | 4 | 1 | 3 | 0 | rw_golden_nft_imm_001, rw_antipattern_mint_001 |
| hybrid | 1 | 1 | 0 | 0 | rw_golden_hybrid_001 |
| covenant | 2 | 0 | 1 | 1 | rw_antipattern_covenant_001 |
| payroll | 2 | 1 | 1 | 0 | rw_class_payroll_fixed, rw_adv_one_sat_redirect |
| vault | 2 | 1 | 0 | 1 | rw_class_vault_timelock |
| oracle | 1 | 1 | 0 | 0 | rw_adv_oracle_price |
| multisig | 1 | 0 | 1 | 0 | rw_adv_partial_auth |
| hashlock | 1 | 0 | 0 | 1 | rw_bench_hashlock_001 |

**INFERRED:** Family coverage mirrors NexOps 11-pattern + CashTokens Wave 2 scope; gaps include standalone timelock, subscription, and conditional_spend as first-class real-world entries.

---

## Recurring Architectures

### 1. Multi-Signature Release Paths

**MEASURED:** Golden `escrow_2of3.cash`, `escrow_2of3_nft.cash`; classification matrix payroll; adversarial `dual_path_admin_public.cash`.

**Pattern structure:**
- Parameterized pubkeys (buyer, seller, arbiter)
- Distinct functions per resolution path: release, refund, arbitrate
- `checkMultiSig` threshold gates on each path

**BCH Knowledge Base alignment:** [`production-patterns.md`](../BCH_Knowledge_Base-main/examples/real-world/production-patterns.md) — escrow, multisig treasury, governance voting all use **function-per-path** idiom.

**Composition implication (PROJECTED):** Escrow + Multisig is lowest-risk 2-pattern compose (both GREEN on scorecard). NFT escrow golden already exists — **Escrow + CashTokens NFT** is production-shaped.

---

### 2. Time-Locked Refund / Claim Dual Paths

**MEASURED:** HTLC fixtures; `vault_with_timelock.cash`; golden `refundable_crowdfund.cash`; oracle_swap timelock refund.

**Pattern structure:**
- Path A: authorized party + optional preimage before deadline
- Path B: counterparty refund after `tx.time >= timeout` or `this.age >= blocks`
- Strict path isolation — no mixed `checkSig` + time in single function (CS-PATH-ISOLATION)

**INFERRED:** BCH HTLC convention uses `hash160(preimage)` not raw SHA256 — matches [`conditional_spend_phase1b_rca.md`](conditional_spend_phase1b_rca.md) rp_002 finding.

**Composition implication (PROJECTED):** Hashlock + Timelock HTLC feasible with golden template; evaluator critical alignment required (YELLOW patterns).

---

### 3. Staged Value / Covenant Continuation

**MEASURED:** Vault classification scenarios; `vulnerable_covenant.cash` (missing lockingBytecode continuation); Wave 2 covenant suites.

**Pattern structure:**
- Announce → delay → claim/cancel state machine
- `tx.outputs[i].lockingBytecode == this.activeBytecode` for covenant carry
- Value conservation: full re-anchor or explicit `input - withdrawAmount` split

**BCH Knowledge Base:** [`multi-contract-architecture.md`](../BCH_Knowledge_Base-main/concepts/multi-contract-architecture.md) — covenants chain UTXOs without account storage.

**Vulnerability class (MEASURED):** Missing continuation in `rw_antipattern_covenant_001` → funds stuck or path escape.

**Composition implication (PROJECTED):** Vault + Timelock compose at architecture level; NexOps vault evaluator debt blocks automated compose until YELLOW→GREEN.

---

### 4. N-Output Distribution / Payroll

**MEASURED:** `payroll_fixed_salary.cash`, `payroll_no_auth.cash`, `leaky_payout.cash`; split benchmark suite.

**Pattern structure:**
- Single input → N outputs with sum conservation `require(out0 + out1 + … == input.value)`
- Optional `tokenAmount` sum for FT payroll
- Authorization on `distribute()` entry

**Vulnerability class (MEASURED):**
- `intent_auth_gate` — distribute without checkSig (`payroll_no_auth`)
- One-satoshi redirect — unconstrained secondary output (`leaky_payout`)

**Composition implication (PROJECTED):** **Blocked** — Split RED on scorecard. Any composition requiring Split as primary distribution (payroll, revenue share, treasury) fails until structural_integrity fix (see [`generation_failure_corpus.md`](generation_failure_corpus.md) GF-005).

---

### 5. CashTokens — FT Transfer, Mint Authority, NFT Commitment

**MEASURED:** Golden FT/NFT transfers; `minting_authority_leak.cash`; `cashtokens_cat_drift_vulnerable.cash`; `stablecoin_minter_sidecar.cash` hybrid.

**Pattern structure:**
- `tokenCategory` equality on inputs/outputs
- NFT: `nftCommitment` preservation or intentional mutation path
- Minting: authority bytes32 suffix `0x02` handling per [`cashtokens/overview.md`](../BCH_Knowledge_Base-main/cashtokens/overview.md)

**BCH Knowledge Base production patterns (INFERRED):** AMM, lending, NFT marketplace examples all repeat category + amount validation — aligns with NexOps Wave 2 detector stack (32 generation / 19 audit detectors per statusjune §6).

**Composition implication (PROJECTED):** **CashTokens FT + Escrow** and **NFT + Escrow** are scorecard-ready. Hybrid sidecar pattern suggests **PROJECTED** 3-pattern compose: minter sidecar + escrow + FT transfer for stablecoin-like flows.

---

### 6. Oracle-Bound Settlement

**MEASURED:** `oracle_swap.cash` — audited v2.1 safe baseline.

**Pattern structure:**
- `checkDataSig(priceData, bytes(currentPrice), oracle)` on swap/liquidation paths
- On-chain binding of oracle pubkey; off-chain price honesty is trust assumption

**Audit KB cross-link:** [`false_positive_playbook.md`](false_positive_playbook.md) FP-006 — fabricated oracle exploit when input IS bound.

**Composition implication (INFERRED):** Oracle + Escrow/HTLC is architecturally common (BCH KB lending pattern) but NexOps oracle pattern lacks generation suite — **PROJECTED** Phase 3+ after conditional_spend/hashlock stabilize.

---

## Recurring Vulnerabilities

| Vulnerability | Ecosystem frequency | NexOps corpus evidence | Detector / lint | Label |
|---------------|--------------------|------------------------|-----------------|-------|
| Missing auth on payout | High | payroll_no_auth, split_004 drafts | intent_auth_gate, LNC auth rules | MEASURED |
| Output sum not conserved | High | leaky_payout, vault adversarial cases | LNC-003, LNC-016, payroll detectors | MEASURED |
| Covenant continuation break | Medium | vulnerable_covenant | continuation detectors, LNC-025 | MEASURED |
| Minting authority escape | Medium (CashTokens) | minting_authority_leak | MintingAuthorityEscape | MEASURED |
| Token category drift | Medium (CashTokens) | cat_drift_vulnerable | token_category_drift | MEASURED |
| Path isolation failure | Medium | cs_005 intent, partial_auth | must_fail_path_isolation | MEASURED |
| Time field misuse | Low–Medium | rp_005 adversarial (safe gen) | tx.time vs block.height | INFERRED |
| Dust / remainder redirect | Medium | ONE_SATOSHI_REDIRECT | AG-1 adversarial | MEASURED |
| Oracle input not bound | Low (when bound, FP) | oracle_swap secure | FP-006 playbook | MEASURED |
| Treasury prefunding narrative | Audit-only FP | payroll classification | FP-001 playbook | MEASURED |

**INFERRED:** BCH KB [`smart-contract-security.md`](../BCH_Knowledge_Base-main/best-practices/security/smart-contract-security.md) mirrors NexOps vulnerability taxonomy — input validation, time `>=`, least privilege, signature malleability awareness.

---

## Governance Models

| Model | On-chain mechanism | Off-chain assumption | Corpus examples | Label |
|-------|-------------------|---------------------|-----------------|-------|
| **2-of-3 escrow arbitration** | checkMultiSig(2, [buyer, seller, arbiter]) | Arbiter honesty | escrow_2of3*, rw_golden_escrow | MEASURED |
| **Single-owner vault + backup cancel** | owner announce/claim; backup cancel | Key custody | vault_with_timelock, vr_010 pattern | INFERRED |
| **Founder treasury ops limit** | instantSpend ≤ opsLimit; cold emergencyRecover | Ops key compromise bounded | vr_023 RCA pattern | INFERRED |
| **Refundable crowdfund** | goal threshold; full refund path | Campaign honesty off-chain | refundable_crowdfund | MEASURED |
| **Linear vesting schedule** | time-gated claim/refund dual path | Beneficiary identity | linear_vesting, rp_004 | MEASURED |
| **DAO-style multisig treasury** | m-of-n distribute | Signer collusion threshold | multisig benchmarks, BCH KB governance examples | INFERRED |
| **Oracle-gated DeFi** | checkDataSig from oracle pubkey | Oracle price honesty | oracle_swap, BCH KB lending | MEASURED |
| **NFT minting authority** | category suffix 0x02; commitment updates | Issuer policy | nft_minting fixtures | MEASURED |

**PROJECTED:** Composition strategy should **not** merge governance models with incompatible trust boundaries — e.g., do not compose Subscription recurring logic (off-chain billing assumption) with on-chain-only escrow until Subscription routing exists.

---

## BCH Knowledge Base — Production Pattern Taxonomy

Source: [`BCH_Knowledge_Base-main/examples/real-world/production-patterns.md`](../BCH_Knowledge_Base-main/examples/real-world/production-patterns.md)

| KB category | Patterns documented | NexOps pattern mapping | Generation readiness | Label |
|-------------|--------------------|-----------------------|---------------------|-------|
| DeFi — AMM | swap with fee, slippage | conditional_spend / cashtokens_ft | FT GREEN; CS YELLOW | INFERRED |
| DeFi — Lending | collateral ratio, liquidation | escrow + oracle + cashtokens_ft | Partial — oracle no gen suite | PROJECTED |
| NFT — Marketplace | list, buy, royalty | cashtokens_nft + escrow | NFT GREEN | INFERRED |
| Gaming — Item escrow | NFT + timeout refund | nft + escrow | GREEN pair | INFERRED |
| Payroll — Fixed/recurring | N-output distribute | split_payment + payroll audit | Split RED — blocked | MEASURED |
| Identity — NFT credentials | immutable NFT transfer | cashtokens_nft | GREEN | MEASURED |
| Stablecoin — Sidecar minter | hybrid mint + peg | hybrid + ft | hybrid 100% bench | MEASURED |

**Critical KB constraint (MEASURED):** CashScript functions **cannot call each other** — composition in BCH is **UTXO chaining across transactions**, not in-contract modular imports. NexOps "composition" therefore means **multi-pattern intent synthesis in a single contract** or **coordinated multi-contract deployment** per [`multi-contract-deployment.md`](../BCH_Knowledge_Base-main/sdk/deployment/multi-contract-deployment.md).

---

## Implications for Composition Strategy

### Tier 1 — Compose Now (MEASURED readiness)

| Composition | Architecture fit | NexOps evidence | Risk |
|-------------|-----------------|-----------------|------|
| Escrow + Multisig | 2-of-3 release paths | Both GREEN; golden exists | Low |
| Escrow + Timelock | refund after timeout | escrow_timeout_refund in timelock bench | Low |
| Escrow + CashTokens NFT | nft escrow golden | escrow_2of3_nft.cash | Low |
| Multisig + Timelock | backup spend delay | ms_006 benchmark | Low |
| FT transfer + Escrow | tokenized escrow | Wave 2 + escrow rails | Low |

### Tier 2 — Golden Template Only (INFERRED)

| Composition | Blocker | Unlock condition |
|-------------|---------|------------------|
| Vault + Timelock | Vault evaluator YELLOW | Phase 1A eval complete + timeout P0 |
| Vault + Multisig | vr_006 multisig FN | Evaluator alias fix |
| Hashlock + Timelock | Hashlock routing YELLOW | HTLC golden + ripemd160 critical |
| Conditional Spend + Timelock | cs_004 lint/routing | Canonical dual-path template |
| Covenant + Vault | Continuation eval partial | LNC-025 audit parity |

### Tier 3 — Blocked (MEASURED)

| Composition | Blocker | Corpus ID |
|-------------|---------|-----------|
| Split + *any* | structural_integrity + 50% conv | GF-005–007 |
| Subscription + *any* | No first-class pattern | GF-049–051 |
| Refundable + complex vesting | rp_004 class pre-1B | GF-040–041 |
| Split + Multisig payroll | A_split_multisig FAILED | GF-082 |

### Tier 4 — Ecosystem-Aligned but NexOps-Gap (PROJECTED)

| Composition | Ecosystem demand (BCH KB) | NexOps gap |
|-------------|--------------------------|------------|
| Lending + Oracle + FT | High in DeFi patterns | No lending gen; oracle audit-only |
| AMM + FT | KB SimpleAMM | conditional_spend + ft partial |
| DAO treasury + Payroll | KB governance | split blocked |
| Subscription + Escrow | SaaS recurring | subscription RED |

---

## Real-World → Benchmark Traceability

| Index ID | Provenance | Composition relevance | Audit status |
|----------|------------|----------------------|--------------|
| rw_golden_escrow_001 | knowledge/golden/escrow_2of3_nft.cash | Tier 1 NFT escrow compose | never_audited |
| rw_golden_refundable_001 | refundable_crowdfund.cash | Tier 2 refundable + timelock | never_audited |
| rw_golden_vesting_001 | linear_vesting.cash | Tier 2 with refundable canonical | never_audited |
| rw_golden_hybrid_001 | stablecoin_minter_sidecar.cash | Tier 1 FT hybrid | never_audited |
| rw_class_vault_timelock | VAULT_WITH_TIMELOCK scenario | Tier 2 vault+timelock | audited_v2_1 |
| rw_antipattern_covenant_001 | vulnerable_covenant.cash | Negative benchmark — continuation | never_audited |
| rw_antipattern_mint_001 | minting_authority_leak.cash | CashTokens security gate | never_audited |
| rw_adv_oracle_price | ORACLE_PRICE scenario | Oracle compose reference | audited_v2_1 |
| rw_adv_partial_auth | PARTIAL_AUTH_BYPASS | multisig path isolation | audited_v2_1 |
| rw_adv_one_sat_redirect | ONE_SATOSHI_REDIRECT | Split/payroll negative | audited_v2_1 |

**PROJECTED:** Materialize remaining 10 unknown entries (external hackathon, community FT, bench hashlock TBD) to close audit benchmark coverage gap before Phase 2 composite audit suites.

---

## Strategic Recommendations

1. **MEASURED:** Anchor Phase 2 composition benchmarks on Tier 1 pairs already GREEN — measure compose convergence before expanding matrix.

2. **INFERRED:** Import BCH KB production-pattern **structure** (function-per-path, category checks, datasig oracle binds) as golden templates — not raw LLM synthesis — for Tier 2 promotion.

3. **MEASURED:** Prioritize Split structural fix — ecosystem payroll/revenue patterns universally use multiline conservation `require()` that NexOps currently rejects (GF-005).

4. **PROJECTED:** Defer lending/AMM multi-pattern compose until conditional_spend routing overlay and oracle generation suites exist — ecosystem demand is high but NexOps maturity is low.

5. **MEASURED:** Use `audit_benchmark_realworld` unsafe entries as composition **negative controls** — any composed contract must still audit-clean on rw_class_payroll_fixed baseline and fail appropriately on rw_adv_* traps.

6. **INFERRED:** Cross-link audit FPs ([`false_positive_playbook.md`](false_positive_playbook.md)) when composing treasury/oracle patterns — composition must not introduce false CRITICAL findings on deployment assumptions.

---

## Related Documents

- [`composition_readiness_scorecard.md`](composition_readiness_scorecard.md) — executive readiness summary
- [`pattern_maturity_heatmap.md`](pattern_maturity_heatmap.md) — 12×10 dimensional scores
- [`generation_failure_corpus.md`](generation_failure_corpus.md) — 98 generation failure cases
- [`composition_matrix.md`](composition_matrix.md) — pairwise interaction matrix
- [`realworld_collection_strategy.md`](realworld_collection_strategy.md) — corpus expansion plan
- [`audit_benchmark_realworld/README.md`](../audit_benchmark_realworld/README.md) — index usage
