# Composition Benchmark Strategy

**Sprint:** Phase 2 Composition Research (Wave 4)  
**Branch:** `research/composition-sprint-v2`  
**Date:** 2026-06-20  
**Status:** Research specification only — **no runner, no JSON registry, no materialization authorized**

**Prerequisite:** Audit Research Sprint v1 complete ([`research_master_checklist.md`](research_master_checklist.md))  
**Anchors:** P0 top 20 from [`uncommon_contract_catalog.md`](uncommon_contract_catalog.md) §P0; pairwise feasibility from [`composition_matrix.md`](composition_matrix.md); maturity from [`composition_readiness_scorecard.md`](composition_readiness_scorecard.md)

---

## Executive Summary

NexOps Sprint v1 produced **180 single-pattern audit benchmarks** ([`benchmark_registry.json`](benchmark_registry.json)) measuring whether the auditor **detects** flaws in isolated families. Phase 2 requires a parallel **composition benchmark corpus** measuring whether generation and audit handle **interacting patterns** — the failure mode that blocks Payroll Treasury, DAO Treasury, and 46 catalog entries marked "Not yet."

**MEASURED:** Zero executable multi-pattern generation benchmarks exist today; `A_split_multisig` compile FAILED ([`composition_matrix.md`](composition_matrix.md)).  
**INFERRED:** L1 (2-pattern) benchmarks where both operands are Composite Ready (Escrow, Multisig, FT, NFT) can reuse Sprint v1 fixtures with composition tags.  
**PROJECTED:** Full 130-spec corpus materialization requires Split N-output fix + composition planner research before L3+ generation benches become meaningful.

This document defines **130 composition benchmark specifications** scoped P0-first, expanding L1→L4. Implementation deferred to a separate sprint.

---

## Relationship to Sprint v1 Benchmarks

| Corpus | Location | Count | Measures |
|--------|----------|-------|----------|
| Audit (single-family) | [`benchmark_registry.json`](benchmark_registry.json) | 180 | Detect flaws per pattern |
| Executable CI | [`benchmark_registry_executable.json`](benchmark_registry_executable.json) | 38 | Tier 1 deterministic |
| **Composition (this doc)** | Research spec only | **130** | Multi-pattern gen + audit interaction |

Composition specs **extend** (not replace) Sprint v1 entries via `parent_registry_ref` and `composition_level` fields proposed below.

---

## Per-Benchmark Spec Template

| Field | Description |
|-------|-------------|
| **id** | Stable key `comp_{tier}_{nnn}` or `comp_p0_{nnn}` |
| **level** | L1 (2-pattern) · L2 (3-pattern) · L3 (4-pattern) · L4 (5+) |
| **intent** | Natural-language business contract goal |
| **required_patterns** | Ordered pattern stack |
| **invariants** | Cross-pattern invariants (`invariant_id:ENFORCED\|MISSING`) |
| **expected_features** | Generation evaluator features that must pass |
| **expected_findings** | Audit rule IDs on secure baseline (empty) or mutant |
| **security_model** | Composed trust boundary summary |
| **eval_tier** | Maps to [`evaluation_modes.md`](evaluation_modes.md): `fast` · `standard` · `full` |
| **ci_tier** | 1 (detector) · 2 (policy) · 3 (live judge) per [`benchmark_strategy.md`](benchmark_strategy.md) |
| **uct_ref** | Catalog anchor when applicable |
| **matrix_cell** | Primary composition_matrix pair/triple |
| **mutant_id** | Interaction-emergent flaw variant (see [`composition_threat_model.md`](composition_threat_model.md)) |
| **label** | MEASURED · INFERRED · PROJECTED feasibility |

### Proposed Registry Extensions (research only)

```json
{
  "composition_level": "L1",
  "required_patterns": ["escrow", "multisig"],
  "parent_registry_ref": "escrow_basic_multisig",
  "composition_invariants": ["path_isolation:ENFORCED", "auth_gate:ENFORCED"],
  "interaction_mutant": "emergency_bypass_timelock"
}
```

---

## Evaluation Mode Alignment

| eval_tier | Pipeline | Composition use |
|-----------|----------|-----------------|
| **fast** | compile → lint → detectors | L1 token/escrow pairs; structural interaction FPs |
| **standard** | fast + intent invariants + policy | L2–L3 path isolation, timelock mutual exclusion |
| **full** | standard + live semantic judge | L4 governance bypass reasoning; trust-boundary composition |

| ci_tier | Mode | Composition coverage target |
|---------|------|----------------------------|
| **1** | `detector_only` / fast | ~85 specs — path leakage, token drift, missing auth on alternate path |
| **2** | `policy_only` / standard | ~30 specs — timelock bypass as invariant_gap vs trust_assumption |
| **3** | `full_audit` / full | ~15 specs — DAO emergency, cross-path treasury drain reasoning |

**Difficulty ladder** (from [`evaluation_modes.md`](evaluation_modes.md)): L1→difficulty 2–3; L2→3; L3→4; L4→5.

---

## §P0 — Top 20 Priority Composition Benchmarks

Deep specs for catalog §P0 contracts. These gate all L2+ expansion.

| id | level | uct_ref | intent | required_patterns | invariants | expected_features | expected_findings (secure) | security_model | eval_tier | ci_tier | label |
|----|-------|---------|--------|-------------------|------------|-------------------|---------------------------|----------------|-----------|---------|-------|
| comp_p0_001 | L4 | UCT-001 | Monthly payroll with 2-of-3 governance, staged vault, timelocked batches, fixed employee splits | Split+Multisig+Timelock+Vault | sum_conservation:ENFORCED; path_isolation:ENFORCED; timelock_mutual_exclusion:ENFORCED; auth_gate:ENFORCED | n_output_split; multisig_threshold; cltv_batches; vault_stages | [] | Owner + council; employees bound; emergency cannot skip vesting | standard | 2 | PROJECTED |
| comp_p0_002 | L3 | UCT-017 | DAO treasury spend via 2-of-3 after 7-day timelock with vault reserve | Multisig+Timelock+Vault | timelock_mutual_exclusion:ENFORCED; reserve_floor:ENFORCED; auth_gate:ENFORCED | multisig_spend; delay_enforced; vault_continuation | [] | Council multisig; timelock on normal path only | standard | 2 | INFERRED |
| comp_p0_003 | L3 | UCT-033 | Founder cliff vesting with monthly split distribution | Vault+Timelock+Split | cliff_enforced:ENFORCED; sum_conservation:ENFORCED; stage_continuation:ENFORCED | vault_cliff; cltv_release; split_n | [] | Founder bound; investors cannot accelerate | standard | 1 | PROJECTED |
| comp_p0_004 | L3 | UCT-034 | Investor linear vest with covenant state machine | Vault+Timelock+Covenant | continuation:ENFORCED; timelock_mutual_exclusion:ENFORCED | covenant_reanchor; staged_release | [] | Covenant terminates to bound states only | standard | 2 | INFERRED |
| comp_p0_005 | L3 | UCT-049 | Grant batch distribution with council approval and delay | Split+Timelock+Multisig | sum_conservation:ENFORCED; auth_gate:ENFORCED; delay_enforced:ENFORCED | split_n; multisig; cltv | [] | Grant committee 2-of-3 | standard | 1 | PROJECTED |
| comp_p0_006 | L3 | UCT-051 | Revenue share to FT holders via escrow release | Split+Escrow+FT | token_category_drift:ENFORCED; sum_conservation:ENFORCED; escrow_release_auth:ENFORCED | ft_preservation; escrow_2of3; split_ratio | [] | Escrow arbiter + FT category lock | fast | 1 | INFERRED |
| comp_p0_007 | L3 | UCT-065 | HTLC escrow: preimage claim or timeout refund | Escrow+Hashlock+Timelock | mutual_exclusion:ENFORCED; hash_preimage:ENFORCED; timeout_refund:ENFORCED | htlc_claim; htlc_refund; escrow_binding | [] | Hashlock + CLTV refund path isolated | standard | 1 | MEASURED |
| comp_p0_008 | L3 | UCT-066 | NFT escrow 2-of-3 with category preservation | Escrow+Multisig+NFT | nft_commitment:ENFORCED; auth_gate:ENFORCED; category_drift:ENFORCED | escrow_2of3_nft; token_category | [] | Arbiter multisig; NFT immutable | fast | 1 | MEASURED |
| comp_p0_009 | L3 | UCT-113 | Recovery vault: normal staged path vs 2-of-3 emergency after delay | Vault+Multisig+Timelock | path_isolation:ENFORCED; timelock_mutual_exclusion:ENFORCED | vault_stages; recovery_multisig; emergency_cltv | [] | Emergency cannot bypass active vesting | standard | 2 | INFERRED |
| comp_p0_010 | L3 | UCT-081 | Subscription treasury with split routing | Subscription+Split+Multisig | recurring_auth:ENFORCED; sum_conservation:ENFORCED | subscription_period; split_n; multisig | [] | **Conflicting pair** — spec documents expected failure | fast | 1 | PROJECTED |
| comp_p0_011 | L3 | UCT-002 | Token payroll with FT amounts and council sign-off | Split+FT+Multisig | token_amount_conservation:ENFORCED; auth_gate:ENFORCED | ft_transfer; split_n; multisig | [] | FT + multisig on distribute | standard | 1 | INFERRED |
| comp_p0_012 | L3 | UCT-067 | Milestone escrow release with 2-of-3 and timeout | Escrow+Multisig+Timelock | milestone_auth:ENFORCED; timeout_refund:ENFORCED | escrow_milestone; multisig; cltv | [] | Buyer/seller/arbiter | fast | 1 | MEASURED |
| comp_p0_013 | L3 | UCT-129 | Crowdfund goal with refund path and tier splits | Refundable+Split+Timelock | goal_threshold:ENFORCED; refund_isolation:ENFORCED; sum_conservation:ENFORCED | crowdfund_goal; split_tiers; refund_deadline | [] | Backers refunded if goal missed | standard | 2 | PROJECTED |
| comp_p0_014 | L3 | UCT-035 | NFT vesting vault with cliff and staged unlock | Vault+Timelock+NFT | nft_authority:ENFORCED; cliff_enforced:ENFORCED | vault_nft; timelock_cliff | [] | NFT authority retained through stages | fast | 1 | INFERRED |
| comp_p0_015 | L3 | UCT-114 | Emergency recovery via CondSpend without vault bypass | Vault+Multisig+CondSpend | path_isolation:ENFORCED; cond_branch_exclusive:ENFORCED | emergency_branch; vault_continuation | [] | Break-glass isolated from vesting | standard | 2 | INFERRED |
| comp_p0_016 | L4 | UCT-015 | Hybrid FT/NFT treasury with vault and council | FT+NFT+Vault+Multisig | hybrid_continuity:ENFORCED; auth_gate:ENFORCED | ft_nft_coherence; vault_stages; multisig | [] | Dual token types + governance | standard | 2 | INFERRED |
| comp_p0_017 | L3 | UCT-050 | Grant streaming vault with periodic split | Vault+Timelock+Split | stream_rate:ENFORCED; sum_conservation:ENFORCED | vault_stream; split_periodic | [] | Grantee bound; stream cannot over-release | standard | 1 | PROJECTED |
| comp_p0_018 | L3 | UCT-052 | Revenue decay treasury — covenant decay vs split | Vault+Covenant+Split | decay_monotonic:ENFORCED; sum_conservation:ENFORCED | covenant_decay; vault_reserve | [] | **Conflicting Split+Covenant** — decay-only path | standard | 2 | INFERRED |
| comp_p0_019 | L4 | UCT-003 | Payroll with governance recovery overriding normal path | Split+Multisig+Vault+Timelock | path_isolation:ENFORCED; governance_recovery_bounded:ENFORCED | split_n; recovery_2of3; vault; cltv | [] | Recovery cannot drain employee allocations | full | 3 | PROJECTED |
| comp_p0_020 | L3 | UCT-068 | Milestone escrow with partial refund on failure | Escrow+Refundable+Timelock | refund_isolation:ENFORCED; milestone_auth:ENFORCED | escrow_milestone; refund_path; cltv | [] | Milestone failure → refund not redirect | standard | 2 | INFERRED |

### P0 Mutant Variants (interaction-emergent)

| parent_id | mutant_id | expected_findings | maps_to_threat |
|-----------|-----------|-------------------|----------------|
| comp_p0_002 | emergency_bypass_timelock | timelock_bypass_composition | CT-001 |
| comp_p0_003 | split_redirect_emergency | split_redirection | CT-004 |
| comp_p0_007 | htlc_both_paths_open | path_isolation_violation | CT-006 |
| comp_p0_009 | recovery_skips_cltv | governance_recovery_bypass | CT-002 |
| comp_p0_011 | ft_mint_on_distribute | token_authority_leakage | CT-005 |
| comp_p0_016 | nft_drift_on_vault_stage | token_authority_leakage | CT-005 |
| comp_p0_019 | treasury_drain_via_recovery | treasury_drain_composition | CT-006 |

---

## L1 — Two-Pattern Benchmarks (40 specs)

Compatible and Conditional pairs from [`composition_matrix.md`](composition_matrix.md). **C**=Compatible, **N**=Conditional.

| id | matrix | intent | required_patterns | invariants | expected_features | expected_findings | security_model | eval_tier | label |
|----|--------|--------|-------------------|------------|-------------------|-------------------|----------------|-----------|-------|
| comp_l1_001 | Escrow+Multisig C | 2-of-3 escrow release | Escrow+Multisig | auth_gate:ENFORCED | escrow_2of3 | [] | Buyer/seller/arbiter | fast | MEASURED |
| comp_l1_002 | Escrow+Multisig C | Arbiter dispute path isolated | Escrow+Multisig | path_isolation:ENFORCED | dispute_function | [] | Dispute ≠ release | fast | MEASURED |
| comp_l1_003 | Escrow+Timelock C | Timeout refund after deadline | Escrow+Timelock | timeout_refund:ENFORCED | cltv_refund | [] | Depositor recovers | fast | MEASURED |
| comp_l1_004 | Escrow+Hashlock C | Preimage unlock escrow | Escrow+Hashlock | hash_preimage:ENFORCED | htlc_claim | [] | Hash reveals payout | standard | MEASURED |
| comp_l1_005 | Escrow+FT C | Token escrow 2-of-2 | Escrow+FT | token_category_drift:ENFORCED | ft_escrow | [] | Category preserved | fast | MEASURED |
| comp_l1_006 | Escrow+NFT C | NFT primary sale escrow | Escrow+NFT | nft_commitment:ENFORCED | escrow_nft | [] | Immutable NFT | fast | MEASURED |
| comp_l1_007 | Multisig+Timelock C | DAO spend delay | Multisig+Timelock | delay_enforced:ENFORCED | multisig_cltv | [] | Council + delay | standard | INFERRED |
| comp_l1_008 | Timelock+Hashlock C | Classic HTLC | Timelock+Hashlock | mutual_exclusion:ENFORCED | htlc_dual_path | [] | Claim XOR refund | standard | MEASURED |
| comp_l1_009 | Timelock+Vault C | Cliff vesting vault | Timelock+Vault | cliff_enforced:ENFORCED | vault_cliff | [] | Staged unlock | standard | INFERRED |
| comp_l1_010 | Timelock+CondSpend C | Event-triggered spend | Timelock+CondSpend | branch_exclusive:ENFORCED | cond_cltv | [] | Oracle branch gated | standard | INFERRED |
| comp_l1_011 | Hashlock+Refundable C | HTLC refund path | Hashlock+Refundable | refund_isolation:ENFORCED | htlc_refund | [] | rp_002 pattern | standard | MEASURED |
| comp_l1_012 | Hashlock+CondSpend C | Atomic swap branch | Hashlock+CondSpend | swap_atomicity:ENFORCED | swap_paths | [] | Single completion | standard | INFERRED |
| comp_l1_013 | Vault+Covenant C | Stateful vault continuation | Vault+Covenant | continuation:ENFORCED | covenant_reanchor | [] | State machine | standard | INFERRED |
| comp_l1_014 | Vault+NFT C | NFT locked in vault stages | Vault+NFT | nft_authority:ENFORCED | vault_nft | [] | Authority retained | fast | INFERRED |
| comp_l1_015 | Refundable+Subscription C | Annual plan refund window | Refundable+Subscription | refund_window:ENFORCED | subscription_refund | [] | Subscriber protection | standard | PROJECTED |
| comp_l1_016 | Covenant+FT C | Token supply covenant | Covenant+FT | supply_cap:ENFORCED | ft_covenant | [] | Mint bounded | fast | INFERRED |
| comp_l1_017 | Covenant+NFT C | NFT evolution states | Covenant+NFT | commitment_evolution:ENFORCED | nft_state | [] | Valid transitions only | standard | INFERRED |
| comp_l1_018 | FT+NFT C | Hybrid treasury wallet | FT+NFT | hybrid_continuity:ENFORCED | ft_nft_wallet | [] | Dual token coherence | fast | MEASURED |
| comp_l1_019 | Split+Escrow N | Revenue release then escrow hold | Split+Escrow | sum_conservation:ENFORCED | split_then_escrow | [] | Sequential paths | standard | PROJECTED |
| comp_l1_020 | Split+Timelock N | Delayed payroll distribution | Split+Timelock | delay_enforced:ENFORCED | split_cltv | [] | Monthly batches | standard | PROJECTED |
| comp_l1_021 | Split+Hashlock N | Atomic split swap | Split+Hashlock | hash_preimage:ENFORCED | split_htlc | [] | Preimage triggers split | standard | PROJECTED |
| comp_l1_022 | Split+Vault N | Staged payroll vault | Split+Vault | stage_continuation:ENFORCED | vault_split | [] | Vault then distribute | standard | PROJECTED |
| comp_l1_023 | Split+Refundable N | Crowdfund tier payout | Split+Refundable | goal_threshold:ENFORCED | refund_split | [] | Goal gate | standard | PROJECTED |
| comp_l1_024 | Split+CondSpend N | Conditional revenue split | Split+CondSpend | branch_exclusive:ENFORCED | cond_split | [] | Oracle-gated split | standard | PROJECTED |
| comp_l1_025 | Split+FT N | Token airdrop split | Split+FT | token_amount_conservation:ENFORCED | ft_split | [] | FT proportional | fast | INFERRED |
| comp_l1_026 | Split+NFT N | NFT royalty split | Split+NFT | nft_authority:ENFORCED | nft_split | [] | Royalty recipients | fast | INFERRED |
| comp_l1_027 | Escrow+Vault N | Escrow with vault staging | Escrow+Vault | path_isolation:ENFORCED | escrow_vault | [] | Partial release | standard | INFERRED |
| comp_l1_028 | Escrow+Refundable N | Milestone partial refund | Escrow+Refundable | refund_isolation:ENFORCED | escrow_refund | [] | Failure refund | standard | INFERRED |
| comp_l1_029 | Multisig+Hashlock N | Multisig-gated HTLC | Multisig+Hashlock | auth_gate:ENFORCED | ms_htlc | [] | Council + hash | standard | INFERRED |
| comp_l1_030 | Multisig+Vault N | Recovery multisig vault | Multisig+Vault | path_isolation:ENFORCED | ms_vault | [] | Emergency path | standard | INFERRED |
| comp_l1_031 | Multisig+FT N | Token treasury multisig | Multisig+FT | token_category_drift:ENFORCED | ms_ft | [] | FT governance | fast | INFERRED |
| comp_l1_032 | Multisig+NFT N | NFT multisig custody | Multisig+NFT | nft_commitment:ENFORCED | ms_nft | [] | Collective NFT | fast | INFERRED |
| comp_l1_033 | Timelock+Refundable N | Refund deadline | Timelock+Refundable | refund_deadline:ENFORCED | cltv_refund | [] | Time-bound refund | standard | INFERRED |
| comp_l1_034 | Vault+Refundable N | Vesting buyback | Vault+Refundable | buyback_isolation:ENFORCED | vault_buyback | [] | Optional exit | standard | INFERRED |
| comp_l1_035 | Escrow+CondSpend N | Oracle escrow release | Escrow+CondSpend | oracle_binding:ENFORCED | oracle_escrow | [] | Attestation gated | standard | INFERRED |
| comp_l1_036 | Escrow+Covenant N | Stateful escrow machine | Escrow+Covenant | continuation:ENFORCED | escrow_covenant | [] | Stage transitions | standard | INFERRED |
| comp_l1_037 | Multisig+CondSpend N | Multi-path governance | Multisig+CondSpend | branch_exclusive:ENFORCED | ms_cond | [] | Proposal branches | standard | INFERRED |
| comp_l1_038 | Multisig+Covenant N | DAO covenant spend | Multisig+Covenant | continuation:ENFORCED | ms_covenant | [] | Budget cap | standard | INFERRED |
| comp_l1_039 | CondSpend+FT N | Price-feed token release | CondSpend+FT | oracle_binding:ENFORCED | cond_ft | [] | Oracle datasig | standard | INFERRED |
| comp_l1_040 | Split+Multisig X | Payroll multisig distribute — **negative control** | Split+Multisig | routing_conflict:DOCUMENTED | — | compile_fail_expected | Documents X cell | fast | MEASURED |

---

## L2 — Three-Pattern Benchmarks (30 specs)

| id | uct_ref | intent | required_patterns | invariants | expected_features | expected_findings | security_model | eval_tier | label |
|----|---------|--------|-------------------|------------|-------------------|-------------------|----------------|-----------|-------|
| comp_l2_001 | UCT-019 | Governance timelock safe | Multisig+Timelock | delay_enforced:ENFORCED; auth_gate:ENFORCED | ms_cltv | [] | 2-of-3 delayed | standard | MEASURED |
| comp_l2_002 | UCT-023 | Delegate staking escrow | Escrow+Multisig+Timelock | stake_lock:ENFORCED; timeout_refund:ENFORCED | delegate_escrow | [] | Stake + timeout | fast | MEASURED |
| comp_l2_003 | UCT-036 | Employee cliff vault | Vault+Timelock | cliff_enforced:ENFORCED | employee_cliff | [] | 12-month cliff | standard | INFERRED |
| comp_l2_004 | UCT-053 | Milestone grant release | Escrow+Multisig+Timelock | milestone_auth:ENFORCED | grant_milestone | [] | Grant committee | fast | MEASURED |
| comp_l2_005 | UCT-070 | Real estate deposit | Escrow+Timelock+Multisig | deposit_lock:ENFORCED | re_escrow | [] | Deposit protection | fast | MEASURED |
| comp_l2_006 | UCT-073 | Token sale escrow | Escrow+FT+Timelock | token_category_drift:ENFORCED | token_sale | [] | FT sale lock | fast | MEASURED |
| comp_l2_007 | UCT-074 | NFT primary sale | Escrow+NFT+Multisig | nft_commitment:ENFORCED | nft_sale | [] | Primary market | fast | MEASURED |
| comp_l2_008 | UCT-097 | FT staking vault | Vault+FT+Timelock | stake_lock:ENFORCED | ft_stake | [] | Staked FT | fast | INFERRED |
| comp_l2_009 | UCT-115 | Social recovery wallet | Multisig+Timelock+Vault | recovery_bounded:ENFORCED | social_recovery | [] | Guardian recovery | standard | INFERRED |
| comp_l2_010 | UCT-116 | Guardian timelock recovery | Timelock+Multisig+Vault | timelock_mutual_exclusion:ENFORCED | guardian_recovery | [] | Delayed guardians | standard | INFERRED |
| comp_l2_011 | UCT-123 | NFT recovery escrow | Escrow+NFT+Multisig | nft_authority:ENFORCED | nft_recovery | [] | Lost key recovery | fast | MEASURED |
| comp_l2_012 | UCT-131 | All-or-nothing crowdfund | Refundable+Timelock | goal_threshold:ENFORCED | aon_crowdfund | [] | Goal gate | standard | INFERRED |
| comp_l2_013 | UCT-145 | Atomic swap HTLC | Hashlock+Timelock+CondSpend | swap_atomicity:ENFORCED | atomic_swap | [] | Cross-chain style | standard | INFERRED |
| comp_l2_014 | UCT-146 | P2P trade escrow | Escrow+Multisig+FT | token_category_drift:ENFORCED | p2p_trade | [] | FT P2P | fast | MEASURED |
| comp_l2_015 | UCT-147 | NFT marketplace | Escrow+NFT+Multisig | nft_commitment:ENFORCED | nft_market | [] | Marketplace | fast | MEASURED |
| comp_l2_016 | UCT-149 | Limit order hashlock | Hashlock+Escrow+Timelock | mutual_exclusion:ENFORCED | limit_order | [] | Order book style | standard | INFERRED |
| comp_l2_017 | UCT-153 | NFT auction escrow | Escrow+NFT+Timelock | auction_close:ENFORCED | nft_auction | [] | Timed auction | fast | MEASURED |
| comp_l2_018 | UCT-161 | Oracle-gated escrow | CondSpend+Escrow+Timelock | oracle_binding:ENFORCED | oracle_escrow | [] | Oracle attestation | standard | INFERRED |
| comp_l2_019 | UCT-177 | Stateful escrow machine | Covenant+Escrow+Timelock | continuation:ENFORCED | stateful_escrow | [] | Multi-stage | standard | INFERRED |
| comp_l2_020 | UCT-040 | Revocable grant vest | Vault+Multisig+Timelock | revocation_bounded:ENFORCED | revocable_vest | [] | Council revoke | standard | INFERRED |
| comp_l2_021 | UCT-055 | Matching fund vault | Vault+Refundable+Multisig | match_ratio:ENFORCED | matching_fund | [] | Matching grants | standard | INFERRED |
| comp_l2_022 | UCT-078 | Partial release escrow | Escrow+Vault+Timelock | partial_release:ENFORCED | partial_escrow | [] | Incremental | standard | INFERRED |
| comp_l2_023 | UCT-105 | Multi-token swap | Escrow+FT+Hashlock | swap_atomicity:ENFORCED | multi_swap | [] | Multi-asset | standard | INFERRED |
| comp_l2_024 | UCT-118 | Key rotation escrow | Escrow+Multisig+Hashlock | rotation_auth:ENFORCED | key_rotation | [] | Key upgrade | standard | INFERRED |
| comp_l2_025 | UCT-132 | Milestone crowdfund | Refundable+Escrow+Multisig | milestone_refund:ENFORCED | cf_milestone | [] | Milestone gates | standard | INFERRED |
| comp_l2_026 | UCT-008 | Department budget split | Split+Multisig+Timelock | sum_conservation:ENFORCED | dept_budget | [] | Dept allocations | standard | PROJECTED |
| comp_l2_027 | UCT-010 | Payroll holdback | Escrow+Split+Timelock | holdback_isolation:ENFORCED | holdback | [] | Salary holdback | standard | PROJECTED |
| comp_l2_028 | UCT-021 | Emergency DAO pause | Multisig+CondSpend+Timelock | pause_exclusive:ENFORCED | dao_pause | [] | Circuit breaker | standard | INFERRED |
| comp_l2_029 | UCT-043 | SAFT token vest | Vault+FT+Timelock | saft_lock:ENFORCED | saft_vest | [] | SAFT compliance | fast | INFERRED |
| comp_l2_030 | UCT-210 | Research sandbox | Escrow+Multisig+Timelock | sandbox_isolated:ENFORCED | research_escrow | [] | Controlled release | fast | MEASURED |

---

## L3 — Four-Pattern Benchmarks (25 specs)

| id | uct_ref | intent | required_patterns | invariants | expected_features | expected_findings | security_model | eval_tier | label |
|----|---------|--------|-------------------|------------|-------------------|-------------------|----------------|-----------|-------|
| comp_l3_001 | UCT-001 | Payroll treasury (reduced) | Split+Multisig+Timelock+Vault | sum_conservation:ENFORCED; path_isolation:ENFORCED | payroll_4pat | [] | Full payroll | standard | PROJECTED |
| comp_l3_002 | UCT-003 | Governance recovery payroll | Split+Multisig+Vault+Timelock | governance_recovery_bounded:ENFORCED | gov_payroll | [] | Recovery bounded | full | PROJECTED |
| comp_l3_003 | UCT-015 | Hybrid treasury | FT+NFT+Vault+Multisig | hybrid_continuity:ENFORCED | hybrid_4pat | [] | Dual token + gov | standard | INFERRED |
| comp_l3_004 | UCT-017 | DAO treasury full | Multisig+Timelock+Vault+CondSpend | timelock_mutual_exclusion:ENFORCED | dao_full | [] | DAO + emergency | full | INFERRED |
| comp_l3_005 | UCT-033 | Founder vesting split | Vault+Timelock+Split+Multisig | cliff_enforced:ENFORCED; sum_conservation:ENFORCED | founder_4pat | [] | Founder + split | standard | PROJECTED |
| comp_l3_006 | UCT-049 | Grant distribution | Split+Timelock+Multisig+Vault | grant_isolation:ENFORCED | grant_4pat | [] | Grant pipeline | standard | PROJECTED |
| comp_l3_007 | UCT-051 | Revenue sharing | Split+Escrow+FT+Multisig | revenue_conservation:ENFORCED | revenue_4pat | [] | Revenue pipeline | standard | INFERRED |
| comp_l3_008 | UCT-065 | HTLC escrow full | Escrow+Hashlock+Timelock+CondSpend | mutual_exclusion:ENFORCED | htlc_4pat | [] | Full HTLC | standard | INFERRED |
| comp_l3_009 | UCT-081 | Subscription treasury | Subscription+Split+Multisig+Vault | recurring_auth:ENFORCED | sub_treasury | compile_fail_expected | Conflicting | fast | PROJECTED |
| comp_l3_010 | UCT-114 | Emergency recovery | Vault+Multisig+CondSpend+Timelock | path_isolation:ENFORCED | emergency_4pat | [] | Break-glass | full | INFERRED |
| comp_l3_011 | UCT-129 | Crowdfund refundable | Refundable+Split+Timelock+Multisig | refund_isolation:ENFORCED | crowdfund_4pat | [] | Crowdfund tiers | standard | PROJECTED |
| comp_l3_012 | UCT-064 | Open source bounty | Escrow+Split+Multisig+Timelock | bounty_auth:ENFORCED | bounty_4pat | [] | Bounty pool | standard | PROJECTED |
| comp_l3_013 | UCT-022 | Quadratic funding | Vault+Split+Multisig+Timelock | qf_matching:ENFORCED | qf_4pat | [] | QF treasury | standard | PROJECTED |
| comp_l3_014 | UCT-039 | Performance vest | Vault+Escrow+Timelock+Multisig | performance_gate:ENFORCED | perf_vest | [] | KPI gated | standard | INFERRED |
| comp_l3_015 | UCT-060 | Impact bond | Escrow+CondSpend+Timelock+Multisig | impact_oracle:ENFORCED | impact_bond | [] | Outcome bond | full | INFERRED |
| comp_l3_016 | UCT-072 | Dispute arbitration | Escrow+Multisig+CondSpend+Timelock | dispute_isolation:ENFORCED | dispute_4pat | [] | Arbiter path | standard | INFERRED |
| comp_l3_017 | UCT-079 | Multi-party vault escrow | Escrow+Vault+Multisig+Timelock | multi_party_auth:ENFORCED | multi_escrow | [] | N-party | standard | INFERRED |
| comp_l3_018 | UCT-100 | NFT collection drop | NFT+Covenant+Timelock+Multisig | drop_cap:ENFORCED | nft_drop | [] | Limited drop | standard | INFERRED |
| comp_l3_019 | UCT-124 | Treasury emergency drain | Vault+Multisig+CondSpend+Timelock | drain_bounded:ENFORCED | emergency_drain | [] | Bounded drain | full | INFERRED |
| comp_l3_020 | UCT-140 | Multi-tier crowdfund | Refundable+Split+Multisig+Timelock | tier_isolation:ENFORCED | tier_cf | [] | Tier refunds | standard | PROJECTED |
| comp_l3_021 | UCT-150 | DEX router | CondSpend+FT+Escrow+Hashlock | router_atomicity:ENFORCED | dex_router | [] | Swap router | standard | INFERRED |
| comp_l3_022 | UCT-167 | Multi-oracle threshold | CondSpend+Escrow+Multisig+Timelock | oracle_quorum:ENFORCED | multi_oracle | [] | Oracle quorum | full | INFERRED |
| comp_l3_023 | UCT-182 | Payroll state covenant | Covenant+Split+Multisig+Timelock | state_continuation:ENFORCED | payroll_cov | routing_conflict | Split+Covenant X | standard | PROJECTED |
| comp_l3_024 | UCT-195 | Prize pool escrow | Escrow+Split+Multisig+Timelock | prize_conservation:ENFORCED | prize_pool | [] | Winner split | standard | PROJECTED |
| comp_l3_025 | UCT-198 | Safe deposit box | Multisig+Vault+Timelock+CondSpend | deposit_isolation:ENFORCED | safe_deposit | [] | Bank-style | standard | INFERRED |

---

## L4 — Five+ Pattern Benchmarks (15 specs)

| id | uct_ref | intent | required_patterns | invariants | expected_features | expected_findings | security_model | eval_tier | label |
|----|---------|--------|-------------------|------------|-------------------|-------------------|----------------|-----------|-------|
| comp_l4_001 | UCT-001 | Payroll treasury full stack | Split+Multisig+Timelock+Vault+CondSpend | all_paths_isolated:ENFORCED | payroll_l4 | [] | Enterprise payroll | full | PROJECTED |
| comp_l4_002 | UCT-003 | Payroll governance recovery L4 | Split+Multisig+Vault+Timelock+Refundable | recovery_bounded:ENFORCED | gov_payroll_l4 | [] | Gov + refund | full | PROJECTED |
| comp_l4_003 | UCT-015 | Hybrid FT/NFT treasury L4 | FT+NFT+Vault+Multisig+Timelock | hybrid_continuity:ENFORCED | hybrid_l4 | [] | Protocol treasury | full | INFERRED |
| comp_l4_004 | UCT-206 | Multi-stage workflow | Vault+Escrow+Covenant+Timelock+Multisig | workflow_continuation:ENFORCED | workflow_l4 | [] | 5-stage workflow | full | INFERRED |
| comp_l4_005 | UCT-207 | Generic L5 composite | Split+Escrow+Multisig+Timelock+Vault+NFT | composition_planner_required:DOCUMENTED | generic_l5 | planner_required | Negative control | full | PROJECTED |
| comp_l4_006 | — | Example D (plan): vest+decay+split+NFT+multisig | Vault+Timelock+Covenant+Split+Multisig+NFT | decay_monotonic:ENFORCED | example_d | [] | Complex workflow | full | PROJECTED |
| comp_l4_007 | UCT-052 | Revenue decay treasury L4 | Vault+Covenant+Split+Multisig+Timelock | decay_no_split_bypass:ENFORCED | decay_l4 | [] | Decay treasury | full | INFERRED |
| comp_l4_008 | UCT-017 | DAO treasury L4 + FT reserve | Multisig+Timelock+Vault+FT+CondSpend | reserve_floor:ENFORCED | dao_ft_l4 | [] | DAO + token reserve | full | INFERRED |
| comp_l4_009 | UCT-049 | Grant distribution L4 | Split+Timelock+Multisig+Vault+Refundable | grant_refund_isolated:ENFORCED | grant_l4 | [] | Grant + clawback | full | PROJECTED |
| comp_l4_010 | UCT-129 | Crowdfund L4 full | Refundable+Split+Timelock+Escrow+Multisig | crowdfund_atomic:ENFORCED | crowdfund_l4 | [] | Full campaign | full | PROJECTED |
| comp_l4_011 | UCT-081 | Subscription treasury L4 | Subscription+Split+Multisig+Vault+Timelock | recurring_auth:ENFORCED | sub_l4 | compile_fail_expected | Conflicting pairs | fast | PROJECTED |
| comp_l4_012 | UCT-154 | Bonding curve covenant L4 | Covenant+FT+Split+Vault+Multisig | curve_monotonic:ENFORCED | bonding_l4 | routing_conflict | Split+Covenant | full | PROJECTED |
| comp_l4_013 | UCT-191 | Rolling window covenant L4 | Covenant+Timelock+Split+Vault+Multisig | window_reset:ENFORCED | rolling_l4 | routing_conflict | Split blocked | full | PROJECTED |
| comp_l4_014 | UCT-208 | Campus meal plan L4 | Vault+Subscription+Split+Multisig+Timelock | meal_credit:ENFORCED | meal_l4 | compile_fail_expected | Subscription blocked | fast | PROJECTED |
| comp_l4_015 | — | Protocol upgrade timelock L4 | Timelock+Multisig+Covenant+Vault+CondSpend | upgrade_isolated:ENFORCED | upgrade_l4 | [] | Protocol governance | full | INFERRED |

---

## Corpus Statistics

| Level | Count | Generatable today (INFERRED) | Blocked (MEASURED/PROJECTED) |
|-------|-------|------------------------------|------------------------------|
| P0 deep | 20 | 4 (MEASURED) | 16 |
| L1 | 40 | 12 (MEASURED) | 28 |
| L2 | 30 | 10 (MEASURED) | 20 |
| L3 | 25 | 2 (MEASURED) | 23 |
| L4 | 15 | 0 | 15 |
| **Total** | **130** | **28** | **102** |

---

## Materialization Phases (research recommendation — not authorized)

| Phase | Scope | Prerequisite | Effort (PROJECTED) |
|-------|-------|--------------|-------------------|
| **M0** | Materialize 12 MEASURED L1/L2 secure baselines as audit-only composition fixtures | Sprint v1 loader | 1 week |
| **M1** | P0 mutants CT-001–CT-006 as Tier 1 composition audit benches | M0 + threat model | 2 weeks |
| **M2** | L1 full table (40) as `composition_benchmark_registry.json` | Split N-output research complete | 3 weeks |
| **M3** | L2–L3 generation convergence benches | Composition planner research | 6–8 weeks |
| **M4** | L4 + full judge Tier 3 | M3 + multi-pattern audit architecture | 8–12 weeks |

---

## Related Documents

| Document | Relationship |
|----------|--------------|
| [`composition_matrix.md`](composition_matrix.md) | Pair feasibility per spec |
| [`composition_threat_model.md`](composition_threat_model.md) | Mutant taxonomy |
| [`uncommon_contract_catalog.md`](uncommon_contract_catalog.md) | UCT anchors |
| [`benchmark_strategy.md`](benchmark_strategy.md) | Sprint v1 tier model |
| [`evaluation_modes.md`](evaluation_modes.md) | fast/standard/full |
| [`pattern_coverage_roadmap.md`](pattern_coverage_roadmap.md) | Materialization order |
| [`research_master_checklist_v2.md`](research_master_checklist_v2.md) | Implementation gate |
