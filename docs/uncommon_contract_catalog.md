# Uncommon Contract Catalog

**Sprint:** Phase 2 Composition Research
**Branch:** `research/composition-sprint-v2`
**Date:** 2026-06-20
**Purpose:** Catalog of 200+ multi-pattern business contracts for benchmark materialization and composition planner research.

**Related:**
- [`composition_readiness_scorecard.md`](composition_readiness_scorecard.md) — per-pattern Gen/Audit/Composite Ready
- [`composition_matrix.md`](composition_matrix.md) — pairwise compatibility and P0 deep-dives

---

## §P0 Top 20 Priority Contracts

Ranked by composition-matrix P0 examples, audit fixture coverage, and generation blockers (MEASURED/INFERRED from scorecard).

| Rank | ID | Contract | Patterns | Tier | Readiness | Rationale |
|------|-----|----------|----------|------|-----------|-----------|
| 1 | UCT-001 | Payroll Treasury | Split+Multisig+Timelock+Vault | L4 | Not yet | Split 50% RED; A_split_multisig FAILED; payroll audit assumes owner sig — composition_matrix P0 #1 |
| 2 | UCT-017 | DAO Treasury | Multisig+Timelock+Vault | L3 | Almost | Multisig+Timelock compatible; triple needs planner; dao_treasury.md KB |
| 3 | UCT-033 | Founder Vesting | Vault+Timelock+Split | L3 | Almost | Vault+Timelock C pair; rp_004 vesting compile fail blocks Split overlay |
| 4 | UCT-034 | Investor Vesting | Vault+Timelock+Covenant | L3 | Partial | Vault Almost + Covenant Partial; staged release golden feasible |
| 5 | UCT-049 | Grant Distribution | Split+Timelock+Multisig | L3 | Not yet | Split+Timelock Conditional but Split RED; grant batch audit exists |
| 6 | UCT-051 | Revenue Sharing | Split+Escrow+FT | L3 | Partial | Escrow+FT C; Split blocks primary distribution path |
| 7 | UCT-065 | HTLC Escrow | Escrow+Hashlock+Timelock | L3 | Almost | Triple Conditional; rp_002 HTLC fixture; hash160/sha256 evaluator gap |
| 8 | UCT-066 | NFT Escrow | Escrow+Multisig+NFT | L3 | Generatable today | Escrow+NFT C MEASURED; golden escrow_2of3_nft in _GOLDEN_TYPE_MAP |
| 9 | UCT-113 | Recovery Vault | Vault+Multisig+Timelock | L3 | Almost | Vault+Multisig Conditional; emergency path timelock bypass gap |
| 10 | UCT-081 | Subscription Treasury | Subscription+Split+Multisig | L3 | Not yet | Subscription not first-class; Split+Subscription X conflicting |
| 11 | UCT-002 | Token Payroll | Split+FT+Multisig | L3 | Partial | FT Yes; Split+Multisig X; FT+Escrow path workaround only |
| 12 | UCT-067 | Milestone Payout | Escrow+Multisig+Timelock | L3 | Generatable today | Escrow+Multisig+Timelock all pairwise C; 2-of-3 release golden |
| 13 | UCT-129 | Crowdfund Refundable | Refundable+Split+Timelock | L3 | Not yet | Refundable 67%; Split 50%; golden crowdfund bench exists |
| 14 | UCT-035 | NFT Vesting Contract | Vault+Timelock+NFT | L3 | Almost | Vault+NFT C Almost; no golden vault+nft composite gen |
| 15 | UCT-114 | Emergency Recovery Vault | Vault+Multisig+CondSpend | L3 | Almost | Vault+Multisig Conditional; CondSpend Partial overlay |
| 16 | UCT-015 | Hybrid FT/NFT Treasury | FT+NFT+Vault+Multisig | L4 | Partial | FT+NFT C; Vault+Multisig Conditional; L4 planner required |
| 17 | UCT-050 | Grant Streaming Vault | Vault+Timelock+Split | L3 | Almost | Vault+Timelock C; Split overlay blocks full synthesis |
| 18 | UCT-052 | Revenue Decay Treasury | Vault+Covenant+Split | L3 | Partial | Covenant+Split X conflicting; decay state machine doc only |
| 19 | UCT-003 | Payroll With Governance Recovery | Split+Multisig+Vault+Timelock | L4 | Not yet | L4; Split blocked; multisig payroll audit gap MEASURED |
| 20 | UCT-068 | Milestone Release Escrow | Escrow+Refundable+Timelock | L3 | Partial | Escrow+Refundable N Conditional; milestone golden partial |

---

## Field Legend

| Column | Description |
|--------|-------------|
| **ID** | Stable catalog key `UCT-NNN` |
| **Name** | Business contract label |
| **Patterns** | Ordered pattern stack (Split, Escrow, Multisig, Timelock, Hashlock, Vault, Refundable, Subscription, CondSpend, Covenant, FT, NFT) |
| **Tier** | Composition complexity L1–L5 per [`composition_matrix.md`](composition_matrix.md) |
| **Readiness** | NexOps synthesis readiness aligned to scorecard: **Generatable today** / **Almost** / **Partial** / **Not yet** |
| **Bench** | Benchmark materialization: **Y**=executable, **P**=stub/YAML, **N**=none |
| **Audit** | Audit fixture coverage: **Y**=executable, **P**=partial/doc, **N**=gap |
| **registry_ref** | Generation or audit registry key |
| **fixture_ref** | Primary `.cash` fixture path under `tests/fixtures/` |

**Readiness mapping:** Split/Subscription primary → **Not yet**; Escrow/Multisig/FT/NFT pairs → **Generatable today**; Timelock/Hashlock/Vault → **Almost**; CondSpend/Covenant → **Partial**.

---

## Payroll / Treasury

| ID | Name | Patterns | Tier | Readiness | Bench | Audit | registry_ref | fixture_ref |
|----|------|----------|------|-----------|-------|-------|--------------|-------------|
| UCT-001 | Payroll Treasury | Split+Multisig+Timelock+Vault | L4 | Not yet | N | N | `split_003_multisig_distribution` | `payroll/fixed_salary_secure.cash` |
| UCT-002 | Token Payroll | Split+FT+Multisig | L3 | Partial | P | P | `bench_token_payroll_001` | `cashtokens/ft_payroll_secure.cash` |
| UCT-003 | Payroll With Governance Recovery | Split+Multisig+Vault+Timelock | L4 | Not yet | N | N | `bench_payroll_gov_001` | `payroll/governance_recovery_secure.cash` |
| UCT-004 | Monthly Salary Vault | Vault+Timelock+Split | L3 | Almost | P | P | `bench_payroll_004` | `vault/monthly_salary_secure.cash` |
| UCT-005 | Contractor Batch Payout | Split+Multisig | L2 | Not yet | N | N | `bench_payroll_005` | `payroll/contractor_batch_secure.cash` |
| UCT-006 | Bonus Pool Treasury | Vault+Multisig+Split | L3 | Not yet | N | N | `bench_payroll_006` | `vault/bonus_pool_secure.cash` |
| UCT-007 | Overtime Accrual Vault | Vault+Timelock | L2 | Almost | P | P | `bench_payroll_007` | `vault/overtime_accrual_secure.cash` |
| UCT-008 | Department Budget Split | Split+Multisig+Timelock | L3 | Not yet | N | N | `bench_payroll_008` | `split/dept_budget_secure.cash` |
| UCT-009 | Executive Compensation Vault | Vault+Timelock+Covenant | L3 | Partial | P | P | `bench_payroll_009` | `vault/exec_comp_secure.cash` |
| UCT-010 | Payroll Escrow Holdback | Escrow+Split+Timelock | L3 | Partial | P | P | `bench_payroll_010` | `escrow/payroll_holdback_secure.cash` |
| UCT-011 | Multi-Currency Payroll | Split+FT+Vault | L3 | Partial | P | P | `bench_payroll_011` | `cashtokens/multi_currency_payroll_secure.cash` |
| UCT-012 | Payroll Audit Trail Vault | Vault+Covenant+Multisig | L3 | Partial | P | P | `bench_payroll_012` | `covenant/payroll_audit_secure.cash` |
| UCT-013 | Seasonal Workforce Treasury | Split+Timelock | L2 | Not yet | N | N | `bench_payroll_013` | `split/seasonal_workforce_secure.cash` |
| UCT-014 | Payroll Refund Recovery | Refundable+Split+Multisig | L3 | Not yet | N | N | `bench_payroll_014` | `refundable/payroll_refund_secure.cash` |
| UCT-015 | Hybrid FT/NFT Treasury | FT+NFT+Vault+Multisig | L4 | Partial | P | P | `bench_hybrid_treasury_001` | `cashtokens/hybrid_treasury_secure.cash` |
| UCT-016 | Treasury Yield Reserve | Vault+Timelock+FT | L3 | Almost | P | P | `bench_payroll_015` | `vault/yield_reserve_secure.cash` |

## DAO / Governance

| ID | Name | Patterns | Tier | Readiness | Bench | Audit | registry_ref | fixture_ref |
|----|------|----------|------|-----------|-------|-------|--------------|-------------|
| UCT-017 | DAO Treasury | Multisig+Timelock+Vault | L3 | Almost | P | P | `bench_dao_001` | `dao_treasury/timelock_multisig_secure.cash` |
| UCT-018 | Proposal Execution Vault | Multisig+Timelock+CondSpend | L3 | Partial | P | P | `bench_dao_002` | `dao_treasury/proposal_exec_secure.cash` |
| UCT-019 | Governance Timelock Safe | Multisig+Timelock | L2 | Generatable today | Y | Y | `bench_dao_003` | `multisig/governance_timelock_secure.cash` |
| UCT-020 | Council Multisig Treasury | Multisig+Vault | L2 | Almost | P | P | `bench_dao_004` | `dao_treasury/council_multisig_secure.cash` |
| UCT-021 | Emergency DAO Pause | Multisig+CondSpend+Timelock | L3 | Partial | P | P | `bench_dao_005` | `dao_treasury/emergency_pause_secure.cash` |
| UCT-022 | Quadratic Funding Vault | Vault+Split+Multisig | L3 | Not yet | N | N | `bench_dao_006` | `vault/quadratic_funding_secure.cash` |
| UCT-023 | Delegate Staking Escrow | Escrow+Multisig+Timelock | L3 | Generatable today | Y | Y | `bench_dao_007` | `escrow/delegate_stake_secure.cash` |
| UCT-024 | Governance NFT Gate | NFT+Multisig+Covenant | L3 | Partial | P | P | `bench_dao_008` | `cashtokens/governance_nft_gate_secure.cash` |
| UCT-025 | Treasury Diversification Split | Split+Multisig+FT | L3 | Not yet | N | N | `bench_dao_009` | `split/treasury_diversify_secure.cash` |
| UCT-026 | On-Chain Budget Covenant | Covenant+Multisig+Timelock | L3 | Partial | P | P | `bench_dao_010` | `covenant/onchain_budget_secure.cash` |
| UCT-027 | DAO Grant Committee | Multisig+Vault+Split | L3 | Not yet | N | N | `bench_dao_011` | `dao_treasury/grant_committee_secure.cash` |
| UCT-028 | Snapshot Execution Bridge | Multisig+Hashlock | L2 | Almost | P | P | `bench_dao_012` | `hashlock/snapshot_bridge_secure.cash` |
| UCT-029 | Protocol Upgrade Timelock | Timelock+Multisig+Covenant | L3 | Partial | P | P | `bench_dao_013` | `timelock/protocol_upgrade_secure.cash` |
| UCT-030 | Community Multisig Wallet | Multisig+FT | L2 | Partial | P | P | `bench_dao_014` | `multisig/community_wallet_secure.cash` |
| UCT-031 | Governance Recovery Vault | Vault+Multisig+Timelock | L3 | Almost | P | P | `bench_dao_015` | `vault/governance_recovery_secure.cash` |
| UCT-032 | Treasury Spend Cap Covenant | Covenant+Multisig+Vault | L3 | Partial | P | P | `bench_dao_016` | `covenant/treasury_spend_cap_secure.cash` |

## Vesting

| ID | Name | Patterns | Tier | Readiness | Bench | Audit | registry_ref | fixture_ref |
|----|------|----------|------|-----------|-------|-------|--------------|-------------|
| UCT-033 | Founder Vesting | Vault+Timelock+Split | L3 | Almost | P | P | `bench_vesting_001` | `vault/founder_cliff_secure.cash` |
| UCT-034 | Investor Vesting | Vault+Timelock+Covenant | L3 | Partial | P | P | `bench_vesting_002` | `vault/investor_linear_secure.cash` |
| UCT-035 | NFT Vesting Contract | Vault+Timelock+NFT | L3 | Almost | P | P | `bench_nft_vest_001` | `vault/nft_vesting_cliff_secure.cash` |
| UCT-036 | Employee Cliff Vault | Vault+Timelock | L2 | Almost | P | P | `bench_vesting_003` | `vault/employee_cliff_secure.cash` |
| UCT-037 | Advisor Token Vesting | Vault+Timelock+FT | L3 | Almost | P | P | `bench_vesting_004` | `vault/advisor_token_vest_secure.cash` |
| UCT-038 | Team Linear Release | Vault+Timelock+Split | L3 | Almost | P | P | `bench_vesting_005` | `vault/team_linear_secure.cash` |
| UCT-039 | Performance Milestone Vest | Vault+Escrow+Timelock | L3 | Almost | P | P | `bench_vesting_006` | `vault/performance_vest_secure.cash` |
| UCT-040 | Revocable Grant Vest | Vault+Multisig+Timelock | L3 | Almost | P | P | `bench_vesting_007` | `vault/revocable_grant_secure.cash` |
| UCT-041 | Dual Cliff Schedule | Vault+Covenant+Timelock | L3 | Partial | P | P | `bench_vesting_008` | `covenant/dual_cliff_secure.cash` |
| UCT-042 | NFT Royalty Vest | Vault+NFT+Timelock | L3 | Almost | P | P | `bench_vesting_009` | `vault/nft_royalty_vest_secure.cash` |
| UCT-043 | SAFT Token Vest | Vault+FT+Timelock | L3 | Almost | P | P | `bench_vesting_010` | `vault/saft_token_vest_secure.cash` |
| UCT-044 | Vesting with Buyback | Vault+Refundable+Timelock | L3 | Partial | P | P | `bench_vesting_011` | `vault/vesting_buyback_secure.cash` |
| UCT-045 | Accelerated Vest Trigger | Vault+CondSpend+Timelock | L3 | Partial | P | P | `bench_vesting_012` | `vault/accelerated_vest_secure.cash` |
| UCT-046 | Multi-Recipient Vest Split | Vault+Split+Timelock | L3 | Not yet | N | N | `bench_vesting_013` | `vault/multi_recipient_vest_secure.cash` |
| UCT-047 | Vesting Recovery Escrow | Escrow+Vault+Timelock | L3 | Almost | P | P | `bench_vesting_014` | `escrow/vesting_recovery_secure.cash` |
| UCT-048 | Contractor Milestone Vest | Vault+Escrow+Split | L3 | Partial | P | P | `bench_vesting_015` | `vault/contractor_milestone_vest_secure.cash` |

## Revenue / Grants

| ID | Name | Patterns | Tier | Readiness | Bench | Audit | registry_ref | fixture_ref |
|----|------|----------|------|-----------|-------|-------|--------------|-------------|
| UCT-049 | Grant Distribution | Split+Timelock+Multisig | L3 | Not yet | N | N | `bench_grant_001` | `payroll/grant_batch_secure.cash` |
| UCT-050 | Grant Streaming Vault | Vault+Timelock+Split | L3 | Almost | P | P | `bench_grant_stream_001` | `vault/grant_stream_secure.cash` |
| UCT-051 | Revenue Sharing | Split+Escrow+FT | L3 | Partial | P | P | `bench_revenue_001` | `split/revenue_share_secure.cash` |
| UCT-052 | Revenue Decay Treasury | Vault+Covenant+Split | L3 | Partial | P | P | `bench_revenue_decay_001` | `covenant/revenue_decay_secure.cash` |
| UCT-053 | Milestone Grant Release | Escrow+Multisig+Timelock | L3 | Generatable today | Y | Y | `bench_grant_002` | `escrow/milestone_grant_secure.cash` |
| UCT-054 | Retroactive Grant Payout | Split+Multisig | L2 | Not yet | N | N | `bench_grant_003` | `split/retroactive_grant_secure.cash` |
| UCT-055 | Matching Fund Vault | Vault+Refundable+Multisig | L3 | Partial | P | P | `bench_grant_004` | `vault/matching_fund_secure.cash` |
| UCT-056 | Royalty Split Treasury | Split+FT+Escrow | L3 | Partial | P | P | `bench_grant_005` | `split/royalty_split_secure.cash` |
| UCT-057 | Creator Revenue Share | Split+NFT+Escrow | L3 | Partial | P | P | `bench_grant_006` | `split/creator_revenue_secure.cash` |
| UCT-058 | Grant Refund Clawback | Refundable+Vault+Multisig | L3 | Partial | P | P | `bench_grant_007` | `refundable/grant_clawback_secure.cash` |
| UCT-059 | Streaming Micro-Grant | Vault+Timelock | L2 | Almost | P | P | `bench_grant_008` | `vault/micro_grant_stream_secure.cash` |
| UCT-060 | Impact Bond Payout | Escrow+CondSpend+Timelock | L3 | Partial | P | P | `bench_grant_009` | `escrow/impact_bond_secure.cash` |
| UCT-061 | DAO Grant Streaming | Vault+Multisig+Timelock | L3 | Almost | P | P | `bench_grant_010` | `vault/dao_grant_stream_secure.cash` |
| UCT-062 | Fee Sink Revenue Vault | Vault+Split+FT | L3 | Not yet | N | N | `bench_grant_011` | `vault/fee_sink_secure.cash` |
| UCT-063 | Partnership Revenue Escrow | Escrow+Split+FT | L3 | Partial | P | P | `bench_grant_012` | `escrow/partnership_revenue_secure.cash` |
| UCT-064 | Open Source Bounty Pool | Escrow+Split+Multisig | L3 | Partial | P | P | `bench_grant_013` | `escrow/opensource_bounty_secure.cash` |

## Escrow / Milestones

| ID | Name | Patterns | Tier | Readiness | Bench | Audit | registry_ref | fixture_ref |
|----|------|----------|------|-----------|-------|-------|--------------|-------------|
| UCT-065 | HTLC Escrow | Escrow+Hashlock+Timelock | L3 | Almost | P | P | `rp_002` | `refundable/htlc_refund_secure.cash` |
| UCT-066 | NFT Escrow | Escrow+Multisig+NFT | L3 | Generatable today | Y | Y | `escrow_2of3_nft` | `escrow/nft_two_of_three_secure.cash` |
| UCT-067 | Milestone Payout | Escrow+Multisig+Timelock | L3 | Generatable today | Y | Y | `escrow_milestone_001` | `escrow/milestone_release_secure.cash` |
| UCT-068 | Milestone Release Escrow | Escrow+Refundable+Timelock | L3 | Partial | P | P | `escrow_milestone_refund_001` | `escrow/milestone_refund_secure.cash` |
| UCT-069 | Freelance Delivery Escrow | Escrow+Multisig | L2 | Generatable today | Y | Y | `escrow_basic_multisig` | `escrow/two_of_three_secure.cash` |
| UCT-070 | Real Estate Deposit Escrow | Escrow+Timelock+Multisig | L3 | Generatable today | Y | Y | `bench_escrow_001` | `escrow/real_estate_deposit_secure.cash` |
| UCT-071 | Bounty Completion Escrow | Escrow+Hashlock | L2 | Almost | P | P | `bench_escrow_002` | `escrow/bounty_completion_secure.cash` |
| UCT-072 | Dispute Arbitration Escrow | Escrow+Multisig+CondSpend | L3 | Partial | P | P | `bench_escrow_003` | `escrow/dispute_arbitration_secure.cash` |
| UCT-073 | Token Sale Escrow | Escrow+FT+Timelock | L3 | Generatable today | Y | Y | `bench_escrow_004` | `escrow/token_sale_secure.cash` |
| UCT-074 | NFT Primary Sale Escrow | Escrow+NFT+Multisig | L3 | Generatable today | Y | Y | `bench_escrow_005` | `escrow/nft_primary_sale_secure.cash` |
| UCT-075 | Milestone Penalty Escrow | Escrow+Refundable+Multisig | L3 | Partial | P | P | `bench_escrow_006` | `escrow/milestone_penalty_secure.cash` |
| UCT-076 | Cross-Chain Swap Escrow | Escrow+Hashlock+CondSpend | L3 | Almost | P | P | `bench_escrow_007` | `escrow/cross_chain_swap_secure.cash` |
| UCT-077 | Service Level Escrow | Escrow+Timelock | L2 | Generatable today | Y | Y | `bench_escrow_008` | `escrow/service_level_secure.cash` |
| UCT-078 | Escrow with Partial Release | Escrow+Vault+Timelock | L3 | Almost | P | P | `bench_escrow_009` | `escrow/partial_release_secure.cash` |
| UCT-079 | Multi-Party Escrow Vault | Escrow+Vault+Multisig | L3 | Almost | P | P | `bench_escrow_010` | `escrow/multi_party_vault_secure.cash` |
| UCT-080 | Licensed IP Escrow | Escrow+Covenant+Timelock | L3 | Partial | P | P | `bench_escrow_011` | `escrow/licensed_ip_secure.cash` |

## Subscription

| ID | Name | Patterns | Tier | Readiness | Bench | Audit | registry_ref | fixture_ref |
|----|------|----------|------|-----------|-------|-------|--------------|-------------|
| UCT-081 | Subscription Treasury | Subscription+Split+Multisig | L3 | Not yet | N | N | `rp_003` | `refundable/subscription_secure.cash` |
| UCT-082 | SaaS Recurring Vault | Subscription+Vault+Timelock | L3 | Not yet | N | N | `bench_sub_001` | `subscription/saas_recurring_secure.cash` |
| UCT-083 | Membership NFT Subscription | Subscription+NFT+Multisig | L3 | Not yet | N | N | `bench_sub_002` | `subscription/membership_nft_secure.cash` |
| UCT-084 | Content Paywall Escrow | Subscription+Escrow | L2 | Not yet | N | N | `bench_sub_003` | `subscription/content_paywall_secure.cash` |
| UCT-085 | Annual Plan Refundable | Subscription+Refundable | L2 | Not yet | N | N | `bench_sub_004` | `subscription/annual_refund_secure.cash` |
| UCT-086 | Usage-Based Billing Vault | Subscription+Vault+Split | L3 | Not yet | N | N | `bench_sub_005` | `subscription/usage_billing_secure.cash` |
| UCT-087 | Family Plan Split Sub | Subscription+Split | L2 | Not yet | N | N | `bench_sub_006` | `subscription/family_plan_secure.cash` |
| UCT-088 | Trial Period Escrow | Subscription+Escrow+Timelock | L3 | Not yet | N | N | `bench_sub_007` | `subscription/trial_escrow_secure.cash` |
| UCT-089 | Governance Subscription Fee | Subscription+Multisig | L2 | Not yet | N | N | `bench_sub_008` | `subscription/governance_fee_secure.cash` |
| UCT-090 | Token-Gated Subscription | Subscription+FT+Vault | L3 | Not yet | N | N | `bench_sub_009` | `subscription/token_gated_secure.cash` |
| UCT-091 | Creator Patron Sub Vault | Subscription+Vault+NFT | L3 | Not yet | N | N | `bench_sub_010` | `subscription/creator_patron_secure.cash` |
| UCT-092 | Subscription Grace Period | Subscription+Timelock+Refundable | L3 | Not yet | N | N | `bench_sub_011` | `subscription/grace_period_secure.cash` |
| UCT-093 | Enterprise Seat License | Subscription+Multisig+Split | L3 | Not yet | N | N | `bench_sub_012` | `subscription/enterprise_seat_secure.cash` |
| UCT-094 | Streaming Media Sub Escrow | Subscription+Escrow+FT | L3 | Not yet | N | N | `bench_sub_013` | `subscription/streaming_media_secure.cash` |
| UCT-095 | Subscription Recovery Vault | Subscription+Vault+Multisig | L3 | Not yet | N | N | `bench_sub_014` | `subscription/recovery_vault_secure.cash` |
| UCT-096 | Metered API Subscription | Subscription+CondSpend+Vault | L3 | Not yet | N | N | `bench_sub_015` | `subscription/metered_api_secure.cash` |

## Token / NFT

| ID | Name | Patterns | Tier | Readiness | Bench | Audit | registry_ref | fixture_ref |
|----|------|----------|------|-----------|-------|-------|--------------|-------------|
| UCT-097 | FT Staking Vault | Vault+FT+Timelock | L3 | Almost | P | P | `bench_token_001` | `cashtokens/ft_staking_secure.cash` |
| UCT-098 | NFT Fractional Vault | Vault+NFT+Split | L3 | Not yet | N | N | `bench_token_002` | `cashtokens/nft_fractional_secure.cash` |
| UCT-099 | Token Mint Escrow | Escrow+FT+Multisig | L3 | Generatable today | Y | Y | `bench_token_003` | `cashtokens/token_mint_escrow_secure.cash` |
| UCT-100 | NFT Collection Drop | NFT+Covenant+Timelock | L3 | Partial | P | P | `bench_token_004` | `cashtokens/nft_collection_drop_secure.cash` |
| UCT-101 | Wrapped BCH Token Vault | Vault+FT+Covenant | L3 | Partial | P | P | `bench_token_005` | `cashtokens/wrapped_bch_secure.cash` |
| UCT-102 | Soulbound NFT Gate | NFT+Covenant+Multisig | L3 | Partial | P | P | `bench_token_006` | `cashtokens/soulbound_gate_secure.cash` |
| UCT-103 | Token Airdrop Split | Split+FT | L2 | Partial | P | P | `bench_token_007` | `cashtokens/airdrop_split_secure.cash` |
| UCT-104 | NFT Marketplace Royalty | NFT+Escrow+Split | L3 | Partial | P | P | `bench_token_008` | `cashtokens/nft_royalty_escrow_secure.cash` |
| UCT-105 | Multi-Token Swap Escrow | Escrow+FT+Hashlock | L3 | Almost | P | P | `bench_token_009` | `cashtokens/multi_token_swap_secure.cash` |
| UCT-106 | Immutable NFT Vault | Vault+NFT+Covenant | L3 | Almost | P | P | `bench_token_010` | `cashtokens/immutable_nft_vault_secure.cash` |
| UCT-107 | FT/NFT Bridge Covenant | FT+NFT+Covenant | L3 | Partial | P | P | `bench_token_011` | `cashtokens/ft_nft_bridge_secure.cash` |
| UCT-108 | Token Vesting NFT Bundle | FT+NFT+Vault | L3 | Almost | P | P | `bench_token_012` | `cashtokens/token_nft_bundle_secure.cash` |
| UCT-109 | Semi-Fungible Escrow | NFT+FT+Escrow | L3 | Partial | P | P | `bench_token_013` | `cashtokens/semi_fungible_escrow_secure.cash` |
| UCT-110 | NFT Collateral Vault | Vault+NFT+Escrow | L3 | Almost | P | P | `bench_token_014` | `cashtokens/nft_collateral_secure.cash` |
| UCT-111 | Token Burn Escrow | Escrow+FT+Covenant | L3 | Partial | P | P | `bench_token_015` | `cashtokens/token_burn_escrow_secure.cash` |
| UCT-112 | Dynamic NFT State Vault | NFT+Covenant+Vault | L3 | Partial | P | P | `bench_token_016` | `cashtokens/dynamic_nft_state_secure.cash` |

## Recovery / Emergency

| ID | Name | Patterns | Tier | Readiness | Bench | Audit | registry_ref | fixture_ref |
|----|------|----------|------|-----------|-------|-------|--------------|-------------|
| UCT-113 | Recovery Vault | Vault+Multisig+Timelock | L3 | Almost | P | P | `vr_010` | `vault/recovery_multisig_secure.cash` |
| UCT-114 | Emergency Recovery Vault | Vault+Multisig+CondSpend | L3 | Almost | P | P | `vr_023` | `vault/emergency_recovery_secure.cash` |
| UCT-115 | Social Recovery Wallet | Multisig+Timelock+Vault | L3 | Almost | P | P | `bench_recovery_001` | `vault/social_recovery_secure.cash` |
| UCT-116 | Guardian Timelock Recovery | Timelock+Multisig+Vault | L3 | Almost | P | P | `bench_recovery_002` | `timelock/guardian_recovery_secure.cash` |
| UCT-117 | Dead Man Switch Vault | Vault+Timelock+CondSpend | L3 | Partial | P | P | `bench_recovery_003` | `vault/dead_man_switch_secure.cash` |
| UCT-118 | Key Rotation Escrow | Escrow+Multisig+Hashlock | L3 | Almost | P | P | `bench_recovery_004` | `escrow/key_rotation_secure.cash` |
| UCT-119 | Inheritance Timelock Vault | Vault+Timelock+Covenant | L3 | Partial | P | P | `bench_recovery_005` | `vault/inheritance_timelock_secure.cash` |
| UCT-120 | Emergency Pause Multisig | Multisig+CondSpend | L2 | Partial | P | P | `bench_recovery_006` | `multisig/emergency_pause_secure.cash` |
| UCT-121 | Backup Signer Recovery | Multisig+Vault | L2 | Almost | P | P | `bench_recovery_007` | `multisig/backup_signer_secure.cash` |
| UCT-122 | Lost Key Hashlock Recovery | Hashlock+Multisig+Timelock | L3 | Almost | P | P | `bench_recovery_008` | `hashlock/lost_key_recovery_secure.cash` |
| UCT-123 | NFT Recovery Escrow | Escrow+NFT+Multisig | L3 | Generatable today | Y | Y | `bench_recovery_009` | `escrow/nft_recovery_secure.cash` |
| UCT-124 | Treasury Emergency Drain | Vault+Multisig+CondSpend | L3 | Almost | P | P | `bench_recovery_010` | `vault/emergency_drain_secure.cash` |
| UCT-125 | Circuit Breaker Covenant | Covenant+Multisig+Timelock | L3 | Partial | P | P | `bench_recovery_011` | `covenant/circuit_breaker_secure.cash` |
| UCT-126 | Recovery Refund Path | Refundable+Multisig+Timelock | L3 | Partial | P | P | `bench_recovery_012` | `refundable/recovery_refund_secure.cash` |
| UCT-127 | Compromised Key Rotation | Multisig+Hashlock+Vault | L3 | Almost | P | P | `bench_recovery_013` | `multisig/compromised_key_secure.cash` |
| UCT-128 | Break-Glass Admin Vault | Vault+CondSpend+Multisig | L3 | Partial | P | P | `bench_recovery_014` | `vault/break_glass_admin_secure.cash` |

## Crowdfund / Refundable

| ID | Name | Patterns | Tier | Readiness | Bench | Audit | registry_ref | fixture_ref |
|----|------|----------|------|-----------|-------|-------|--------------|-------------|
| UCT-129 | Crowdfund Refundable | Refundable+Split+Timelock | L3 | Not yet | N | N | `rp_001` | `refundable/crowdfund_goal_secure.cash` |
| UCT-130 | Stretch Goal Crowdfund | Refundable+Split+Escrow | L3 | Not yet | N | N | `bench_cf_001` | `refundable/stretch_goal_secure.cash` |
| UCT-131 | All-or-Nothing Campaign | Refundable+Timelock | L2 | Partial | P | P | `bench_cf_002` | `refundable/all_or_nothing_secure.cash` |
| UCT-132 | Milestone Crowdfund Escrow | Refundable+Escrow+Multisig | L3 | Partial | P | P | `bench_cf_003` | `refundable/milestone_crowdfund_secure.cash` |
| UCT-133 | Refund Deadline Vault | Refundable+Vault+Timelock | L3 | Partial | P | P | `bench_cf_004` | `refundable/refund_deadline_secure.cash` |
| UCT-134 | Subscription Crowdfund | Refundable+Subscription | L2 | Not yet | N | N | `bench_cf_005` | `refundable/subscription_crowdfund_secure.cash` |
| UCT-135 | NFT Crowdfund Mint | Refundable+NFT+Escrow | L3 | Partial | P | P | `bench_cf_006` | `refundable/nft_crowdfund_secure.cash` |
| UCT-136 | Token Presale Refundable | Refundable+FT+Timelock | L3 | Partial | P | P | `bench_cf_007` | `refundable/token_presale_secure.cash` |
| UCT-137 | Partial Refund Escrow | Refundable+Escrow | L2 | Partial | P | P | `bench_cf_008` | `refundable/partial_refund_secure.cash` |
| UCT-138 | Backer Protection Vault | Refundable+Vault+Multisig | L3 | Partial | P | P | `bench_cf_009` | `refundable/backer_protection_secure.cash` |
| UCT-139 | Goal Not Met Refund | Refundable+Hashlock | L2 | Almost | P | P | `bench_cf_010` | `refundable/goal_not_met_secure.cash` |
| UCT-140 | Multi-Tier Crowdfund Split | Refundable+Split+Multisig | L3 | Not yet | N | N | `bench_cf_011` | `refundable/multi_tier_secure.cash` |
| UCT-141 | Charity Matching Refund | Refundable+Vault+Split | L3 | Not yet | N | N | `bench_cf_012` | `refundable/charity_matching_secure.cash` |
| UCT-142 | Escrow Hold Until Goal | Refundable+Escrow+Timelock | L3 | Partial | P | P | `bench_cf_013` | `refundable/hold_until_goal_secure.cash` |
| UCT-143 | Creator Accountability Fund | Refundable+Covenant+Multisig | L3 | Partial | P | P | `bench_cf_014` | `refundable/creator_accountability_secure.cash` |
| UCT-144 | Early Bird Refund Window | Refundable+Timelock+Escrow | L3 | Partial | P | P | `bench_cf_015` | `refundable/early_bird_secure.cash` |

## Marketplace / DeFi

| ID | Name | Patterns | Tier | Readiness | Bench | Audit | registry_ref | fixture_ref |
|----|------|----------|------|-----------|-------|-------|--------------|-------------|
| UCT-145 | Atomic Swap HTLC | Hashlock+Timelock+CondSpend | L3 | Almost | P | P | `bench_defi_001` | `hashlock/atomic_swap_secure.cash` |
| UCT-146 | P2P Trade Escrow | Escrow+Multisig+FT | L3 | Generatable today | Y | Y | `bench_defi_002` | `escrow/p2p_trade_secure.cash` |
| UCT-147 | NFT Marketplace Escrow | Escrow+NFT+Multisig | L3 | Generatable today | Y | Y | `bench_defi_003` | `escrow/nft_marketplace_secure.cash` |
| UCT-148 | Liquidity Pool Covenant | Covenant+FT+Vault | L3 | Partial | P | P | `bench_defi_004` | `covenant/liquidity_pool_secure.cash` |
| UCT-149 | Limit Order Hashlock | Hashlock+Escrow+Timelock | L3 | Almost | P | P | `bench_defi_005` | `hashlock/limit_order_secure.cash` |
| UCT-150 | DEX Router CondSpend | CondSpend+FT+Escrow | L3 | Partial | P | P | `bench_defi_006` | `conditional_spend/dex_router_secure.cash` |
| UCT-151 | Flash Loan Guard Vault | Vault+CondSpend+Covenant | L3 | Partial | P | P | `bench_defi_007` | `vault/flash_loan_guard_secure.cash` |
| UCT-152 | Yield Farm Timelock | Vault+Timelock+FT | L3 | Almost | P | P | `bench_defi_008` | `vault/yield_farm_secure.cash` |
| UCT-153 | NFT Auction Escrow | Escrow+NFT+Timelock | L3 | Generatable today | Y | Y | `bench_defi_009` | `escrow/nft_auction_secure.cash` |
| UCT-154 | Bonding Curve Covenant | Covenant+FT+Split | L3 | Not yet | N | N | `bench_defi_010` | `covenant/bonding_curve_secure.cash` |
| UCT-155 | Collateralized Loan Vault | Vault+Escrow+FT | L3 | Almost | P | P | `bench_defi_011` | `vault/collateral_loan_secure.cash` |
| UCT-156 | Swap Pool Multisig | Multisig+FT+Hashlock | L3 | Partial | P | P | `bench_defi_012` | `multisig/swap_pool_secure.cash` |
| UCT-157 | Market Maker Split | Split+FT+Escrow | L3 | Partial | P | P | `bench_defi_013` | `split/market_maker_secure.cash` |
| UCT-158 | Options Settlement Escrow | Escrow+CondSpend+Timelock | L3 | Partial | P | P | `bench_defi_014` | `escrow/options_settlement_secure.cash` |
| UCT-159 | Stablecoin Redemption Vault | Vault+FT+Refundable | L3 | Partial | P | P | `bench_defi_015` | `vault/stablecoin_redemption_secure.cash` |
| UCT-160 | OTC Desk Escrow | Escrow+Multisig+Hashlock | L3 | Almost | P | P | `bench_defi_016` | `escrow/otc_desk_secure.cash` |

## Oracle / Conditional

| ID | Name | Patterns | Tier | Readiness | Bench | Audit | registry_ref | fixture_ref |
|----|------|----------|------|-----------|-------|-------|--------------|-------------|
| UCT-161 | Oracle-Gated Escrow | CondSpend+Escrow+Timelock | L3 | Partial | P | P | `bench_oracle_001` | `conditional_spend/oracle_escrow_secure.cash` |
| UCT-162 | Price Feed CondSpend | CondSpend+FT+Vault | L3 | Partial | P | P | `bench_oracle_002` | `conditional_spend/price_feed_secure.cash` |
| UCT-163 | Weather Derivative Payout | CondSpend+Refundable+Timelock | L3 | Partial | P | P | `bench_oracle_003` | `conditional_spend/weather_derivative_secure.cash` |
| UCT-164 | Sports Outcome Escrow | Escrow+CondSpend+Hashlock | L3 | Partial | P | P | `bench_oracle_004` | `escrow/sports_outcome_secure.cash` |
| UCT-165 | Insurance Claim CondSpend | CondSpend+Vault+Multisig | L3 | Partial | P | P | `bench_oracle_005` | `conditional_spend/insurance_claim_secure.cash` |
| UCT-166 | Data Attestation Release | CondSpend+Multisig+Timelock | L3 | Partial | P | P | `bench_oracle_006` | `conditional_spend/data_attestation_secure.cash` |
| UCT-167 | Multi-Oracle Threshold | CondSpend+Escrow+Multisig | L3 | Partial | P | P | `bench_oracle_007` | `conditional_spend/multi_oracle_secure.cash` |
| UCT-168 | Delayed Oracle Vault | Vault+CondSpend+Timelock | L3 | Partial | P | P | `bench_oracle_008` | `vault/delayed_oracle_secure.cash` |
| UCT-169 | Conditional Grant Release | CondSpend+Vault+Split | L3 | Not yet | N | N | `bench_oracle_009` | `conditional_spend/conditional_grant_secure.cash` |
| UCT-170 | Betting Pool Hashlock | Hashlock+CondSpend+Escrow | L3 | Almost | P | P | `bench_oracle_010` | `hashlock/betting_pool_secure.cash` |
| UCT-171 | RWA Settlement CondSpend | CondSpend+Escrow+FT | L3 | Partial | P | P | `bench_oracle_011` | `conditional_spend/rwa_settlement_secure.cash` |
| UCT-172 | Event Trigger Timelock | Timelock+CondSpend | L2 | Partial | P | P | `bench_oracle_012` | `timelock/event_trigger_secure.cash` |
| UCT-173 | KYC Gate CondSpend | CondSpend+Multisig+Vault | L3 | Partial | P | P | `bench_oracle_013` | `conditional_spend/kyc_gate_secure.cash` |
| UCT-174 | Compliance Oracle Vault | Vault+CondSpend+Covenant | L3 | Partial | P | P | `bench_oracle_014` | `vault/compliance_oracle_secure.cash` |
| UCT-175 | Prediction Market Escrow | Escrow+CondSpend+Refundable | L3 | Partial | P | P | `bench_oracle_015` | `escrow/prediction_market_secure.cash` |
| UCT-176 | Supply Chain Attestation | CondSpend+Escrow+Covenant | L3 | Partial | P | P | `bench_oracle_016` | `conditional_spend/supply_chain_secure.cash` |

## Covenant / Stateful

| ID | Name | Patterns | Tier | Readiness | Bench | Audit | registry_ref | fixture_ref |
|----|------|----------|------|-----------|-------|-------|--------------|-------------|
| UCT-177 | Stateful Escrow Machine | Covenant+Escrow+Timelock | L3 | Partial | P | P | `bench_cov_001` | `covenant/stateful_escrow_secure.cash` |
| UCT-178 | UTXO State Machine | Covenant+CondSpend | L2 | Partial | P | P | `bench_cov_002` | `covenant/utxo_state_machine_secure.cash` |
| UCT-179 | Recursive Covenant Vault | Covenant+Vault+Timelock | L3 | Partial | P | P | `bench_cov_003` | `covenant/recursive_vault_secure.cash` |
| UCT-180 | NFT Evolution Covenant | Covenant+NFT+Timelock | L3 | Partial | P | P | `bench_cov_004` | `covenant/nft_evolution_secure.cash` |
| UCT-181 | Token Vesting Covenant | Covenant+FT+Vault | L3 | Partial | P | P | `bench_cov_005` | `covenant/token_vesting_secure.cash` |
| UCT-182 | Payroll State Continuation | Covenant+Split+Multisig | L3 | Not yet | N | N | `bench_cov_006` | `covenant/payroll_state_secure.cash` |
| UCT-183 | Escrow Stage Covenant | Covenant+Escrow+Multisig | L3 | Partial | P | P | `bench_cov_007` | `covenant/escrow_stage_secure.cash` |
| UCT-184 | Fee Schedule Covenant | Covenant+Split+FT | L3 | Not yet | N | N | `bench_cov_008` | `covenant/fee_schedule_secure.cash` |
| UCT-185 | Governance State Fork | Covenant+Multisig+Timelock | L3 | Partial | P | P | `bench_cov_009` | `covenant/governance_fork_secure.cash` |
| UCT-186 | Mint Authority Covenant | Covenant+FT+Multisig | L3 | Partial | P | P | `bench_cov_010` | `covenant/mint_authority_secure.cash` |
| UCT-187 | Burn Gate Covenant | Covenant+FT+CondSpend | L3 | Partial | P | P | `bench_cov_011` | `covenant/burn_gate_secure.cash` |
| UCT-188 | Continuity Escrow NFT | Covenant+NFT+Escrow | L3 | Partial | P | P | `bench_cov_012` | `covenant/continuity_nft_secure.cash` |
| UCT-189 | Stateful Refund Machine | Covenant+Refundable+Timelock | L3 | Partial | P | P | `bench_cov_013` | `covenant/stateful_refund_secure.cash` |
| UCT-190 | Stage Gate Workflow | Covenant+Vault+Escrow | L3 | Partial | P | P | `bench_cov_014` | `covenant/stage_gate_secure.cash` |
| UCT-191 | Rolling Window Covenant | Covenant+Timelock+Split | L3 | Not yet | N | N | `bench_cov_015` | `covenant/rolling_window_secure.cash` |
| UCT-192 | Identity Continuation Rail | Covenant+Multisig+NFT | L3 | Partial | P | P | `bench_cov_016` | `covenant/identity_continuation_secure.cash` |

## Misc

| ID | Name | Patterns | Tier | Readiness | Bench | Audit | registry_ref | fixture_ref |
|----|------|----------|------|-----------|-------|-------|--------------|-------------|
| UCT-193 | Gift Card Vault | Vault+Hashlock+Timelock | L3 | Almost | P | P | `bench_misc_001` | `vault/gift_card_secure.cash` |
| UCT-194 | Will Execution Timelock | Timelock+Vault+Multisig | L3 | Almost | P | P | `bench_misc_002` | `timelock/will_execution_secure.cash` |
| UCT-195 | Prize Pool Escrow | Escrow+Split+Multisig | L3 | Not yet | N | N | `bench_misc_003` | `escrow/prize_pool_secure.cash` |
| UCT-196 | Escrow Agent Fee Split | Escrow+Split | L2 | Partial | P | P | `bench_misc_004` | `escrow/agent_fee_split_secure.cash` |
| UCT-197 | Time-Locked Donation | Timelock+Vault | L2 | Almost | P | P | `bench_misc_005` | `vault/timed_donation_secure.cash` |
| UCT-198 | Multi-Sig Safe Deposit | Multisig+Vault+Timelock | L3 | Almost | P | P | `bench_misc_006` | `multisig/safe_deposit_secure.cash` |
| UCT-199 | Hashlock Riddle Vault | Hashlock+Vault | L2 | Almost | P | P | `bench_misc_007` | `hashlock/riddle_vault_secure.cash` |
| UCT-200 | Conditional Inheritance | CondSpend+Vault+Timelock | L3 | Partial | P | P | `bench_misc_008` | `vault/conditional_inheritance_secure.cash` |
| UCT-201 | Blind Auction Hashlock | Hashlock+Escrow+Timelock | L3 | Almost | P | P | `bench_misc_009` | `hashlock/blind_auction_secure.cash` |
| UCT-202 | Rent Payment Subscription | Subscription+Split+Timelock | L3 | Not yet | N | N | `bench_misc_010` | `subscription/rent_payment_secure.cash` |
| UCT-203 | Ticket NFT Escrow | Escrow+NFT+Refundable | L3 | Partial | P | P | `bench_misc_011` | `escrow/ticket_nft_secure.cash` |
| UCT-204 | Charity Disbursement Split | Split+Multisig+Vault | L3 | Not yet | N | N | `bench_misc_012` | `split/charity_disbursement_secure.cash` |
| UCT-205 | Proof-of-Work Bounty | Hashlock+Escrow | L2 | Almost | P | P | `bench_misc_013` | `hashlock/pow_bounty_secure.cash` |
| UCT-206 | Multi-Stage Workflow | Vault+Escrow+Covenant+Timelock | L4 | Partial | P | P | `bench_misc_014` | `vault/multi_stage_workflow_secure.cash` |
| UCT-207 | Generic 5-Pattern Composite | Split+Escrow+Multisig+Timelock+Vault | L5 | Not yet | N | N | `bench_misc_015` | `composite/generic_l5_secure.cash` |
| UCT-208 | Campus Meal Plan Vault | Vault+Subscription+Split | L3 | Not yet | N | N | `bench_misc_016` | `vault/campus_meal_plan_secure.cash` |
| UCT-209 | Escrow Notary Multisig | Escrow+Multisig+Covenant | L3 | Partial | P | P | `bench_misc_017` | `escrow/notary_multisig_secure.cash` |
| UCT-210 | Research Sandbox Composite | Escrow+Multisig+Timelock | L3 | Generatable today | Y | Y | `bench_misc_018` | `escrow/research_sandbox_secure.cash` |

---

## Statistics

| Metric | Value |
|--------|-------|
| **Total catalog entries** | 210 |
| **Families** | 13 |
| **P0 priority contracts** | 20 |

### By Readiness

| Readiness | Count | % |
|-----------|-------|---|
| Generatable today | 16 | 7.6% |
| Almost | 53 | 25.2% |
| Partial | 95 | 45.2% |
| Not yet | 46 | 21.9% |

### By Tier

| Tier | Count |
|------|-------|
| L2 | 30 |
| L3 | 175 |
| L4 | 4 |
| L5 | 1 |

### By Family

| Family | Count |
|--------|-------|
| Payroll / Treasury | 16 |
| DAO / Governance | 16 |
| Vesting | 16 |
| Revenue / Grants | 16 |
| Escrow / Milestones | 16 |
| Subscription | 16 |
| Token / NFT | 16 |
| Recovery / Emergency | 16 |
| Crowdfund / Refundable | 16 |
| Marketplace / DeFi | 16 |
| Oracle / Conditional | 16 |
| Covenant / Stateful | 16 |
| Misc | 18 |

### Pattern Stack Frequency (top composites)

| Pattern | Appearances | Scorecard Composite Ready |
|---------|-------------|---------------------------|
| Timelock | 91 | Almost |
| Vault | 91 | Almost |
| Multisig | 86 | Yes |
| Escrow | 74 | Yes |
| Split | 51 | No |
| Covenant | 43 | Partial |
| CashTokens FT | 40 | Yes |
| Conditional Spend | 35 | Partial |
| Refundable | 30 | No |
| CashTokens NFT | 27 | Yes |
| Hashlock | 19 | Almost |
| Subscription | 19 | No |

---

## Related Documents

- [`composition_readiness_scorecard.md`](composition_readiness_scorecard.md)
- [`composition_matrix.md`](composition_matrix.md)
- [`benchmark_strategy.md`](benchmark_strategy.md)
- [`benchmark_registry.json`](benchmark_registry.json)
- [`research_sprint_plan.md`](research_sprint_plan.md)
- [`security_patterns/README.md`](security_patterns/README.md)
- [`realworld_collection_strategy.md`](realworld_collection_strategy.md)
