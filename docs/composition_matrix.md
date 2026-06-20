# Pattern Composition Matrix

**Sprint:** Phase 2 Composition Research  
**Branch:** `research/composition-sprint-v2`  
**Date:** 2026-06-18  
**Input:** [`composition_readiness_scorecard.md`](composition_readiness_scorecard.md)  
**Patterns (12):** Split, Escrow, Multisig, Timelock, Hashlock, Vault, Refundable, Subscription, Conditional Spend, Covenant, CashTokens FT, CashTokens NFT

---

## Summary

| Compatibility | Cell count | Interpretation |
|---------------|------------|----------------|
| Compatible | 38 | Both patterns Composite Ready or Almost; no rail conflict |
| Conditional | 32 | Feasible with golden template or single-function staging |
| Conflicting | 12 | Rail conflict, routing hijack, or both patterns weak |
| Unsupported | 8 | No knowledge path; defer |

**Central finding (INFERRED):** NexOps can support **2-pattern** compositions where both operands are Escrow/Multisig/Timelock/FT/NFT. **3+ pattern** business contracts (Payroll Treasury, DAO Treasury) require a composition planner — tag stacking + single `effective_mode` fails.

---

## Abbreviated 12×12 Matrix

Rows = primary pattern; Columns = composed pattern.  
**C**=Compatible **N**=Conditional **X**=Conflicting **U**=Unsupported

|  | Split | Escrow | Multisig | Timelock | Hashlock | Vault | Refund | Subscr | CondSp | Cov | FT | NFT |
|--|:-----:|:------:|:--------:|:--------:|:--------:|:-----:|:------:|:------:|:------:|:---:|:--:|:---:|
| **Split** | — | N | X | N | N | N | N | X | N | X | N | N |
| **Escrow** | N | — | C | C | C | N | N | N | N | N | C | C |
| **Multisig** | X | C | — | C | N | N | N | N | N | N | N | N |
| **Timelock** | N | C | C | — | C | C | N | N | C | N | N | N |
| **Hashlock** | N | C | N | C | — | N | C | N | C | N | N | N |
| **Vault** | N | N | N | C | N | — | N | N | N | C | N | C |
| **Refundable** | N | N | N | N | C | N | — | C | N | N | N | N |
| **Subscription** | X | N | N | N | N | N | C | — | N | N | N | N |
| **CondSpend** | N | N | N | C | C | N | N | N | — | N | N | N |
| **Covenant** | X | N | N | N | N | C | N | N | N | — | C | C |
| **FT** | N | C | N | N | N | N | N | N | N | C | — | C |
| **NFT** | N | C | N | N | N | C | N | N | N | C | C | — |

---

## P0 Pair Deep-Dives

### Split + Multisig — **Conflicting** | Priority P0 | Feasibility: Not yet

| Dimension | Assessment | Label |
|-----------|------------|-------|
| Compatibility | Conflicting | INFERRED |
| Security | Multisig on distribute path; split sum conservation across N outputs | INFERRED |
| Routing | `multisig+distribution`→`split` wins `effective_mode`; multisig profile may not load | MEASURED |
| Generation | `A_split_multisig` FAILED compile | MEASURED |
| Audit | Payroll fixtures assume owner sig, not multisig threshold | MEASURED |
| Benchmark | `split_003_multisig_distribution` — registry stub only | MEASURED |
| Example | Payroll Treasury, Token Payroll | — |

### Escrow + Multisig — **Compatible** | Priority P0 | Feasibility: Supported

| Dimension | Assessment | Label |
|-----------|------------|-------|
| Compatibility | Compatible | MEASURED |
| Security | 2-of-3 release; arbiter dispute path | INFERRED |
| Routing | `timelock+multisig`→`escrow` tag enrichment | MEASURED |
| Generation | `escrow_basic_multisig` golden path | MEASURED |
| Audit | `escrow/two_of_three_secure.cash`, `basic_multisig_secure.cash` | MEASURED |
| Example | HTLC Escrow (partial), Milestone Payout | — |

### Escrow + Hashlock + Timelock (HTLC) — **Compatible** triple | Priority P0

| Dimension | Assessment | Label |
|-----------|------------|-------|
| Compatibility | Pairwise Compatible; triple Conditional | INFERRED |
| Security | Preimage reveal OR timeout refund; mutual exclusion | INFERRED |
| Routing | rp_002 routed via swap/conditional_spend | MEASURED |
| Generation | HTLC compile varies; evaluator sha256 vs hash160 mismatch | MEASURED |
| Audit | `hashlock/htlc_secure.cash`, `refundable/htlc_refund_secure.cash` | MEASURED |
| Example | HTLC Escrow (#7 P0 catalog) | — |

### Vault + Timelock — **Compatible** | Priority P0 | Feasibility: Almost

| Dimension | Assessment | Label |
|-----------|------------|-------|
| Compatibility | Compatible | INFERRED |
| Security | Staged release vs absolute CLTV on recovery | INFERRED |
| Routing | Vault canonical path; timelock overlay via features | INFERRED |
| Generation | Vault 67% conv; multi-function timeouts | MEASURED |
| Audit | Vesting fixtures use cliff + timelock patterns | MEASURED |
| Example | Founder Vesting, Recovery Vault | — |

### Vault + Multisig — **Conditional** | Priority P0

| Dimension | Assessment | Label |
|-----------|------------|-------|
| Compatibility | Conditional — separate functions per path | INFERRED |
| Security | Emergency recovery 2-of-3 must not bypass staged vault rules | INFERRED |
| Generation | Vault canonical + multisig prompt blocks | INFERRED |
| Example | DAO Treasury, Recovery Vault | — |

### Vault + CashTokens NFT — **Compatible** | Priority P1

| Dimension | Assessment | Label |
|-----------|------------|-------|
| Compatibility | Compatible | INFERRED |
| Security | NFT authority retained; covenant continuation on vault stages | INFERRED |
| Routing | No golden for vault+nft composite | INFERRED |
| Example | NFT Vesting, NFT Escrow (partial) | — |

### Escrow + CashTokens NFT — **Compatible** | Priority P0

| Dimension | Assessment | Label |
|-----------|------------|-------|
| Compatibility | Compatible | MEASURED |
| Security | Token category preservation on release | MEASURED |
| Generation | `escrow_2of3_nft` in `_GOLDEN_TYPE_MAP` | MEASURED |
| Example | NFT Escrow (#8) | — |

### Split + Timelock — **Conditional** | Priority P0

| Dimension | Assessment | Label |
|-----------|------------|-------|
| Compatibility | Conditional | INFERRED |
| Security | Delayed distribution; CLTV on payout function | INFERRED |
| Generation | Split RED blocks | MEASURED |
| Example | Payroll Treasury (monthly), Grant Distribution | — |

### Refundable + Split — **Conditional** | Priority P1

| Dimension | Assessment | Label |
|-----------|------------|-------|
| Compatibility | Conditional | INFERRED |
| Security | Refund path vs distribution path isolation | INFERRED |
| Generation | Refundable 67%; split 50% | MEASURED |
| Example | Crowdfund with milestone splits | — |

### Subscription + Split — **Conflicting** | Priority P2

| Dimension | Assessment | Label |
|-----------|------------|-------|
| Compatibility | Conflicting | INFERRED |
| Security | Recurring authorization model undefined on-chain | INFERRED |
| Generation | Subscription not first-class | MEASURED |
| Example | Subscription Treasury (#10) — defer | — |

### Covenant + Split — **Conflicting** | Priority P1

| Dimension | Assessment | Label |
|-----------|------------|-------|
| Compatibility | Conflicting | MEASURED |
| Security | Terminating rail vs split P2PKH guidance | MEASURED |
| Evidence | [`semantic_005_008_investigation.md`](semantic_005_008_investigation.md) | MEASURED |

### CashTokens FT + Vault — **Conditional** | Priority P1

| Dimension | Assessment | Label |
|-----------|------------|-------|
| Compatibility | Conditional | INFERRED |
| Security | Token amount conservation across vault stages | INFERRED |
| Generation | FT golden strong; vault canonical | INFERRED |
| Example | Token Payroll, Treasury token reserve | — |

### DAO Treasury (Multisig + Timelock + Vault) — **Conditional** triple

| Dimension | Assessment | Label |
|-----------|------------|-------|
| Compatibility | All pairs Conditional/Compatible; triple needs planner | INFERRED |
| Security | Emergency path timelock bypass — detector **none** | MEASURED |
| Audit | [`dao_treasury.md`](security_patterns/dao_treasury.md) | INFERRED |
| Example | DAO Treasury (#2) | — |

---

## Full Pair Reference (78 unordered + 12 self)

### Split Payment pairs

| Pair | Compat | Route | Gen | Audit | Bench | Example |
|------|--------|-------|-----|-------|-------|---------|
| Split+Escrow | N | 3 | 4 | 3 | 2 | Revenue release escrow |
| Split+Multisig | X | 5 | 5 | 3 | 2 | Payroll Treasury |
| Split+Timelock | N | 3 | 4 | 3 | 2 | Vesting distribution |
| Split+Hashlock | N | 4 | 4 | 2 | 2 | Atomic swap split |
| Split+Vault | N | 4 | 4 | 3 | 2 | Staged payroll vault |
| Split+Refundable | N | 3 | 4 | 3 | 2 | Crowdfund payout |
| Split+Subscription | X | 5 | 5 | 2 | 1 | Subscription Treasury |
| Split+CondSpend | N | 4 | 3 | 3 | 2 | Conditional payout |
| Split+Covenant | X | 5 | 4 | 3 | 2 | Stateful split |
| Split+FT | N | 3 | 3 | 4 | 3 | Token Payroll |
| Split+NFT | N | 4 | 4 | 3 | 2 | NFT royalty split |

### Escrow pairs (non-Split)

| Pair | Compat | Route | Gen | Audit | Bench | Example |
|------|--------|-------|-----|-------|-------|---------|
| Escrow+Multisig | C | 2 | 2 | 2 | 4 | 2-of-3 escrow |
| Escrow+Timelock | C | 2 | 2 | 3 | 3 | Timeout refund |
| Escrow+Hashlock | C | 3 | 3 | 3 | 3 | HTLC Escrow |
| Escrow+Vault | N | 4 | 4 | 3 | 2 | Escrow vault hybrid |
| Escrow+Refundable | N | 3 | 3 | 3 | 3 | Milestone escrow |
| Escrow+Subscription | N | 4 | 4 | 2 | 2 | Subscription escrow |
| Escrow+CondSpend | N | 3 | 3 | 3 | 2 | Swap escrow |
| Escrow+Covenant | N | 4 | 3 | 3 | 2 | Stateful escrow |
| Escrow+FT | C | 2 | 2 | 4 | 4 | Token escrow |
| Escrow+NFT | C | 2 | 2 | 4 | 4 | NFT Escrow |

### Multisig pairs (non-escrow/split)

| Pair | Compat | Route | Gen | Audit | Bench | Example |
|------|--------|-------|-----|-------|-------|---------|
| Multisig+Timelock | C | 2 | 2 | 3 | 3 | DAO timelock |
| Multisig+Hashlock | N | 4 | 3 | 2 | 2 | Multisig HTLC |
| Multisig+Vault | N | 4 | 3 | 3 | 2 | Recovery vault |
| Multisig+Refundable | N | 3 | 3 | 3 | 2 | Multisig refund |
| Multisig+Subscription | N | 4 | 4 | 2 | 1 | Governance sub |
| Multisig+CondSpend | N | 3 | 3 | 3 | 2 | Multi-path spend |
| Multisig+Covenant | N | 4 | 3 | 3 | 2 | DAO covenant |
| Multisig+FT | N | 3 | 2 | 4 | 3 | Token multisig |
| Multisig+NFT | N | 4 | 3 | 4 | 3 | NFT multisig |

### Remaining high-value pairs

| Pair | Compat | Priority | Feasibility | Example contract |
|------|--------|----------|-------------|------------------|
| Timelock+Hashlock | C | P0 | Almost | HTLC |
| Timelock+Vault | C | P0 | Almost | Founder Vesting |
| Timelock+Refundable | N | P1 | Partial | Refund deadline |
| Hashlock+Refundable | C | P0 | Almost | rp_002 HTLC |
| Hashlock+CondSpend | C | P1 | Partial | Atomic swap |
| Vault+Covenant | C | P1 | Partial | Stateful vault |
| Vault+NFT | C | P1 | Almost | NFT vault |
| Refundable+Subscription | C | P2 | Partial | Subscription crowdfund |
| Covenant+FT | C | P1 | Almost | Token covenant |
| Covenant+NFT | C | P1 | Almost | NFT state machine |
| FT+NFT | C | P1 | Almost | Hybrid treasury |

---

## Composition Complexity Tiers

| Tier | Pattern count | NexOps today | Examples |
|------|---------------|--------------|----------|
| L1 | 2 | Partial support | Escrow+Multisig, Escrow+NFT, Timelock+Hashlock |
| L2 | 3 | Not reliable | DAO Treasury, HTLC Escrow, Recovery Vault |
| L3 | 4 | Not supported | Payroll Treasury, Founder Vesting |
| L4 | 5+ | Not supported | Complex Workflow (plan Example D) |

---

## Benchmark Implications

| Gap | Impact | Label |
|-----|--------|-------|
| No composition tags in YAML suites | Cannot measure multi-pattern gen | MEASURED |
| Evaluator single primary pattern | Alias pool mismatch on composites | INFERRED |
| 38 executable audit benches | L1 audit partial; no L3+ composite audit | MEASURED |
| `split_003_multisig_distribution` | Closest gen composite — failed/stub | MEASURED |

---

## Related Documents

- [`composition_readiness_scorecard.md`](composition_readiness_scorecard.md)
- [`uncommon_contract_catalog.md`](uncommon_contract_catalog.md)
- [`semantic_005_008_investigation.md`](semantic_005_008_investigation.md)
- [`coverage_gap_analysis.md`](coverage_gap_analysis.md)
