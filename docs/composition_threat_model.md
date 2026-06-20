# Composition Threat Model

**Sprint:** Phase 2 Composition Research (Wave 4)  
**Branch:** `research/composition-sprint-v2`  
**Date:** 2026-06-20  
**Scope:** **Interaction-emergent threats only** — extends [`bch_threat_model.md`](bch_threat_model.md); does **not** duplicate UTXO, CashToken base, or single-pattern covenant threats

**Inputs:** [`composition_matrix.md`](composition_matrix.md) Conflicting/Conditional cells; P0 catalog from [`uncommon_contract_catalog.md`](uncommon_contract_catalog.md); detector gaps from [`coverage_gap_analysis.md`](coverage_gap_analysis.md)

---

## Scope Boundary

| In scope (this doc) | Out of scope (see `bch_threat_model.md`) |
|---------------------|------------------------------------------|
| Timelock bypass via alternate composed path | Input index confusion |
| Governance recovery bypassing vesting | Token category drift (single-pattern) |
| Vault re-anchor bypass across stages | Minting authority escape |
| Split redirection through emergency path | Fee siphoning |
| Token authority leakage at pattern boundary | NFT commitment loss (isolated) |
| Treasury drain via composition edge case | Oracle stale price (trust) |
| Path isolation failure between functions | Missing checkSig (single-path) |
| Rail routing hijack (effective_mode winner) | Partial aggregation |

**Rule:** A threat qualifies here only if exploitation requires **two or more patterns** interacting, or a **routing/planner failure** that manifests solely in multi-pattern contracts.

---

## STRIDE Classification — Composition Layer

| STRIDE | Composition manifestation | Primary P0 examples |
|--------|---------------------------|---------------------|
| **Spoofing** | Emergency path accepts fewer sigs than declared multisig on primary path | UCT-114, UCT-003 |
| **Tampering** | Attacker redirects split outputs via unconstrained alternate function | UCT-001, UCT-049 |
| **Repudiation** | Governance claims normal timelock applied while emergency path spent | UCT-017, UCT-113 |
| **Information disclosure** | N/A on-chain (deferred) | — |
| **Denial of service** | All paths require mutually exclusive locks; deadlock if composed wrong | UCT-065 HTLC |
| **Elevation of privilege** | Recovery multisig elevates to full treasury without timelock | UCT-002, UCT-124 |

---

## Threat Catalog

### CT-001 — Timelock Bypass via Alternate Path

| Field | Detail |
|-------|--------|
| **STRIDE** | Elevation of privilege |
| **Narrative** | A composed contract declares CLTV/CSV delay on the "normal" spend function, but a second function (recovery, emergency, dispute) releases funds immediately or with shorter delay. Attacker who controls recovery keys drains before intended delay elapses. |
| **Preconditions** | (1) Timelock + at least one alternate auth path; (2) alternate function not bound by same `tx.time`/`tx.age`; (3) both paths can spend same UTXO pool |
| **Pattern pairs** | Timelock+Multisig (**C**); Timelock+Vault (**C**); Multisig+Vault (**N**); Timelock+CondSpend (**C**) |
| **P0 contracts** | UCT-017 DAO Treasury; UCT-113 Recovery Vault; UCT-067 Milestone Payout |
| **Detector coverage** | **none** — [`bch_threat_model.md`](bch_threat_model.md) §Multi-Contract; [`coverage_gap_analysis.md`](coverage_gap_analysis.md) P0 gap **MEASURED** |
| **Benchmark mutant** | `comp_p0_002` / `emergency_bypass_timelock`; `comp_l2_001` mutant |
| **Mitigation research direction** | Cross-function timelock invariant: "no function may spend vault/escrow UTXO with `tx.time < T` unless explicitly labeled break-glass AND bounded amount"; composition-aware intent invariant `timelock_mutual_exclusion` |
| **Label** | INFERRED from dao_treasury.md + coverage gaps |

---

### CT-002 — Governance Recovery Bypass

| Field | Detail |
|-------|--------|
| **STRIDE** | Elevation of privilege |
| **Narrative** | 2-of-3 governance recovery path allows full treasury withdrawal while employee vesting or payroll allocations remain nominally locked on primary path. Recovery was intended for lost keys, not operational override. |
| **Preconditions** | Multisig recovery + Vault or Split on same treasury; recovery threshold ≤ operational threshold; no amount cap on recovery |
| **Pattern pairs** | Multisig+Vault (**N**); Split+Multisig (**X** — routing makes worse); Vault+Multisig+Timelock triple |
| **P0 contracts** | UCT-003 Payroll With Governance Recovery; UCT-114 Emergency Recovery Vault; UCT-113 Recovery Vault |
| **Detector coverage** | **partial** — `auth_gate` per-function only; no cross-path governance scope **INFERRED** |
| **Benchmark mutant** | `comp_p0_019` / `treasury_drain_via_recovery`; `comp_p0_009` / `recovery_skips_cltv` |
| **Mitigation research direction** | Intent invariant `governance_recovery_bounded`: recovery may only move funds to predetermined recovery addresses, capped per epoch; audit reasoning must compare declared recovery scope vs bytecode |
| **Label** | MEASURED payroll audit assumes owner sig not multisig threshold |

---

### CT-003 — Vault Re-Anchor Bypass

| Field | Detail |
|-------|--------|
| **STRIDE** | Tampering |
| **Narrative** | Vault stage transition requires continuation to `activeBytecode` with decremented stage counter, but composed Covenant or CondSpend path re-anchors to attacker-controlled script, skipping remaining vesting stages. |
| **Preconditions** | Vault + Covenant or Vault + CondSpend; continuation check absent on one branch; stage state in NFT commitment or OP_RETURN not preserved |
| **Pattern pairs** | Vault+Covenant (**C**); Vault+CondSpend (**N** via triple); Vault+NFT (**C**) |
| **P0 contracts** | UCT-034 Investor Vesting; UCT-035 NFT Vesting; UCT-045 Accelerated Vest Trigger |
| **Detector coverage** | **partial** — `vulnerable_covenant` on single path; no vault-stage cross-check **INFERRED** |
| **Benchmark mutant** | `comp_l1_013` / `covenant_reanchor_bypass`; `comp_p0_014` mutant |
| **Mitigation research direction** | Composition invariant `stage_continuation`: every spend must either (a) decrement stage with bound output or (b) use explicit terminal function; NFT commitment must encode stage |
| **Label** | INFERRED from vault_layer_diagnosis |

---

### CT-004 — Split Redirection Attack

| Field | Detail |
|-------|--------|
| **STRIDE** | Tampering |
| **Narrative** | Distribution function sends correct sum but to attacker-controlled lockingBytecode because emergency or governance path can rewrite recipient set, or split conservation holds on BCH but not tokenAmount across composed FT path. |
| **Preconditions** | Split composed with any alternate spend path; N-output conservation not enforced on all paths; Split primary distribution **MEASURED** 2-output only |
| **Pattern pairs** | Split+Multisig (**X**); Split+Timelock (**N**); Split+Vault (**N**); Split+FT (**N**) |
| **P0 contracts** | UCT-001 Payroll Treasury; UCT-049 Grant Distribution; UCT-002 Token Payroll |
| **Detector coverage** | **partial** — `fixed_amount_per_recipient` on payroll single-path; no multi-path **MEASURED** |
| **Benchmark mutant** | `comp_p0_003` / `split_redirect_emergency`; `comp_l1_040` negative control |
| **Mitigation research direction** | N-output sum conservation rail; recipient binding invariant across **all** functions that touch distribution outputs; block Split+Multisig until routing conflict resolved |
| **Label** | MEASURED `A_split_multisig` FAILED |

---

### CT-005 — Token Authority Leakage at Pattern Boundary

| Field | Detail |
|-------|--------|
| **STRIDE** | Tampering / Elevation |
| **Narrative** | FT minting authority (0x02) or NFT mutable capability (0x01) escapes to P2PKH or unconstrained output when Escrow release function composed with Vault stage transition — category preserved but capability bit flipped. |
| **Preconditions** | CashTokens composed with Escrow, Vault, or Split; capability check on one function only; hybrid FT+NFT without continuity rules |
| **Pattern pairs** | Escrow+FT (**C**); Escrow+NFT (**C**); FT+NFT (**C**); Vault+NFT (**C**); FT+Vault (**N**) |
| **P0 contracts** | UCT-015 Hybrid FT/NFT Treasury; UCT-002 Token Payroll; UCT-066 NFT Escrow |
| **Detector coverage** | **full** on single-pattern — `authority_leak`, `minting_authority_escape` **MEASURED**; **none** for cross-function capability handoff **INFERRED** |
| **Benchmark mutant** | `comp_p0_011` / `ft_mint_on_distribute`; `comp_p0_016` / `nft_drift_on_vault_stage` |
| **Mitigation research direction** | `hybrid_continuity` composition invariant; per-function capability trace extending Wave 2A.5 to composed paths |
| **Label** | MEASURED single-pattern; INFERRED composition gap |

---

### CT-006 — Treasury Drain via Composition Edge Case

| Field | Detail |
|-------|--------|
| **STRIDE** | Tampering |
| **Narrative** | Multiple composed paths each individually bounded, but sequential composition (Escrow release → Vault deposit → Split distribute) allows attacker to extract more than intended through path ordering or fee siphoning on intermediate UTXO. |
| **Preconditions** | 3+ patterns with shared treasury UTXO; no global reserve floor; intermediate outputs unbound |
| **Pattern pairs** | Escrow+Vault+Split triple; Refundable+Split+Timelock; any L4 stack |
| **P0 contracts** | UCT-001; UCT-129 Crowdfund Refundable; UCT-124 Treasury Emergency Drain |
| **Detector coverage** | **partial** — `fee_assumption_violation`; `treasury_prefunding` as trust only **MEASURED** |
| **Benchmark mutant** | `comp_p0_019` / `treasury_drain_via_recovery`; `comp_l4_001` mutant |
| **Mitigation research direction** | Global `reserve_floor` invariant across functions; composition planner must emit treasury accounting object; policy distinguishes TRUST-1 prefunding from on-chain drain |
| **Label** | INFERRED |

---

### CT-007 — HTLC Mutual Exclusion Failure

| Field | Detail |
|-------|--------|
| **STRIDE** | Tampering |
| **Narrative** | Both preimage claim and timeout refund functions can succeed in same transaction or across concurrent txs when Hashlock+Timelock+Escrow composed with Escrow dispute path that does not invalidate hashlock state. |
| **Preconditions** | Hashlock + Timelock + third path; `hash160`/`sha256` evaluator mismatch **MEASURED**; dispute function lacks spent-state check |
| **Pattern pairs** | Escrow+Hashlock+Timelock (**C** triple); Hashlock+Timelock (**C**); Escrow+Hashlock (**C**) |
| **P0 contracts** | UCT-065 HTLC Escrow |
| **Detector coverage** | **partial** — hashlock detector **none** **MEASURED**; HTLC fixtures in refundable family |
| **Benchmark mutant** | `comp_p0_007` / `htlc_both_paths_open` |
| **Mitigation research direction** | `mutual_exclusion` invariant: claim and refund functions mutually exclusive per UTXO; align evaluator hash160 vs sha256 |
| **Label** | MEASURED rp_002 routing; evaluator gap |

---

### CT-008 — Rail Routing Hijack (effective_mode Winner)

| Field | Detail |
|-------|--------|
| **STRIDE** | Elevation of privilege (generation-time) |
| **Narrative** | Multi-pattern intent resolves to single `effective_mode`; secondary pattern silently dropped. Generated contract implements only winner pattern — e.g., `multisig+distribution` → split wins, multisig profile never loads **MEASURED**. |
| **Preconditions** | 2+ patterns in Phase 1 features; `resolve_effective_mode()` single-winner; no composition planner |
| **Pattern pairs** | Split+Multisig (**X**); Split+Subscription (**X**); Covenant+Split (**X**); any N-cell with weak operand |
| **P0 contracts** | UCT-001; UCT-081; UCT-052 |
| **Detector coverage** | **none** — generation defect, not audit **MEASURED** |
| **Benchmark mutant** | `comp_l1_040`; `comp_p0_010` |
| **Mitigation research direction** | Composition planner research (not implementation); benchmark negative controls document expected compile/routing failure |
| **Label** | MEASURED pipeline.py + A_split_multisig |

---

### CT-009 — Subscription Recurrence Bypass

| Field | Detail |
|-------|--------|
| **STRIDE** | Tampering |
| **Narrative** | Subscription period tracking bypassed when composed with Split (routing conflict) or Refundable (refund path resets period counter without revoking access). |
| **Preconditions** | Subscription + any distribution pattern; subscription not first-class **MEASURED** 25% gen |
| **Pattern pairs** | Subscription+Split (**X**); Subscription+Refundable (**C**); Subscription+Vault (**N**) |
| **P0 contracts** | UCT-081 Subscription Treasury |
| **Detector coverage** | **none** — subscription audit doc only **INFERRED** |
| **Benchmark mutant** | `comp_p0_010`; `comp_l4_011` |
| **Mitigation research direction** | Defer subscription compositions until first-class routing; research recurring authorization model |
| **Label** | MEASURED subscription not first-class |

---

### CT-010 — Covenant–Split Terminating Rail Conflict

| Field | Detail |
|-------|--------|
| **STRIDE** | Denial of service (generation) / Tampering (if forced) |
| **Narrative** | Covenant requires continuation to same bytecode; Split guidance pushes P2PKH outputs — composed contract either fails compile or exits covenant mid-state-machine, forking state. |
| **Preconditions** | Covenant + Split; semantic_005_008 investigation **MEASURED** |
| **Pattern pairs** | Covenant+Split (**X**) |
| **P0 contracts** | UCT-052 Revenue Decay Treasury; UCT-182 Payroll State Continuation |
| **Detector coverage** | **partial** — `vulnerable_covenant` if forced compile |
| **Benchmark mutant** | `comp_p0_018`; `comp_l3_023` |
| **Mitigation research direction** | Classify as Conflicting — do not compose; use Covenant-only decay state machine without Split |
| **Label** | MEASURED semantic_005_008 |

---

### CT-011 — Refundable–Escrow Refund Race

| Field | Detail |
|-------|--------|
| **STRIDE** | Tampering |
| **Narrative** | Milestone escrow release and refundable clawback both executable after deadline because Timelock on one path uses `tx.time` while other uses `tx.age`, creating window where beneficiary and backer both extract. |
| **Preconditions** | Refundable+Escrow+Timelock; mismatched time bases **INFERRED** |
| **Pattern pairs** | Escrow+Refundable (**N**); Refundable+Timelock (**N**) |
| **P0 contracts** | UCT-068 Milestone Release Escrow; UCT-129 Crowdfund Refundable |
| **Detector coverage** | **partial** — `time_validation_error` timelock rail partial |
| **Benchmark mutant** | `comp_p0_020` / `refund_release_race` |
| **Mitigation research direction** | Unified time basis per composed contract; `refund_isolation` invariant |
| **Label** | INFERRED |

---

### CT-012 — Oracle Branch Composition Leak

| Field | Detail |
|-------|--------|
| **STRIDE** | Spoofing / Tampering |
| **Narrative** | CondSpend oracle datasig verified on release path but not on composed Escrow dispute path — attacker triggers release with stale oracle UTXO while dispute path uses different oracle binding. |
| **Preconditions** | CondSpend + Escrow or Vault; oracle output binding on one function only |
| **Pattern pairs** | CondSpend+Escrow (**N**); CondSpend+Vault (**N**); Escrow+CondSpend+Timelock |
| **P0 contracts** | UCT-161 Oracle-Gated Escrow; UCT-072 Dispute Arbitration |
| **Detector coverage** | **partial** — oracle detector gap **MEASURED** in coverage_gap_analysis |
| **Benchmark mutant** | `comp_l2_018` / `oracle_binding_mismatch` |
| **Mitigation research direction** | Single oracle UTXO binding across all conditional branches; trust vs exploit tree per bch_threat_model |
| **Label** | INFERRED |

---

## Cross-Reference Matrix — Conflicting Cells

From [`composition_matrix.md`](composition_matrix.md) §Abbreviated 12×12. **Threat IDs** apply to interaction-emergent risks even when generation fails (negative control).

| Cell | Compat | Primary threats | Generation status | Audit priority |
|------|--------|-----------------|-------------------|----------------|
| **Split+Multisig** | X | CT-004, CT-008 | FAILED compile **MEASURED** | P0 |
| **Split+Subscription** | X | CT-008, CT-009 | Not first-class **MEASURED** | P2 defer |
| **Split+Covenant** | X | CT-010, CT-008 | Terminating conflict **MEASURED** | P1 |
| **Multisig+Split** | X | CT-004, CT-008 | Symmetric to above | P0 |
| **Subscription+Split** | X | CT-009, CT-008 | Recurrence undefined | P2 defer |

### Conditional Cells — High Interaction Risk

| Cell | Compat | Primary threats | Notes |
|------|--------|-----------------|-------|
| Split+Timelock | N | CT-004 | Blocked by Split RED |
| Split+Vault | N | CT-003, CT-004 | Staged payroll |
| Multisig+Vault | N | CT-001, CT-002 | DAO recovery |
| Vault+Multisig+Timelock | triple N/C | CT-001, CT-002 | P0 DAO Treasury |
| Escrow+Refundable | N | CT-011 | Milestone crowdfund |
| Hashlock+CondSpend | C | CT-007 | Atomic swap |
| FT+Vault | N | CT-005 | Token vault stages |

---

## Threat × Detector Coverage Matrix

| Threat ID | Detector | Intent invariant | Semantic judge | Composition benchmark |
|-----------|----------|------------------|----------------|----------------------|
| CT-001 | none | none | reasoning only | comp_p0_002 mutant |
| CT-002 | partial (auth_gate) | none | reasoning | comp_p0_019 mutant |
| CT-003 | partial (covenant) | none | partial | comp_l1_013 mutant |
| CT-004 | partial (payroll) | partial | reasoning | comp_l1_040 |
| CT-005 | full single / none cross | none | partial | comp_p0_016 mutant |
| CT-006 | partial (fee) | trust only | reasoning | comp_l4_001 mutant |
| CT-007 | none (hashlock) | none | partial | comp_p0_007 mutant |
| CT-008 | n/a (gen) | n/a | n/a | comp_l1_040 |
| CT-009 | none | none | doc only | comp_p0_010 |
| CT-010 | partial | none | n/a | comp_p0_018 |
| CT-011 | partial (timelock) | none | reasoning | comp_p0_020 mutant |
| CT-012 | partial (oracle) | none | trust/reasoning | comp_l2_018 mutant |

---

## Mitigation Research Themes (not implementation)

1. **Path isolation invariant family** — every alternate spend function must declare which UTXO pool and bounds it may touch (CT-001, CT-002, CT-004).
2. **Timelock mutual exclusion** — no break-glass without matching delay or amount cap (CT-001, CT-007).
3. **Composition-aware intent invariants** — extend intent matrix beyond single-pattern (CT-002, CT-006).
4. **Negative-control benchmarks** — document Conflicting cells as expected failures (CT-008, CT-009, CT-010).
5. **Hashlock + oracle detector parity** — close P0 single-pattern gaps before composition audit (CT-007, CT-012).

---

## Related Documents

| Document | Relationship |
|----------|--------------|
| [`bch_threat_model.md`](bch_threat_model.md) | Base UTXO/token/covenant threats |
| [`composition_matrix.md`](composition_matrix.md) | Cell cross-ref |
| [`composition_benchmark_strategy.md`](composition_benchmark_strategy.md) | Mutant IDs |
| [`adversarial_strategy.md`](adversarial_strategy.md) | HIDDEN_AUTH, FAKE_AUTH patterns |
| [`false_positive_playbook.md`](false_positive_playbook.md) | TRUST-1 treasury prefunding |
| [`security_patterns/dao_treasury.md`](security_patterns/dao_treasury.md) | DAO emergency path |
| [`coverage_gap_analysis.md`](coverage_gap_analysis.md) | Detector P0 gaps |
| [`research_master_checklist_v2.md`](research_master_checklist_v2.md) | Research vs implementation |
