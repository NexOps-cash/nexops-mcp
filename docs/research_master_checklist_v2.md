# NexOps Research Master Checklist v2

**Sprint:** Phase 2 Composition Research (Wave 4 — Capstone)  
**Branch:** `research/composition-sprint-v2`  
**Date:** 2026-06-20  
**Status:** Research complete for Wave 4 deliverables — **no implementation authorized until separate sprint approved**

---

## Prerequisites

| Prerequisite | Status | Evidence |
|--------------|--------|----------|
| Audit Research Sprint v1 | **Complete** | [`research_master_checklist.md`](research_master_checklist.md) — 180 benchmarks, 200 adversarial, 16 security patterns |
| Wave 1 — Scorecard + Matrix + Catalog | **Complete** | [`composition_readiness_scorecard.md`](composition_readiness_scorecard.md), [`composition_matrix.md`](composition_matrix.md), [`uncommon_contract_catalog.md`](uncommon_contract_catalog.md) §P0 |
| Wave 2 — Evidence foundation | **Complete** | [`generation_failure_corpus.md`](generation_failure_corpus.md), [`pattern_maturity_heatmap.md`](pattern_maturity_heatmap.md), [`bch_contract_ecosystem.md`](bch_contract_ecosystem.md) |
| Wave 3 — Architecture studies | **Complete** | [`multi_pattern_generation_architecture.md`](multi_pattern_generation_architecture.md), [`multi_pattern_audit_architecture.md`](multi_pattern_audit_architecture.md) |
| Wave 4 — Strategy + capstone | **Complete** | This checklist + benchmark strategy + threat model + roadmap |

---

## Sprint v2 Deliverable Index (12 documents)

| # | Document | Wave | Status |
|---|----------|------|--------|
| 0 | [`composition_readiness_scorecard.md`](composition_readiness_scorecard.md) | 1 | Complete |
| 1 | [`composition_matrix.md`](composition_matrix.md) | 1 | Complete |
| 2 | [`uncommon_contract_catalog.md`](uncommon_contract_catalog.md) | 1 | Complete |
| 3 | [`generation_failure_corpus.md`](generation_failure_corpus.md) | 2 | Complete |
| 4 | [`pattern_maturity_heatmap.md`](pattern_maturity_heatmap.md) | 2 | Complete |
| 5 | [`bch_contract_ecosystem.md`](bch_contract_ecosystem.md) | 2 | Complete |
| 6 | [`multi_pattern_generation_architecture.md`](multi_pattern_generation_architecture.md) | 3 | Complete |
| 7 | [`multi_pattern_audit_architecture.md`](multi_pattern_audit_architecture.md) | 3 | Complete |
| 8 | [`composition_benchmark_strategy.md`](composition_benchmark_strategy.md) | 4 | Complete |
| 9 | [`composition_threat_model.md`](composition_threat_model.md) | 4 | Complete |
| 10 | [`pattern_coverage_roadmap.md`](pattern_coverage_roadmap.md) | 4 | Complete |
| 11 | [`research_master_checklist_v2.md`](research_master_checklist_v2.md) | 4 | Complete (this doc) |

### Sprint v1 assets (do not recreate)

| Asset | Path |
|-------|------|
| Audit benchmark registry | [`benchmark_registry.json`](benchmark_registry.json) |
| Executable CI benchmarks | [`benchmark_registry_executable.json`](benchmark_registry_executable.json) |
| BCH threat model (base) | [`bch_threat_model.md`](bch_threat_model.md) |
| Security pattern KB | [`security_patterns/`](security_patterns/) |
| Adversarial registry | [`adversarial_registry.json`](adversarial_registry.json) |
| Real-world index | [`audit_benchmark_realworld/`](../audit_benchmark_realworld/) |
| Audit replay corpus | [`audit_replay_corpus/`](../audit_replay_corpus/) |

---

## Priority 1 — Research complete / Implementation future

| # | Item | Impact | Effort | Dependencies | Research | Implementation |
|---|------|--------|--------|--------------|----------|----------------|
| 1 | **P0 top 20 catalog ranking** | Anchors all Phase 2 work | 2d | Wave 1 | **Done** — [`uncommon_contract_catalog.md`](uncommon_contract_catalog.md) §P0 | — |
| 2 | **12×12 composition matrix** | Pairwise feasibility | 3d | Scorecard | **Done** — [`composition_matrix.md`](composition_matrix.md) | — |
| 3 | **130 composition benchmark specs** | Measurement corpus design | 3d | Matrix, P0 | **Done** — [`composition_benchmark_strategy.md`](composition_benchmark_strategy.md) | M0–M4 phases deferred |
| 4 | **Composition threat model (CT-001–012)** | Interaction-emergent audit | 2d | Matrix, bch_threat_model | **Done** — [`composition_threat_model.md`](composition_threat_model.md) | Detectors deferred |
| 5 | **Pattern coverage roadmap (28 items)** | Execution order | 2d | All Wave 1–4 | **Done** — [`pattern_coverage_roadmap.md`](pattern_coverage_roadmap.md) | Items B1–C5 deferred |
| 6 | **Composition planner research** | L3+ generation path | 3d | Matrix | Wave 3 doc | **Not authorized** |
| 7 | **Path isolation invariant family** | CT-001–004 mitigation | 2d | Threat model | Spec in threat model + Wave 3 | **Not authorized** |
| 8 | **Split N-output implementation** | Unblocks 51 catalog entries | 2–3w | R-04 resolution | RCA in failure corpus | **Future sprint** |

---

## Priority 2 — Research complete / Implementation future

| # | Item | Impact | Effort | Dependencies | Research | Implementation |
|---|------|--------|--------|--------------|----------|----------------|
| 9 | **Generation failure corpus** | Institutional memory | 2d | RCAs | **Done** — 80+ entries | — |
| 10 | **Pattern maturity heatmap** | 12×10 dimensional scores | 2d | statusjune | **Done** | — |
| 11 | **BCH ecosystem survey** | Real-world validation | 2d | A.5 index | **Done** | External harvest deferred |
| 12 | **Multi-pattern audit architecture** | Interaction invariants | 3d | Threat model | Wave 3 | **Not authorized** |
| 13 | **Hashlock detector** | CT-007, UCT-065 | 3d | Sprint v1 gap | Gap documented | **Future sprint** |
| 14 | **Governance timelock bypass invariant** | CT-001, UCT-017 | 2d | Threat model | Spec complete | Detector deferred |
| 15 | **Composition benchmark M0** | 12 L1/L2 audit fixtures | 1w | Schema R-20 | Schema proposed | **Future sprint** |
| 16 | **Vault evaluator FN fix** | UCT-033, 113, 114 | 1w | vault_layer_diagnosis | Gap documented | **Future sprint** |
| 17 | **HTLC golden template** | UCT-065 | 1w | Hashlock fix | Spec in benchmark_strategy | **Future sprint** |
| 18 | **Adversarial composition traps (25)** | Red team CT-* | 2d | adversarial_strategy | R-28 spec | Materialize deferred |

---

## Priority 3 — Deferred / Optional

| # | Item | Impact | Effort | Dependencies | Research | Implementation |
|---|------|--------|--------|--------------|----------|----------------|
| 19 | **Subscription first-class routing** | UCT-081 | 3–4w | Refundable RCA | Defer decision documented | **Defer to 2027** |
| 20 | **Covenant+Split resolution** | UCT-052 | 1d | semantic_005_008 | **Done** — permanent X | No impl planned |
| 21 | **L4/L5 generic composite** | UCT-207 | — | Planner | Negative control spec | **Defer** |
| 22 | **Tier 3 composition E2E** | Live judge on L4 | 1w | M3 | Mode mapped | **Future sprint** |
| 23 | **External hackathon harvest** | Real-world comp | 1w | A.5 | Strategy in ecosystem doc | **Future** |
| 24 | **CompositionIR prototype** | Planner input | 4–6w | Wave 3 arch | **Research only** | **Not authorized** |
| 25 | **Function graph generation** | Multi-function planner | 4–6w | CompositionIR | **Research only** | **Not authorized** |

---

## Review Gate Checklist

- [x] P0 top 20 ranked and evidence-linked — [`uncommon_contract_catalog.md`](uncommon_contract_catalog.md)
- [x] 130 composition benchmark specs — [`composition_benchmark_strategy.md`](composition_benchmark_strategy.md)
- [x] 12 interaction-emergent threats — [`composition_threat_model.md`](composition_threat_model.md)
- [x] 28 ranked roadmap items — [`pattern_coverage_roadmap.md`](pattern_coverage_roadmap.md)
- [x] Research vs implementation separated in all P1–P3 tables
- [x] No implementation code in Wave 4 branch
- [x] Major claims labeled MEASURED / INFERRED / PROJECTED
- [x] No duplication of UTXO base threats from `bch_threat_model.md`
- [ ] Wave 3 architecture docs complete (in progress)
- [ ] PR merge to `main` pending full 12-doc review

---

## 6–12 Month Roadmap (PROJECTED)

Assumes dedicated implementation sprint approved after research merge. Dates from 2026-06-20.

### Q3 2026 (Jul–Sep) — Foundation fixes

| Month | Focus | Deliverables | P0 contracts unlocked |
|-------|-------|--------------|----------------------|
| Jul | Split N-output + routing decision | R-01, R-04, R-06 | UCT-049, 051 partial |
| Aug | Hashlock + timelock audit | R-05, R-13, R-03 impl | UCT-065 |
| Sep | Composition benchmark M0 + M1 | R-08, CT mutants | L1 audit corpus |

**Exit criteria:** 12 L1 composition audit benches green in CI; Split ≥85% conv **PROJECTED**.

### Q4 2026 (Oct–Dec) — L2 convergence

| Month | Focus | Deliverables | P0 contracts unlocked |
|-------|-------|--------------|----------------------|
| Oct | HTLC golden + Escrow triples | R-09, comp_l2_* | UCT-065, 067, 066 |
| Nov | Vault+NFT + governance specs | R-14, R-07 impl | UCT-035, 017 partial |
| Dec | Planner research → spec review | Wave 3 arch approval | L3 design gate |

**Exit criteria:** 10/20 P0 generatable or audit-complete **PROJECTED**.

### Q1 2027 (Jan–Mar) — L3 generation research → prototype

| Month | Focus | Deliverables | P0 contracts unlocked |
|-------|-------|--------------|----------------------|
| Jan | Composition planner prototype (if approved) | R-02 impl | — |
| Feb | Payroll Treasury L3 bench | comp_p0_001 | UCT-001 partial |
| Mar | DAO Treasury L3 | comp_p0_002 | UCT-017 |

**Exit criteria:** 2 L4 contracts compile with planner **PROJECTED**.

### Q2 2027 (Apr–Jun) — L3 audit + L4 research

| Month | Focus | Deliverables | P0 contracts unlocked |
|-------|-------|--------------|----------------------|
| Apr | Multi-pattern audit invariants live | R-11 impl | CT-001–003 detected |
| May | Crowdfund + grant L3 | comp_p0_013, 005 | UCT-129, 049 |
| Jun | L4 negative controls + subscription defer review | comp_l4_* | UCT-081 defer confirmed |

**Exit criteria:** 15/20 P0 audit-complete; 8/20 P0 generatable **PROJECTED**.

---

## Path From Pattern Generator To General BCH Contract Generator

Anchored on **P0 top 20** contracts ([`uncommon_contract_catalog.md`](uncommon_contract_catalog.md) §P0). All answers claim-labeled.

### 1. What capabilities NexOps already has

**MEASURED:**
- Single-pattern generation at ≥95% convergence for Escrow, Multisig, CashTokens FT/NFT ([`composition_readiness_scorecard.md`](composition_readiness_scorecard.md))
- 2-pattern golden paths: Escrow+Multisig (`escrow_basic_multisig`), Escrow+NFT (`escrow_2of3_nft`), Escrow+FT, Multisig+Timelock ([`composition_matrix.md`](composition_matrix.md))
- 180-entry audit benchmark registry with 38 executable CI cases ([`benchmark_registry.json`](benchmark_registry.json))
- 16-family security pattern KB with payroll, dao_treasury, hybrid docs ([`security_patterns/`](security_patterns/))
- Phase 1–4 pipeline with pattern rails, golden templates, DSL lint, toll gate ([`3_PHASE_GENERATION_ARCHITECTURE.md`](3_PHASE_GENERATION_ARCHITECTURE.md))
- Semantic Judge V2.1 validated on 23 adversarial scenarios ([`semantic_judge_v2_1_report.md`](semantic_judge_v2_1_report.md))

**INFERRED:**
- Tag stacking + additive YAML rails support **L1** where both patterns are Composite Ready and no `effective_mode` conflict
- Audit detects single-pattern token authority, auth gate, output binding at high precision on GREEN families

**P0 contracts generatable today (MEASURED):** UCT-066 NFT Escrow, UCT-067 Milestone Payout — 2 of 20.

---

### 2. What capabilities are missing

**MEASURED:**
- No composition planner — `resolve_effective_mode()` single-winner ([`composition_matrix.md`](composition_matrix.md))
- Split 50% convergence; 2-output hardcode ([`split_payment_state_report.md`](split_payment_state_report.md))
- `A_split_multisig` compile FAILED ([`composition_matrix.md`](composition_matrix.md))
- Zero executable multi-pattern generation benchmarks
- Governance timelock bypass: no detector ([`bch_threat_model.md`](bch_threat_model.md), CT-001)
- Hashlock: no audit detector ([`coverage_gap_analysis.md`](coverage_gap_analysis.md))
- Subscription: not first-class (25% gen) ([`composition_readiness_scorecard.md`](composition_readiness_scorecard.md))
- Evaluator pattern alias decoupling — masks composite quality **MEASURED** in layer diagnoses

**INFERRED:**
- No cross-function path isolation invariants
- No composition tags in generation YAML suites
- No `composition_level` field in audit registry (proposed in benchmark_strategy)

**P0 contracts blocked (PROJECTED):** 16 of 20 require Split fix and/or planner.

---

### 3. What architectural upgrades are required

**Research findings only — NOT approved for implementation:**

| Upgrade | Purpose | P0 impact | Label |
|---------|---------|-----------|-------|
| **Composition planner** | Multi-function contracts with isolated paths | UCT-001, 003, 017 | INFERRED |
| **N-output Split rail** | Distribution to N recipients | UCT-001, 049, 129 | MEASURED blocker |
| **effective_mode → mode set** | Resolve rail conflicts | Split+Multisig X | INFERRED |
| **CompositionIR** (research) | Intent decomposition to function graph | L3+ | PROJECTED |
| **Golden composite templates** | Staged synthesis for C/N triples | UCT-065, 033 | INFERRED |
| **Composition evaluator** | Multi-pattern feature satisfaction | All P0 | INFERRED |

**Conflicting pairs requiring architectural decision, not force-compose:** Split+Multisig, Split+Subscription, Covenant+Split ([`composition_matrix.md`](composition_matrix.md) X cells).

---

### 4. What audit upgrades are required

| Upgrade | Threat | P0 contract | Label |
|---------|--------|-------------|-------|
| `timelock_mutual_exclusion` invariant | CT-001 | UCT-017, 113 | INFERRED |
| `governance_recovery_bounded` invariant | CT-002 | UCT-003 | INFERRED |
| `path_isolation` cross-function | CT-004 | UCT-001 | INFERRED |
| Hashlock detector | CT-007 | UCT-065 | MEASURED gap |
| `hybrid_continuity` cross-path | CT-005 | UCT-015 | INFERRED |
| Composition-aware semantic judge slots | CT-006 | UCT-129 | MEASURED single-slot ceiling |
| Oracle composition binding | CT-012 | UCT-161 | INFERRED |

**MEASURED:** Single semantic slot compensated by deterministics today ([`semantic_judge_v2_adversarial_report.md`](semantic_judge_v2_adversarial_report.md)) — insufficient for L4 payroll+governance reasoning.

---

### 5. What benchmark upgrades are required

| Upgrade | Spec count | Tier | Label |
|---------|------------|------|-------|
| Composition benchmark registry (new JSON) | 130 specs | Research doc | Done — no JSON yet |
| `composition_level` + `required_patterns` schema | 130 | M0–M4 | PROJECTED |
| P0 mutant variants (CT-001–006) | 7 | Tier 1–2 | PROJECTED |
| L1 40-spec table materialization | 40 | fast/standard | PROJECTED |
| Generation convergence benches for L3 | 25 | separate runner | PROJECTED |
| Coverage probes for known CT gaps | 12 | `--include-coverage-probes` | INFERRED |

Align with [`evaluation_modes.md`](evaluation_modes.md): fast for L1 structural; standard for L2–L3 invariants; full for L4 governance.

---

### 6. What realistic timeline reaches multi-pattern contract generation

| Milestone | Timeline | P0 coverage | Label |
|-----------|----------|-------------|-------|
| L1 2-pattern free synthesis (C pairs) | **Now** — 12 pairs | UCT-066, 067 | MEASURED |
| L2 3-pattern golden templates | Q4 2026 | +UCT-065, 035, 070 | PROJECTED |
| L3 4-pattern with planner | Q1–Q2 2027 | +UCT-017, 033, 113 | PROJECTED |
| L4 5-pattern Payroll Treasury | Q2–Q3 2027 | UCT-001, 003 | PROJECTED |
| L4 Subscription Treasury | Defer 2027+ | UCT-081 | INFERRED — X cell |

**Critical path:** Split N-output (R-01) ∥ planner research (R-02) → L3 prototype Q1 2027 **PROJECTED**.

---

### 7. What realistic timeline reaches multi-pattern contract auditing

| Milestone | Timeline | Detection target | Label |
|-----------|----------|------------------|-------|
| L1 composition audit fixtures | Q3 2026 | Token drift, auth on 2-path | PROJECTED |
| CT-001 timelock bypass invariant | Q4 2026 | UCT-017 | PROJECTED |
| CT-002 governance recovery | Q1 2027 | UCT-003 | PROJECTED |
| L3 interaction invariants live | Q2 2027 | 8/12 CT threats | PROJECTED |
| L4 full judge on payroll+governance | Q3 2027 | UCT-001, 003 | PROJECTED |

**MEASURED:** Sprint v1 audit covers single-pattern at 85–95% on GREEN families. Composition audit lags generation by ~2 quarters **PROJECTED**.

---

### 8. Biggest technical risks

| Risk | Severity | Evidence | Mitigation research |
|------|----------|----------|---------------------|
| Composition planner complexity underestimated | **High** | No prior art in pipeline | Wave 3 architecture study |
| Split N-output fix insufficient for token splits | **High** | 50% conv MEASURED | GF-005–007 in failure corpus |
| effective_mode refactor breaks GREEN singles | **Medium** | Escrow 100% MEASURED | Golden regression |
| Evaluator continues masking composite failures | **Medium** | Layer diagnoses MEASURED | R-24 decoupling |
| Conflicting pairs force-composed | **High** | X cells documented | Negative controls only |
| Planner + LLM synthesis variance on L4 | **Medium** | Vault 67% MEASURED | Golden-first policy |

---

### 9. Biggest research risks

| Risk | Severity | Notes |
|------|----------|-------|
| P0 top 20 ranking wrong for ecosystem | Medium | Validated against bch_contract_ecosystem; 28 real-world sample small |
| 130 benchmark specs over-specify before planner exists | Medium | 102/130 marked PROJECTED/blocked |
| Duplicating Sprint v1 audit work | Low | Schema extends, not replaces |
| Implementation pressure before Wave 3 complete | **High** | This checklist gates authorization |
| Subscription defer stranding 19 catalog entries | Medium | Documented P2 defer |
| 6–12 month timeline optimistic if Split fix slips | **High** | 51 catalog entries depend on R-01 |

---

### 10. Recommended roadmap for the next 6–12 months

**Q3 2026 — Measure and fix foundations**
1. Approve implementation sprint (separate from this research)
2. Split N-output (R-01) + Split+Multisig decision (R-04)
3. Materialize composition benchmark M0 — 12 L1 audit fixtures (R-08)
4. Hashlock detector (R-05) for UCT-065

**Q4 2026 — L2 convergence**
5. HTLC golden (R-09) → UCT-065 generatable
6. Vault evaluator FN (R-06) → UCT-033, 113
7. Complete Wave 3 architecture docs → planner spec review gate
8. Governance timelock invariant research → Tier 2 policy bench (R-26)

**Q1 2027 — L3 prototype**
9. Composition planner prototype (if approved) — **only after research merge**
10. DAO Treasury (UCT-017) + Recovery Vault (UCT-113) L3 benches
11. Multi-pattern audit invariants (R-11 implementation)
12. Payroll Treasury partial (UCT-001) — 4-pattern without Subscription

**Q2 2027 — P0 audit parity**
13. Crowdfund Refundable (UCT-129) + Grant Distribution (UCT-049)
14. Hybrid FT/NFT Treasury audit (UCT-015)
15. L4 negative controls (UCT-081, 052, 207) — document expected failures
16. Adversarial composition traps materialize (R-28)

**Defer beyond 12 months:** Subscription compositions (UCT-081), L5 generic composite (UCT-207), CompositionIR production.

---

## P0 Top 20 — Research Status Summary

| Rank | UCT | Contract | Gen research | Audit research | Impl authorized |
|------|-----|----------|--------------|----------------|-----------------|
| 1 | UCT-001 | Payroll Treasury | Planner required | CT-001,004,006 specs | **No** |
| 2 | UCT-017 | DAO Treasury | L3 golden feasible | CT-001,002 specs | **No** |
| 3 | UCT-033 | Founder Vesting | Split blocks | Vault+Timelock spec | **No** |
| 4 | UCT-034 | Investor Vesting | Covenant partial | CT-003 spec | **No** |
| 5 | UCT-049 | Grant Distribution | Split blocks | CT-004 spec | **No** |
| 6 | UCT-051 | Revenue Sharing | Escrow+FT path | CT-005 partial | **No** |
| 7 | UCT-065 | HTLC Escrow | Almost | CT-007 spec | **No** |
| 8 | UCT-066 | NFT Escrow | **Generatable** | MEASURED bench | Partial — maintain |
| 9 | UCT-113 | Recovery Vault | Almost | CT-001,002 spec | **No** |
| 10 | UCT-081 | Subscription Treasury | **Defer** X cell | CT-009 spec | **No** |
| 11 | UCT-002 | Token Payroll | Split blocks | CT-005 spec | **No** |
| 12 | UCT-067 | Milestone Payout | **Generatable** | MEASURED bench | Partial — maintain |
| 13 | UCT-129 | Crowdfund Refundable | Split+Refundable | CT-011 spec | **No** |
| 14 | UCT-035 | NFT Vesting | Almost | CT-003,005 spec | **No** |
| 15 | UCT-114 | Emergency Recovery | Almost | CT-002 spec | **No** |
| 16 | UCT-015 | Hybrid Treasury | FT+NFT C | CT-005 spec | **No** |
| 17 | UCT-050 | Grant Streaming | Split blocks | CT-004 spec | **No** |
| 18 | UCT-052 | Revenue Decay | Covenant only | CT-010 X cell | **No** |
| 19 | UCT-003 | Payroll Gov Recovery | L4 planner | CT-002,006 spec | **No** |
| 20 | UCT-068 | Milestone Release | Partial | CT-011 spec | **No** |

---

## Authorization Gate

```
┌─────────────────────────────────────────────────────────────┐
│  IMPLEMENTATION NOT AUTHORIZED                              │
│                                                             │
│  Prerequisites for implementation sprint approval:          │
│  1. All 12 Phase 2 research docs merged to main             │
│  2. Wave 3 architecture studies reviewed                    │
│  3. P0 top 20 ranking accepted by stakeholders              │
│  4. composition_benchmark_strategy.md M0 scope approved     │
│  5. Separate implementation sprint charter signed           │
│                                                             │
│  Until then: research-only commits on                       │
│  research/composition-sprint-v2                             │
└─────────────────────────────────────────────────────────────┘
```

---

## Quick Links — Full Phase 2 + Sprint v1 Cross-Reference

| Topic | Phase 2 doc | Sprint v1 / supporting doc |
|-------|-------------|---------------------------|
| Pattern readiness | [scorecard](composition_readiness_scorecard.md) | [statusjune.md](../statusjune.md) |
| Pairwise feasibility | [matrix](composition_matrix.md) | [security_patterns/](security_patterns/) |
| Business contracts | [catalog](uncommon_contract_catalog.md) | [realworld index](../audit_benchmark_realworld/) |
| Failures | [failure corpus](generation_failure_corpus.md) | [false_positive_playbook](false_positive_playbook.md) |
| Maturity | [heatmap](pattern_maturity_heatmap.md) | [coverage_gap_analysis](coverage_gap_analysis.md) |
| Ecosystem | [bch_contract_ecosystem](bch_contract_ecosystem.md) | BCH_Knowledge_Base |
| Generation arch | [multi_pattern_generation_architecture](multi_pattern_generation_architecture.md) | [3_PHASE_GENERATION_ARCHITECTURE](3_PHASE_GENERATION_ARCHITECTURE.md) |
| Audit arch | [multi_pattern_audit_architecture](multi_pattern_audit_architecture.md) | [audit_pipeline_architecture](audit_pipeline_architecture.md) |
| Benchmarks | [composition_benchmark_strategy](composition_benchmark_strategy.md) | [benchmark_strategy](benchmark_strategy.md) |
| Threats | [composition_threat_model](composition_threat_model.md) | [bch_threat_model](bch_threat_model.md) |
| Roadmap | [pattern_coverage_roadmap](pattern_coverage_roadmap.md) | [detector_roadmap](detector_roadmap.md) |
| Checklist v1 | — | [research_master_checklist](research_master_checklist.md) |
| Evaluation | [evaluation_modes](evaluation_modes.md) | [benchmark_registry.json](benchmark_registry.json) |

---

## Sprint v2 Completion Criteria

- [x] P0 top 20 validated and ranked
- [x] ≥100 composition benchmark specifications (130 delivered)
- [x] Interaction-emergent threat model extending bch_threat_model
- [x] 25–30 ranked roadmap items with dependencies
- [x] Path From Pattern Generator section — 10 questions answered
- [x] 6–12 month quarterly roadmap
- [x] Research vs implementation clearly separated
- [x] No judge/policy/generator code changes
- [ ] Wave 3 docs complete (parent sprint item)
- [ ] PR merge pending
