# NexOps Audit System — Strategic Research Sprint Plan

**Version:** 2.0  
**Branch:** `research/audit-sprint-v2`  
**Date:** 2026-06-18

## North Star

> **Benchmark corpus is Workstream #1. Everything else supports it.**

NexOps has **183 generation benchmark cases** but only **~45 audit evaluation scenarios**. This sprint produced durable research assets to close that gap — **no code or architecture redesign**.

---

## Deliverables Completed

| Workstream | Output | Status |
|------------|--------|--------|
| **A** | [`benchmark_strategy.md`](benchmark_strategy.md) + [`benchmark_registry.json`](benchmark_registry.json) (180 entries) | Done |
| **A.5** | [`realworld_collection_strategy.md`](realworld_collection_strategy.md) + [`audit_benchmark_realworld/`](../audit_benchmark_realworld/) | Done |
| **I** | [`audit_replay_strategy.md`](audit_replay_strategy.md) + [`audit_replay_corpus/`](../audit_replay_corpus/) | Done |
| **C** | [`coverage_gap_analysis.md`](coverage_gap_analysis.md) — detector vs reasoning split | Done |
| **B** | [`adversarial_strategy.md`](adversarial_strategy.md) + [`adversarial_registry.json`](adversarial_registry.json) (200 entries) | Done |
| **D** | [`security_patterns/`](security_patterns/) (16 family docs) | Done |
| **E** | [`false_positive_playbook.md`](false_positive_playbook.md) (18 patterns) | Done |
| **H** | [`bch_threat_model.md`](bch_threat_model.md) | Done |
| **F** | [`detector_roadmap.md`](detector_roadmap.md) (minimal) | Done |
| **G** | [`architecture_debt_review.md`](architecture_debt_review.md) (minimal) | Done |
| — | [`research_master_checklist.md`](research_master_checklist.md) | Done |

---

## Pipeline Context

```
compile → lint → detectors → intent_invariants → AuditFactBundle → SemanticJudge V2.1 → finding_policy → report
```

Semantic Judge V2.1 validated: 23/23 adversarial scenarios ([`semantic_judge_v2_1_report.md`](semantic_judge_v2_1_report.md)).

---

## Workstream Details

### A — Benchmark Corpus (#1)

- **180 scenarios** in `benchmark_registry.json`
- **3 tiers:** deterministic (CI), policy (mocked judge), full E2E (nightly)
- Migration map from 183 generation YAML cases
- See [`benchmark_strategy.md`](benchmark_strategy.md)

### A.5 — Real-World Collection

- **28 contracts** indexed: safe / unsafe / unknown
- Sources: golden, anti-pattern, fixtures, classification, adversarial
- See [`realworld_collection_strategy.md`](realworld_collection_strategy.md)

### I — Audit Replay Corpus

- **32 replay entries** with expected vs actual (V2 → V2.1)
- Permanent regression for payroll FP, trust confusion, contradictions
- See [`audit_replay_strategy.md`](audit_replay_strategy.md)

### C — Coverage Analysis (#2)

- **Detector coverage** and **reasoning coverage** reported separately
- P0 gaps: hashlock, oracle detector, fake auth, dual-path
- See [`coverage_gap_analysis.md`](coverage_gap_analysis.md)

### B — Adversarial Corpus (#3)

- **200 scenarios** in 8 categories × 25
- 23 implemented (existing adversarial judge)
- See [`adversarial_strategy.md`](adversarial_strategy.md)

### D — Security Pattern KB (#4)

- 16 family documents with security model, invariants, checklist
- See [`security_patterns/README.md`](security_patterns/README.md)

### E — False Positive Playbook

- 18 documented patterns (FP-001 through FP-018)
- Feeds benchmark negative expectations
- See [`false_positive_playbook.md`](false_positive_playbook.md)

### H — BCH Threat Model (#5)

- UTXO, CashToken, covenant, oracle, treasury threats
- See [`bch_threat_model.md`](bch_threat_model.md)

### F / G — Optional (minimal)

- Detector ROI tiers; architecture debt P0/P1/P2 register
- Low priority vs benchmarks

---

## Execution Order (as completed)

1. A — Benchmark strategy + registry
2. E — FP playbook (parallel)
3. A.5 + I — Real-world + replay
4. C — Coverage gap analysis
5. B — Adversarial strategy
6. D — Security patterns
7. H — Threat model
8. F, G — Minimal roadmaps
9. Master checklist

---

## Success Metrics

| Metric | Target | Actual |
|--------|--------|--------|
| Benchmark scenarios | ≥ 100 | **180** |
| Real-world index | ≥ 20 | **28** |
| Replay entries | ≥ 30 | **32** |
| Adversarial scenarios | ≥ 200 | **200** |
| FP patterns | ≥ 15 | **18** |
| Security pattern docs | 13+ | **16** |
| Detector vs reasoning matrices | 100% attack classes | Done |

---

## Future Implementation Handoff

| Asset | Next step |
|-------|-----------|
| `benchmark_registry.json` | `tests/audit_benchmark/` pytest loader |
| `audit_benchmark_realworld/` | Copy contracts from provenance paths |
| `audit_replay_corpus/` | `scripts/run_audit_replay.py` |
| `adversarial_registry.json` | Materialize 177 planned `.cash` stubs |
| Tier 3 E2E | Nightly workflow with live judge |

---

## Non-Goals (honored)

- No Semantic Judge V2.1 redesign
- No finding policy redesign
- No new RFCs or enums
- No production code changes in this sprint

---

## Generator Scripts

| Script | Output |
|--------|--------|
| `scripts/generate_audit_benchmark_registry.py` | `docs/benchmark_registry.json` |
| `scripts/generate_adversarial_registry.py` | `docs/adversarial_registry.json` |
| `scripts/generate_security_patterns.py` | `docs/security_patterns/*.md` |
