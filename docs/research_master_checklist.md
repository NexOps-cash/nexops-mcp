# NexOps Research Master Checklist

**Sprint:** Audit Research v2  
**Branch:** `research/audit-sprint-v2`

---

## Priority 1 — Highest leverage (complete)

| # | Item | Impact | Effort | Dependencies | Status |
|---|------|--------|--------|--------------|--------|
| 1 | **A: Benchmark strategy + 180-entry registry** | Enables all future measurement | 5–6d | — | **Done** — [`benchmark_strategy.md`](benchmark_strategy.md), [`benchmark_registry.json`](benchmark_registry.json) |
| 2 | **A.5: Real-world contract index** | Higher signal than synthetic | 3–4d | A | **Done** — [`audit_benchmark_realworld/`](../audit_benchmark_realworld/) |
| 3 | **I: Audit replay corpus** | Permanent regression suite | 3–4d | E, A.5 | **Done** — [`audit_replay_corpus/`](../audit_replay_corpus/) |
| 4 | **C: Split coverage analysis** | Detector vs reasoning gaps | 4–5d | A family list | **Done** — [`coverage_gap_analysis.md`](coverage_gap_analysis.md) |
| 5 | **B: 200 adversarial scenario spec** | Stress-test judge + policy | 4–5d | C, E | **Done** — [`adversarial_strategy.md`](adversarial_strategy.md) |
| 6 | **E: False positive playbook** | Prevents benchmark pollution | 2–3d | — | **Done** — [`false_positive_playbook.md`](false_positive_playbook.md) |

---

## Priority 2 — Important (complete)

| # | Item | Impact | Effort | Dependencies | Status |
|---|------|--------|--------|--------------|--------|
| 7 | **D: Security pattern KB** | Human audit knowledge | 5–7d | C | **Done** — [`security_patterns/`](security_patterns/) |
| 8 | **H: BCH threat model** | Long-term reference | 3–4d | C | **Done** — [`bch_threat_model.md`](bch_threat_model.md) |

---

## Priority 3 — Optional / future (complete or deferred)

| # | Item | Impact | Effort | Dependencies | Status |
|---|------|--------|--------|--------------|--------|
| 9 | **F: Detector roadmap** | Low vs benchmarks | 1–2d | C | **Done (minimal)** — [`detector_roadmap.md`](detector_roadmap.md) |
| 10 | **G: Architecture debt** | Low — known issues | skip | — | **Done (minimal)** — [`architecture_debt_review.md`](architecture_debt_review.md) |
| 11 | Implement `tests/audit_benchmark/` | Tier 1 CI | 1–2 weeks | A spec | **Future** |
| 12 | Materialize 177 adversarial `.cash` files | Full B corpus | 2–3 weeks | B spec | **Future** |
| 13 | Copy real-world contracts to `contracts/` | A.5 phase 2 | 1 week | A.5 index | **Future** |
| 14 | Tier 3 nightly E2E runner | Model regression | 1 week | A, I | **Future** |
| 15 | Hashlock audit matrix (P0 gap) | Family coverage | 3d | A migration | **Future** |

---

## Recommended Next Execution Order (implementation phase)

1. `tests/audit_benchmark/test_tier1.py` — load `benchmark_registry.json`, Tier 1 deterministic
2. Expand classification matrix with hashlock, decay, covenant scenarios from registry
3. `scripts/run_audit_replay.py` — replay corpus on each release
4. Harvest 10+ external hackathon contracts into A.5 index
5. Materialize FAKE_AUTH + HIDDEN_AUTH adversarial contracts (highest FP source)
6. Register or delete 5 unregistered detectors per roadmap

---

## Quick Links

| Document | Purpose |
|----------|---------|
| [research_sprint_plan.md](research_sprint_plan.md) | Master sprint summary |
| [benchmark_strategy.md](benchmark_strategy.md) | Evaluation corpus design |
| [coverage_gap_analysis.md](coverage_gap_analysis.md) | What to test next |
| [false_positive_playbook.md](false_positive_playbook.md) | What NOT to flag |
| [adversarial_strategy.md](adversarial_strategy.md) | How to break the auditor |

---

## Sprint Completion Criteria

- [x] ≥ 100 benchmark specifications
- [x] ≥ 200 adversarial specifications
- [x] Detector + reasoning coverage matrices
- [x] Real-world + replay corpus designs
- [x] Security pattern KB
- [x] FP institutional memory
- [x] No judge/policy code changes
