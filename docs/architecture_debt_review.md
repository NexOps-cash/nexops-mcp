# NexOps Architecture Debt Review

**Workstream:** G (P3 — minimal register)  
**No redesign proposals** — ranked maintainability risks only.

---

## P0 — High blast radius

| Item | Risk | Remediation type |
|------|------|------------------|
| Triple taxonomy drift (`contract_type` / `canonical_pattern` / YAML `family`) | Wrong profile → disabled detectors | document-only mapping table |
| `UNKNOWN` triggerability defaults permissive | Grief findings as security | policy tweak when benchmarks demand |
| Audit vs gen detector registry drift | Missed findings on audit path | consolidate registry (future) |

---

## P1 — Maintainability

| Item | Risk | Remediation type |
|------|------|------------------|
| Three invariant modules (`intent_invariants`, `invariant_engine`, `invariant_engine_core`) | Confusion on which engine runs | document pipeline diagram |
| Manual `RULE_KIND_HINTS` curation | New detectors misclassified | add hint with each detector PR |
| Legacy judge path `SEMANTIC_JUDGE_V2=0` | Two codepaths to test | delete when Tier 3 stable |
| Intent amount heuristics (regex) | payroll false positives/negatives | structured IntentModel fields (future) |

---

## P2 — Cleanup

| Item | Risk | Remediation type |
|------|------|------------------|
| 5 unregistered detectors in `anti_pattern_detectors.py` | Dead code confusion | delete per detector roadmap |
| Duplicate `single_sig_transfer` YAML suites | Benchmark noise | merge files |
| `benchmark/results/` unbounded growth | Disk | retention policy |

---

## Deferred (do not address in research sprint)

- Full triggerability enum expansion
- Multi-finding semantic JSON
- Shared protocol IR between gen and audit
- Scoring v3 redesign
