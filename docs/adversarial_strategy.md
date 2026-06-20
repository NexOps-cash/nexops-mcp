# NexOps Adversarial Corpus Strategy

**Workstream:** B  
**Registry:** [`adversarial_registry.json`](adversarial_registry.json) — **200 scenarios**

---

## Purpose

Stress-test the auditor beyond ground-truth benchmarks:

- **Benchmark corpus (A)** = what should be found
- **Adversarial corpus (B)** = can the system avoid being fooled

~30% intentional overlap with A (adversarial variants of secure baselines).

---

## Taxonomy (8 × 25 = 200)

| Category ID | Name | Count | Techniques |
|-------------|------|-------|------------|
| FAKE_AUTH | Fake auth | 25 | Dead-code checkSig, auth on wrong branch, commented require |
| MISLEAD | Misleading comments | 25 | "SECURE: multisig" above weak check, false @audit annotations |
| PARTIAL | Partial protection | 25 | Recipient bound not value; auth on 1 of 2 paths |
| HIDDEN_AUTH | Hidden auth failure | 25 | Admin + public paths, signature reuse, threshold bypass |
| TRUST | Trust-boundary traps | 25 | Treasury, oracle, key rotation, LP funding |
| TOKEN | Token edge cases | 25 | 0x02 wrong output, commitment truncation, hybrid drift |
| UTXO | UTXO edge cases | 25 | Index OOB, partial aggregation, fee siphon |
| CONTRA | Contradictory signals | 25 | Secure code + scary intent; bundle vs claim mismatch |

---

## Implemented Seeds (23)

Existing adversarial judge scenarios map to registry:

| ID | Category | Status |
|----|----------|--------|
| AG-1..3 | FAKE_AUTH | implemented |
| AUTH-1..3 | HIDDEN_AUTH / FAKE_AUTH | implemented |
| TRUST-1..3 | TRUST | implemented |
| INTENT-1..3 | CONTRA / MISLEAD | implemented |
| CONTRA-1..3 | CONTRA | implemented |
| CONF-1..3 | TRUST / CONTRA | implemented |
| BCH-1..3 | TOKEN / TRUST | implemented |
| MIXED-1..2 | TRUST | implemented |

---

## Evaluation Modes

| Mode | Input | Validates |
|------|-------|-----------|
| `policy_only` | Mock bad `SemanticJudgment` | Guards + `finalize_from_judgment()` |
| `detector_only` | Real `.cash` | No false CRITICAL on secure variants |
| `full_audit` | Real `.cash` + intent + live judge | End-to-end classification |

---

## Planned Scenario Stubs (177)

Remaining entries in registry: `{CATEGORY}-{NN}` with `status: planned`, `family_hint`, and contract sketch TBD during implementation sprint.

Priority order for materialization:

1. FAKE_AUTH, HIDDEN_AUTH (auth is highest volume FP source)
2. TRUST, CONTRA (V2.1 validation focus)
3. TOKEN, UTXO (detector alignment)
4. MISLEAD, PARTIAL (judge stress)

---

## Linkage

| Asset | Link |
|-------|------|
| FP playbook | Each category maps to FP-00N patterns |
| Coverage gaps | P0 gaps drive category priority |
| Replay corpus | Failed adversarial runs → replay entries |
| Benchmark registry | Shared `contract_ref` for baseline variants |

---

## Success Criteria

- [x] 200 scenarios registered
- [x] 8 categories defined
- [x] 23 implemented seeds documented
- [ ] 177 contracts materialized (future sprint)
- [ ] Pytest runner `tests/adversarial_audit/` (future)
