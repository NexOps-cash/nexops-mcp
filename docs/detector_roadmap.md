# NexOps Detector Roadmap

**Workstream:** F (P3 — minimal)  
**Principle:** Semantic judge is the biggest lever; detector investment follows benchmark failures.

---

## High ROI (build or enhance when benchmarks fail)

| Detector | Gap filled | Evidence |
|----------|------------|----------|
| `output_binding_missing` | Value redirection | High fixture pass rate |
| `token_category_drift` | FT/NFT splits | 8 invalid-logic fixtures |
| `authority_leak` / `minting_authority_escape` | Mint escape | Investor demo + fixtures |
| `index_underflow` / `positive_offset_oob` | UTXO index | Audit + gen parity |
| `intent_auth_gate` (invariant) | Missing auth | Classification payroll_d |

---

## Medium ROI (enhance when family benchmark fails)

| Detector | Notes |
|----------|-------|
| `vulnerable_covenant` | Complex state machines need more fixtures |
| `fee_assumption_violation` | Partial fee path coverage |
| `capability_*` set | Audit-only traces; align with gen |
| `partial_aggregation_risk` | Edge cases in aggregation loops |
| Hashlock-specific (new) | **P0 gap** — 5 gen cases, 0 audit |

---

## Low ROI / Deprecate candidates

| Detector | Recommendation |
|----------|----------------|
| `authorization_model_classifier` | Keep metadata-only in audit profile |
| `EVMHallucinationDetector` | Unregistered — delete or never register |
| `MissingOutputLimitDetector` | Unregistered — overlap with lint LNC rules |
| `InvariantBreakDetector` | Unregistered — unclear scope |
| `weak_output_count_limit` | Noisy on valid patterns — profile disable |

---

## Unregistered Detectors (decide: activate or delete)

| Detector | Suggestion |
|----------|------------|
| `EscrowRoleEnforcementDetector` | Activate if escrow benchmarks fail role checks |
| `SpendingPathSecurityDetector` | Merge into dual-path adversarial coverage first |
| `MissingOutputLimitDetector` | Delete — lint covers |
| `EVMHallucinationDetector` | Delete — BCH-only codebase |
| `InvariantBreakDetector` | Delete or document scope |

---

## Overlap: Generation vs Audit

| ID | Gen | Audit | Capability |
|----|-----|-------|------------|
| index_underflow | yes | yes | — |
| output_binding_missing | yes | yes | — |
| partial_aggregation_risk | yes | yes | — |
| token_category_drift | yes | yes | — |
| capability_token_continuity_break | — | yes | yes |

**Maintain parity** when adding detectors; audit profile is source of truth for audit path.

---

## Investment Rule

> Add a detector only when: (1) a benchmark entry fails Tier 1, AND (2) reasoning coverage cannot catch it, AND (3) pattern appears in real-world index.

Otherwise invest in benchmark + adversarial + judge compliance.
