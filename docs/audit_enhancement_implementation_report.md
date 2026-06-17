# Audit Enhancement Implementation Report

**Branch:** `auditenhancement` (merged with `origin/main`)  
**Date:** 2026-06-17  
**Scope:** Finding quality & severity correctness (Phase A + B). No sessions, storage, regression tracking, or scoring redesign.

---

## Files changed

| File | Change |
|------|--------|
| [`src/models.py`](../src/models.py) | Added `FindingKind`, `ConfidenceLevel`, `Provenance`, `Triggerability` enums; extended `AuditIssue`; added `intent_model` to `AuditRequest` |
| [`src/services/finding_policy.py`](../src/services/finding_policy.py) | **New** — title generation, severity caps, triggerability, confidence derivation, `finalize()` chokepoint |
| [`src/services/intent_invariants.py`](../src/services/intent_invariants.py) | **New** — deterministic intent invariant matrix + `verify_intent_invariants()` |
| [`src/services/audit_agent.py`](../src/services/audit_agent.py) | All findings route through `_emit_issue()` → `finding_policy.finalize()`; intent verification; invariant matrix in LLM prompt |
| [`src/server.py`](../src/server.py) | Pass `intent_model` to `AuditAgent.audit()` |
| [`tests/test_finding_policy.py`](../tests/test_finding_policy.py) | **New** — policy unit tests |
| [`tests/test_intent_invariants.py`](../tests/test_intent_invariants.py) | **New** — payroll invariant tests |
| [`tests/test_audit_classification.py`](../tests/test_audit_classification.py) | Updated for new axes; treasury + intent integration tests |
| [`tests/test_audit_semantic.py`](../tests/test_audit_semantic.py) | Fixed `validate_audit` mocks; updated title/severity expectations |
| [`tests/test_policy_lint_semantic.py`](../tests/test_policy_lint_semantic.py) | Fixed `validate_audit` mock |

---

## Architecture decisions

### 1. Single policy chokepoint

All audit findings (compile, lint, detector, intent, semantic) are built via `_emit_issue()` which calls `finding_policy.finalize()`. The LLM supplies `category`, `explanation`, and `confidence` only — **never** final `title` or `severity`.

### 2. Lightweight triggerability (3 values)

`ATTACKER` / `NON_ATTACKER` / `UNKNOWN` replaces the larger RFC enum. Keyword markers + `rule_id` hints classify whether someone can intentionally benefit.

### 3. Scoring unchanged

`scoring.py` is untouched. Legacy `semantic_category` on `AuditReport` is preserved for attacker-path findings; **re-mapped from policy kind only for `NON_ATTACKER` findings** so operational issues do not inflate the semantic bucket.

### 4. Intent invariants before LLM

`verify_intent_invariants()` runs after deterministic detectors when compile succeeds and intent is present. Emits `intent_*` findings with `PROVEN` / `deterministic` provenance.

### 5. Detector rule hints

`RULE_KIND_HINTS` and `RULE_ISSUE_CLASS_HINTS` preserve prior behavior for known detectors (e.g. `output_binding_missing` → `INVARIANT_GAP` / `CONTEXTUAL` / `MEDIUM`).

---

## Deviations from RFC

| RFC item | Implementation |
|----------|----------------|
| Full `Triggerability` enum (OPERATOR, HONEST_FAILURE, etc.) | Deferred — 3-value lightweight enum only |
| `FALSE_POSITIVE` issue_class usage | Not assigned (no resolution tracking in scope) |
| Multi-finding semantic JSON | Single semantic finding retained |
| `HYBRID` provenance | Enum exists; not yet emitted (no corroboration pass) |
| Compile syntax → deployability only | Compile errors use `OPERATIONAL_RISK` with `RULE_SEVERITY_CAP_OVERRIDES` for toolchain errors at HIGH |
| Checklist injection | Invariant matrix only (not full BCH security checklist) |

---

## Unresolved concerns

1. **Intent parsing is heuristic** — fixed-amount detection uses intent text markers + regex on per-output `require()` equality; structured `IntentModel` fields for amounts are not yet defined.
2. **UNKNOWN triggerability defaults permissive** in `is_exploitable()` backward-compat helper (returns `True`) — may still allow some grief findings through as security on deterministic path.
3. **`RULE_KIND_HINTS` is manually curated** — new detectors need hints or rely on keyword inference.
4. **Proportional splits** without literal fixed amounts may not trigger `fixed_amount_per_recipient` (by design — only when intent text requests fixed amounts).
5. **Tests patching `Phase3.validate`** elsewhere in repo may still fail if not updated to `validate_audit` (fixed in touched test files).

---

## Payroll findings: before vs after

### Scenario A — Missing fixed salary (valid first finding)

**Intent:** Fixed recipients + fixed salary amounts per employee.

| | Before | After |
|---|--------|-------|
| Source | LLM semantic only | **Deterministic** `intent_fixed_amount_per_recipient` |
| Title | `Security Risk: Moderate Logic Flaw` or similar | `Policy Gap: fixed amount per recipient` |
| Kind | (none) | `INVARIANT_GAP` |
| Severity | HIGH (semantic) | **MEDIUM** |
| Confidence | LLM float | **PROVEN** |
| Triggerability | (none) | **ATTACKER** |
| Provenance | `llm` | **deterministic** |

### Scenario B — Treasury underfunded (false positive)

**LLM returns:** `EXPLOIT` + `direct_fund_loss` + "Treasury may be underfunded..."

| | Before | After |
|---|--------|-------|
| Title | `Critical Risk: Major Protocol Flaw` | `Operational Risk: Treasury may be underfunded...` or `Deployment Requirement: ...` |
| Kind | (implicit exploit) | `OPERATIONAL_RISK` or `DEPLOYMENT_REQUIREMENT` |
| Severity | CRITICAL / HIGH | **LOW** |
| Triggerability | (none) | **NON_ATTACKER** |
| Security title | Yes | **No** |

### Scenario C — No change / dust handling

| | Before | After |
|---|--------|-------|
| Title | `Security Risk: Moderate Logic Flaw` | `Design Trade-off: ...` |
| Kind | moderate_logic_risk | `DESIGN_TRADE_OFF` |
| Severity | MEDIUM / HIGH | **INFO** |
| Triggerability | (none) | **NON_ATTACKER** |

### Scenario D — After fixing salary enforcement

Deterministic `intent_fixed_amount_per_recipient` **absent** when per-output amount `require()` bindings exist. LLM receives invariant matrix showing salary as **ENFORCED**, reducing re-discovery of the same gap.

---

## Test results

```
86 passed — tests/test_audit_classification.py, test_audit_semantic.py,
test_policy_lint_semantic.py, test_finding_policy.py, test_intent_invariants.py,
tests/audit_engine/*
```

---

## Next phases (out of scope)

- Audit sessions & resolution tracking
- Finding fingerprinting & re-audit memory
- Scoring v3 / security vs operational score split
- Multi-finding semantic output
- Expanded triggerability enum
- Structured `IntentModel` amount fields
