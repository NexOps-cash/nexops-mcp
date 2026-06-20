# Audit Replay Corpus Strategy

**Workstream:** I  
**Output:** [`../audit_replay_corpus/`](../audit_replay_corpus/)

## Goal

Permanent regression suite storing **expected vs actual** audit outcomes. Every pipeline change replays against known historical bugs.

---

## Schema

```json
{
  "id": "replay_payroll_treasury_001",
  "contract_ref": "tests/audit_classification_matrix/scenarios.py:PAYROLL_FIXED_SALARY",
  "intent": "Payroll with treasury pre-funding requirement.",
  "expected_audit": {
    "findings": [],
    "kinds": [],
    "max_severity": "LOW",
    "deployment_allowed": true
  },
  "actual_audit_v2": {
    "findings": [{"kind": "vulnerability", "severity": "CRITICAL"}],
    "bug": "Treasury underfunding flagged as exploitable"
  },
  "actual_audit_v2_1": {
    "findings": [{"kind": "deployment_requirement", "severity": "LOW"}],
    "fixed": true
  },
  "replay_trigger": "payroll_fp",
  "fp_pattern": "FP-001",
  "source": "audit_enhancement_implementation_report"
}
```

---

## Seed Replays (30+)

See [`../audit_replay_corpus/index.json`](../audit_replay_corpus/index.json).

| ID | Trigger | V2 bug | V2.1 fix |
|----|---------|--------|----------|
| replay_payroll_treasury_001 | payroll_fp | VULN CRITICAL | DEPLOYMENT_REQUIREMENT LOW |
| replay_payroll_auth_hallucination_001 | adversarial_fail | AUTH hallucination | none + contradicts |
| replay_trust_oracle_001 | trust_confusion | VULNERABILITY | DEPLOYMENT_REQUIREMENT |
| replay_contra_auth_001 | bundle_contradiction | VULNERABILITY | suppressed |
| replay_ag_dust_001 | attacker_gain | operational_risk | VULNERABILITY or INVARIANT_GAP |
| replay_intent_metadata_001 | intent_tier | VULNERABILITY | none |

---

## Replay Runner (Future)

```
scripts/run_audit_replay.py --corpus audit_replay_corpus/index.json --tier 3
```

Pass: `actual_audit` matches `expected_audit` on kind + severity ceiling.

---

## Integration

- Links to [`false_positive_playbook.md`](false_positive_playbook.md) via `fp_pattern`
- Links to [`benchmark_registry.json`](benchmark_registry.json) via shared contract refs
- Links to adversarial IDs (AG-*, TRUST-*, etc.)
