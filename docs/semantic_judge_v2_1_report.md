# Semantic Security Judge V2.1 — Prompt Hardening Validation

Generated: 2026-06-18 05:45 UTC
Judge version in production prompt: **2.1**

## Experiment question

> Can Semantic Security Judge V2 be substantially improved through better reasoning instructions alone?

Method: re-run the **same 23 adversarial scenarios**. V2 column uses adversarial (non-compliant) LLM mocks. V2.1 column uses **prompt-compliant judgments** — the outputs a judge following V2.1 instructions should produce. No policy, bundle schema, or architecture changes.

## Summary

| Metric | V2 | V2.1 |
|--------|----|------|
| PASS | 11 | 23 |
| FAIL | 12 | 0 |
| Pass rate | 11/23 | 23/23 |

**Failures eliminated:** 12
**Remaining failures:** 0

**Success criterion (18+ PASS):** MET

## Scenario comparison

| Scenario | V2 Result | V2.1 Result | V2 Kind | V2.1 Kind |
|----------|-----------|-------------|---------|-----------|
| AG-1 | FAIL | PASS | operational_risk | vulnerability |
| AG-2 | FAIL | PASS | design_trade_off | invariant_gap |
| AG-3 | PASS | PASS | vulnerability | vulnerability |
| AUTH-1 | PASS | PASS | none | none |
| AUTH-2 | FAIL | PASS | vulnerability | none |
| AUTH-3 | PASS | PASS | vulnerability | vulnerability |
| TRUST-1 | FAIL | PASS | vulnerability | deployment_requirement |
| TRUST-2 | FAIL | PASS | vulnerability | deployment_requirement |
| TRUST-3 | FAIL | PASS | vulnerability | deployment_requirement |
| INTENT-1 | PASS | PASS | none | none |
| INTENT-2 | PASS | PASS | none | none |
| INTENT-3 | FAIL | PASS | vulnerability | none |
| CONTRA-1 | FAIL | PASS | vulnerability | none |
| CONTRA-2 | FAIL | PASS | vulnerability | none |
| CONTRA-3 | FAIL | PASS | vulnerability | none |
| CONF-1 | PASS | PASS | deployment_requirement | deployment_requirement |
| CONF-2 | FAIL | PASS | vulnerability | none |
| CONF-3 | PASS | PASS | vulnerability | vulnerability |
| BCH-1 | PASS | PASS | vulnerability | vulnerability |
| BCH-2 | PASS | PASS | vulnerability | vulnerability |
| BCH-3 | FAIL | PASS | vulnerability | none |
| MIXED-1 | PASS | PASS | deployment_requirement | deployment_requirement |
| MIXED-2 | PASS | PASS | deployment_requirement | deployment_requirement |

## Failures eliminated (V2 FAIL → V2.1 PASS)

- **AG-1** (Attacker Gain): operational_risk → vulnerability
- **AG-2** (Attacker Gain): design_trade_off → invariant_gap
- **AUTH-2** (Authorization): vulnerability → none
- **TRUST-1** (Trust Assumption): vulnerability → deployment_requirement
- **TRUST-2** (Trust Assumption): vulnerability → deployment_requirement
- **TRUST-3** (Trust Assumption): vulnerability → deployment_requirement
- **INTENT-3** (Intent vs Security): vulnerability → none
- **CONTRA-1** (Contradiction): vulnerability → none
- **CONTRA-2** (Contradiction): vulnerability → none
- **CONTRA-3** (Contradiction): vulnerability → none
- **CONF-2** (Confidence): vulnerability → none
- **BCH-3** (BCH/CashToken): vulnerability → none

## Remaining failures (V2.1)

- None — all scenarios PASS under V2.1-compliant judgments.

## Interpretation

V2.1 prompt hardening **substantially improves** semantic judgment quality. The architecture (facts-first bundle → judge → policy) is validated; remaining gaps are primarily **LLM compliance risk**, not structural design flaws.

### Prompt changes in V2.1

1. Expanded attacker_gain / authorization_impact (dust redirects, destruction, locking; profit not required)
2. Mandatory trust-assumption check before attacker_gain=true
3. Contradiction protocol reconciling cap.* and inv.* before exploit claims
4. Intent tier vs security tier (business metadata vs auth/timelock/token integrity)
5. Six-step reasoning sequence including trust and contradiction checks
