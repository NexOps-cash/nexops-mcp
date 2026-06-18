# Semantic Security Judge V2 — Adversarial Validation Report

Generated: 2026-06-18 05:31 UTC

## Executive summary

| Metric | Count |
|--------|-------|
| Scenarios | 23 |
| V2 handled correctly (PASS) | 11 |
| V2 weakness exposed (FAIL) | 12 |

PASS = guards + policy + deterministic layers produced acceptable outcome against adversarial LLM input.
FAIL = red-team found misclassification, missing telemetry, or confidence abuse.

### Scenario scorecard

| ID | Category | Pass | Expected kind(s) | Actual kind | Confidence | Contradicts |
|----|----------|------|------------------|-------------|------------|-------------|
| AG-1 | Attacker Gain | FAIL | invariant_gap, vulnerability | operational_risk | 0.90 | — |
| AG-2 | Attacker Gain | FAIL | invariant_gap, vulnerability | design_trade_off | 0.90 | — |
| AG-3 | Attacker Gain | PASS | vulnerability | vulnerability | 0.90 | — |
| AUTH-1 | Authorization | PASS | vulnerability | none | — | — |
| AUTH-2 | Authorization | FAIL | deployment_requirement, invariant_gap, observation | vulnerability | 0.50 | cap.has_signature_auth |
| AUTH-3 | Authorization | PASS | vulnerability | vulnerability | 0.90 | — |
| TRUST-1 | Trust Assumption | FAIL | deployment_requirement, operational_risk | vulnerability | 0.90 | — |
| TRUST-2 | Trust Assumption | FAIL | deployment_requirement, invariant_gap | vulnerability | 0.90 | — |
| TRUST-3 | Trust Assumption | FAIL | deployment_requirement, operational_risk | vulnerability | 0.90 | — |
| INTENT-1 | Intent vs Security | PASS | invariant_gap | none | — | — |
| INTENT-2 | Intent vs Security | PASS | vulnerability | none | — | — |
| INTENT-3 | Intent vs Security | FAIL | design_trade_off, invariant_gap, observation | vulnerability | 0.90 | — |
| CONTRA-1 | Contradiction | FAIL | deployment_requirement, invariant_gap, observation | vulnerability | 0.50 | cap.has_signature_auth |
| CONTRA-2 | Contradiction | FAIL | invariant_gap, observation | vulnerability | 0.90 | — |
| CONTRA-3 | Contradiction | FAIL | invariant_gap, observation | vulnerability | 0.90 | — |
| CONF-1 | Confidence | PASS | deployment_requirement, operational_risk | deployment_requirement | 0.60 | — |
| CONF-2 | Confidence | FAIL | invariant_gap, observation | vulnerability | 0.50 | cap.has_signature_auth |
| CONF-3 | Confidence | PASS | invariant_gap, observation, vulnerability | vulnerability | 0.60 | — |
| BCH-1 | BCH/CashToken | PASS | invariant_gap, vulnerability | vulnerability | 0.90 | — |
| BCH-2 | BCH/CashToken | PASS | invariant_gap, vulnerability | vulnerability | 0.90 | — |
| BCH-3 | BCH/CashToken | FAIL | design_trade_off, invariant_gap, observation | vulnerability | 0.90 | — |
| MIXED-1 | Mixed Issues | PASS | deployment_requirement, vulnerability | deployment_requirement | 0.90 | — |
| MIXED-2 | Mixed Issues | PASS | deployment_requirement, invariant_gap, vulnerability | deployment_requirement | 0.90 | — |

## AG-1 — Attacker Gain (**FAIL**)

### 1. Contract intent
Owner-signed payroll; victim output fixed, second output unconstrained.

### 2. Contract behavior
Attacker can redirect remainder (even 1 satoshi) via unconstrained output[1].

### 3. AuditFactBundle (excerpt)
```json
{
  "bundle_version": "1.0",
  "contract": {
    "contract_mode": "split_payment"
  },
  "intent": {
    "raw_text": "Owner-signed payroll; victim output fixed, second output unconstrained.",
    "derived_patterns": [
      "split_payment",
      "recipient_binding"
    ]
  },
  "invariant_matrix": {
    "entries": [
      {
        "invariant_id": "auth_gate",
        "label": "authorization gate (signature)",
        "status": "ENFORCED",
        "tier": "business",
        "detail": "",
        "fact_id": "inv.auth_gate"
      },
      {
        "invariant_id": "recipient_binding",
        "label": "recipient binding",
        "status": "ENFORCED",
        "tier": "business",
        "detail": "",
        "fact_id": "inv.recipient_binding"
      },
      {
        "invariant_id": "value_conservation",
        "label": "value conservation",
        "status": "ENFORCED",
        "tier": "business",
        "detail": "",
        "fact_id": "inv.value_conservation"
      }
    ]
  },
  "capabilities": {
    "by_tier": {
      "Structural": {
        "structurally_valid": true
      },
      "Authorization": {
        "has_signature_auth": true,
        "has_multisig_auth": false,...
```

### 4. Adversarial semantic judgment
```json
{"judge_version": "2.0", "verdict": "finding", "intent_fidelity_score": 5, "intent_fidelity_notes": "", "finding": {"gap_id": "semantic.dust_redirect", "attacker_gain": false, "authorization_impact": false, "value_impact": "none", "trust_assumption": "none", "affected_invariant": "", "deferred_validation": false, "attacker_controlled_inputs": [], "spend_path": {"function": "", "line_hint": 0}, "fact_refs": [], "contradicts_fact_ids": [], "evidence_gaps": [], "uncertainty_reason": "", "reasoning_steps": ["Examined declared intent invariants for this contract pattern.", "Identified attacker-controlled transaction inputs relevant to the spend path.", "Assessed value impact on BCH and token flows.", "Determined whether an attacker gains unauthorized value or authorization."], "summary": "On...
```

### 5. Final classification

| Field | Value |
|-------|-------|
| Expected kind(s) | invariant_gap, vulnerability |
| Actual kind | operational_risk |
| Pass/fail | FAIL |
| Severity | LOW |
| Triggerability | non_attacker |
| Confidence level | firm |
| Confidence score | 0.9 |
| Semantic rule_id | semantic_operational_risk |
| Deterministic findings | none |

### 6. Correctness

**Ground truth:** Small value redirect is still attacker_gain with value_impact low+.

**Classification correct:** No — weakness exposed

**Telemetry**
- contradicts_fact_ids: []
- evidence_gaps: []
- uncertainty_reason: (empty)

**Failures:**
- Kind operational_risk not in ground truth ['invariant_gap', 'vulnerability']
- Forbidden kind operational_risk

## AG-2 — Attacker Gain (**FAIL**)

### 1. Contract intent
Token contract; burning should not destroy others' balances without authorization.

### 2. Contract behavior
Anyone can burn tokens from contract input without auth gate.

### 3. AuditFactBundle (excerpt)
```json
{
  "bundle_version": "1.0",
  "contract": {
    "contract_mode": "generic"
  },
  "intent": {
    "raw_text": "Token contract; burning should not destroy others' balances without authorization.",
    "derived_patterns": []
  },
  "invariant_matrix": {
    "entries": []
  },
  "capabilities": {
    "by_tier": {
      "Structural": {
        "structurally_valid": true
      },
      "Authorization": {
        "has_signature_auth": false,
        "has_multisig_auth": false,
        "requires_signature": false,
        "requires_multisig": false
      },
      "TokenFlow": {
        "preserves_token_category": false,
        "preserves_token_amount": false,
        "preserves_split_token_supply": false,
        "burns_output_tokens": false,
        "token_category_constrained": false,
        "enforces_supply_cap": false
      },
      "Lifecycle": {
        "reanchors_covenant": false,
        "migratory_output": false,
        "terminating_output": false,
        "capability_retained": false,
        "capability_escaped": false
      }
    },
    "evidence": [
      {
        "fact_id": "cap.structurally_valid",
        "key": "structurally_valid",
        "value": true,
        ...
```

### 4. Adversarial semantic judgment
```json
{"judge_version": "2.0", "verdict": "finding", "intent_fidelity_score": 5, "intent_fidelity_notes": "", "finding": {"gap_id": "semantic.token_burn", "attacker_gain": false, "authorization_impact": false, "value_impact": "low", "trust_assumption": "none", "affected_invariant": "", "deferred_validation": false, "attacker_controlled_inputs": [], "spend_path": {"function": "", "line_hint": 0}, "fact_refs": [], "contradicts_fact_ids": [], "evidence_gaps": [], "uncertainty_reason": "", "reasoning_steps": ["Examined declared intent invariants for this contract pattern.", "Identified attacker-controlled transaction inputs relevant to the spend path.", "Assessed value impact on BCH and token flows.", "Determined whether an attacker gains unauthorized value or authorization."], "summary": "Attack...
```

### 5. Final classification

| Field | Value |
|-------|-------|
| Expected kind(s) | invariant_gap, vulnerability |
| Actual kind | design_trade_off |
| Pass/fail | FAIL |
| Severity | INFO |
| Triggerability | non_attacker |
| Confidence level | informational |
| Confidence score | 0.9 |
| Semantic rule_id | semantic_design_trade_off |
| Deterministic findings | token_category_drift, token_amount_inflation, capability_token_continuity_break |

### 6. Correctness

**Ground truth:** Destructive unauthorized action = authorization_impact even without gain.

**Classification correct:** No — weakness exposed

**Telemetry**
- contradicts_fact_ids: []
- evidence_gaps: []
- uncertainty_reason: (empty)

**Failures:**
- Kind design_trade_off not in ground truth ['invariant_gap', 'vulnerability']
- Forbidden kind design_trade_off

## AG-3 — Attacker Gain (PASS)

### 1. Contract intent
Vault accepts deposits but has no spend path.

### 2. Contract behavior
Funds permanently locked; denial-of-access.

### 3. AuditFactBundle (excerpt)
```json
{
  "bundle_version": "1.0",
  "contract": {
    "contract_mode": "generic"
  },
  "intent": {
    "raw_text": "Vault accepts deposits but has no spend path.",
    "derived_patterns": []
  },
  "invariant_matrix": {
    "entries": []
  },
  "capabilities": {
    "by_tier": {
      "Structural": {
        "structurally_valid": true
      },
      "Authorization": {
        "has_signature_auth": false,
        "has_multisig_auth": false,
        "requires_signature": false,
        "requires_multisig": false
      },
      "TokenFlow": {
        "preserves_token_category": false,
        "preserves_token_amount": false,
        "preserves_split_token_supply": false,
        "burns_output_tokens": false,
        "token_category_constrained": false,
        "enforces_supply_cap": false
      },
      "Lifecycle": {
        "reanchors_covenant": false,
        "migratory_output": false,
        "terminating_output": false,
        "capability_retained": false,
        "capability_escaped": false
      }
    },
    "evidence": [
      {
        "fact_id": "cap.structurally_valid",
        "key": "structurally_valid",
        "value": true,
        "tier": "Structural",
        "source...
```

### 4. Adversarial semantic judgment
```json
{"judge_version": "2.0", "verdict": "finding", "intent_fidelity_score": 5, "intent_fidelity_notes": "", "finding": {"gap_id": "semantic.funds_unspendable", "attacker_gain": false, "authorization_impact": false, "value_impact": "none", "trust_assumption": "none", "affected_invariant": "funds_unspendable", "deferred_validation": false, "attacker_controlled_inputs": [], "spend_path": {"function": "", "line_hint": 0}, "fact_refs": [], "contradicts_fact_ids": [], "evidence_gaps": [], "uncertainty_reason": "", "reasoning_steps": ["Examined declared intent invariants for this contract pattern.", "Identified attacker-controlled transaction inputs relevant to the spend path.", "Assessed value impact on BCH and token flows.", "Determined whether an attacker gains unauthorized value or authorizati...
```

### 5. Final classification

| Field | Value |
|-------|-------|
| Expected kind(s) | vulnerability |
| Actual kind | vulnerability |
| Pass/fail | PASS |
| Severity | CRITICAL |
| Triggerability | non_attacker |
| Confidence level | firm |
| Confidence score | 0.9 |
| Semantic rule_id | semantic_vulnerability |
| Deterministic findings | none |

### 6. Correctness

**Ground truth:** Permanent lock is VULNERABILITY via funds_unspendable special case.

**Classification correct:** Yes

**Telemetry**
- contradicts_fact_ids: []
- evidence_gaps: []
- uncertainty_reason: (empty)

## AUTH-1 — Authorization (PASS)

### 1. Contract intent
2-of-3 multisig treasury spend.

### 2. Contract behavior
Only single checkSig; threshold not enforced on-chain.

### 3. AuditFactBundle (excerpt)
```json
{
  "bundle_version": "1.0",
  "contract": {
    "contract_mode": "multisig"
  },
  "intent": {
    "raw_text": "2-of-3 multisig treasury spend.",
    "derived_patterns": [
      "split_payment",
      "multisig"
    ],
    "intent_model": {
      "contract_type": "multisig",
      "features": [
        "multisig"
      ],
      "signers": [
        "alice",
        "bob",
        "carol"
      ],
      "threshold": 2,
      "timeout_days": null,
      "token_id": null,
      "token_class": null,
      "nft_capability": null,
      "expected_category": null,
      "requires_commitment": false,
      "is_genesis": false,
      "purpose": "",
      "ownership_mode": "transferable",
      "lifecycle_mode": "persistent",
      "supply_mode": "fixed",
      "commitment_schema": "opaque"
    }
  },
  "invariant_matrix": {
    "entries": [
      {
        "invariant_id": "auth_gate",
        "label": "authorization gate (signature)",
        "status": "ENFORCED",
        "tier": "business",
        "detail": "",
        "fact_id": "inv.auth_gate"
      },
      {
        "invariant_id": "value_conservation",
        "label": "value conservation",
        "status": "MISSING",
        "t...
```

### 4. Adversarial semantic judgment
```json
{"judge_version": "2.0", "verdict": "no_issue", "intent_fidelity_score": 5, "intent_fidelity_notes": ""}
```

### 5. Final classification

| Field | Value |
|-------|-------|
| Expected kind(s) | vulnerability |
| Actual kind | none |
| Pass/fail | PASS |
| Severity | n/a |
| Triggerability | n/a |
| Confidence level | n/a |
| Confidence score | n/a |
| Semantic rule_id | none |
| Deterministic findings | intent_value_conservation, intent_sanity_check |

### 6. Correctness

**Ground truth:** Deterministic intent_sanity_check must surface multisig bypass.

**Classification correct:** Yes

**Telemetry**
- contradicts_fact_ids: []
- evidence_gaps: []
- uncertainty_reason: (empty)

## AUTH-2 — Authorization (**FAIL**)

### 1. Contract intent
Payroll distributing fixed salary amounts to predetermined employee lockingBytecode destinations. Owner must authorize each payout. Owner must sign all spends.

### 2. Contract behavior
Bundle proves checkSig present; judge hallucinates missing auth.

### 3. AuditFactBundle (excerpt)
```json
{
  "bundle_version": "1.0",
  "contract": {
    "contract_mode": "split_payment"
  },
  "intent": {
    "raw_text": "Payroll distributing fixed salary amounts to predetermined employee lockingBytecode destinations. Owner must authorize each payout. Owner must sign all spends.",
    "derived_patterns": [
      "split_payment",
      "fixed_amount",
      "recipient_binding"
    ]
  },
  "invariant_matrix": {
    "entries": [
      {
        "invariant_id": "auth_gate",
        "label": "authorization gate (signature)",
        "status": "ENFORCED",
        "tier": "business",
        "detail": "",
        "fact_id": "inv.auth_gate"
      },
      {
        "invariant_id": "recipient_binding",
        "label": "recipient binding",
        "status": "ENFORCED",
        "tier": "business",
        "detail": "",
        "fact_id": "inv.recipient_binding"
      },
      {
        "invariant_id": "value_conservation",
        "label": "value conservation",
        "status": "ENFORCED",
        "tier": "business",
        "detail": "",
        "fact_id": "inv.value_conservation"
      },
      {
        "invariant_id": "fixed_amount_per_recipient",
        "label": "fixed amount per re...
```

### 4. Adversarial semantic judgment
```json
{"judge_version": "2.0", "verdict": "finding", "intent_fidelity_score": 5, "intent_fidelity_notes": "", "finding": {"gap_id": "semantic.missing_auth", "attacker_gain": true, "authorization_impact": true, "value_impact": "high", "trust_assumption": "none", "affected_invariant": "", "deferred_validation": false, "attacker_controlled_inputs": ["tx.outputs[1]"], "spend_path": {"function": "", "line_hint": 0}, "fact_refs": ["cap.has_signature_auth"], "contradicts_fact_ids": [], "evidence_gaps": [], "uncertainty_reason": "", "reasoning_steps": ["Examined declared intent invariants for this contract pattern.", "Identified attacker-controlled transaction inputs relevant to the spend path.", "Assessed value impact on BCH and token flows.", "Determined whether an attacker gains unauthorized value...
```

### 5. Final classification

| Field | Value |
|-------|-------|
| Expected kind(s) | deployment_requirement, invariant_gap, observation |
| Actual kind | vulnerability |
| Pass/fail | FAIL |
| Severity | MEDIUM |
| Triggerability | attacker |
| Confidence level | speculative |
| Confidence score | 0.5 |
| Semantic rule_id | semantic_vulnerability |
| Deterministic findings | LNC-003, LNC-003, unrestricted_token_transfer, capability_token_continuity_break, capability_hybrid_migration_mismatch |

### 6. Correctness

**Ground truth:** Hallucinated missing auth should trigger contradicts_fact_ids; must not be VULNERABILITY.

**Classification correct:** No — weakness exposed

**Telemetry**
- contradicts_fact_ids: ['cap.has_signature_auth']
- evidence_gaps: []
- uncertainty_reason: (empty)

**Failures:**
- Kind vulnerability not in ground truth ['deployment_requirement', 'invariant_gap', 'observation']
- Forbidden kind vulnerability

## AUTH-3 — Authorization (PASS)

### 1. Contract intent
Admin path signed; public path must not move value without policy.

### 2. Contract behavior
publicSpend() bypasses signature entirely.

### 3. AuditFactBundle (excerpt)
```json
{
  "bundle_version": "1.0",
  "contract": {
    "contract_mode": "generic"
  },
  "intent": {
    "raw_text": "Admin path signed; public path must not move value without policy.",
    "derived_patterns": []
  },
  "invariant_matrix": {
    "entries": [
      {
        "invariant_id": "auth_gate",
        "label": "authorization gate (signature)",
        "status": "ENFORCED",
        "tier": "business",
        "detail": "",
        "fact_id": "inv.auth_gate"
      }
    ]
  },
  "capabilities": {
    "by_tier": {
      "Structural": {
        "structurally_valid": true
      },
      "Authorization": {
        "has_signature_auth": true,
        "has_multisig_auth": false,
        "requires_signature": true,
        "requires_multisig": false
      },
      "TokenFlow": {
        "preserves_token_category": false,
        "preserves_token_amount": false,
        "preserves_split_token_supply": false,
        "burns_output_tokens": false,
        "token_category_constrained": false,
        "enforces_supply_cap": false
      },
      "Lifecycle": {
        "reanchors_covenant": false,
        "migratory_output": true,
        "terminating_output": false,
        "capability_ret...
```

### 4. Adversarial semantic judgment
```json
{"judge_version": "2.0", "verdict": "finding", "intent_fidelity_score": 5, "intent_fidelity_notes": "", "finding": {"gap_id": "semantic.public_spend_bypass", "attacker_gain": true, "authorization_impact": true, "value_impact": "high", "trust_assumption": "none", "affected_invariant": "", "deferred_validation": false, "attacker_controlled_inputs": ["function selector", "tx.outputs[0].lockingBytecode"], "spend_path": {"function": "", "line_hint": 0}, "fact_refs": [], "contradicts_fact_ids": [], "evidence_gaps": [], "uncertainty_reason": "", "reasoning_steps": ["Examined declared intent invariants for this contract pattern.", "Identified attacker-controlled transaction inputs relevant to the spend path.", "Assessed value impact on BCH and token flows.", "Determined whether an attacker gain...
```

### 5. Final classification

| Field | Value |
|-------|-------|
| Expected kind(s) | vulnerability |
| Actual kind | vulnerability |
| Pass/fail | PASS |
| Severity | HIGH |
| Triggerability | attacker |
| Confidence level | firm |
| Confidence score | 0.9 |
| Semantic rule_id | semantic_vulnerability |
| Deterministic findings | none |

### 6. Correctness

**Ground truth:** Partial authorization failure on alternate path.

**Classification correct:** Yes

**Telemetry**
- contradicts_fact_ids: []
- evidence_gaps: []
- uncertainty_reason: (empty)

## TRUST-1 — Trust Assumption (**FAIL**)

### 1. Contract intent
Payroll distributing fixed salary amounts to predetermined employee lockingBytecode destinations. Owner must authorize each payout. Treasury must be externally pre-funded.

### 2. Contract behavior
Script fails if input underfunded; no attacker extraction path.

### 3. AuditFactBundle (excerpt)
```json
{
  "bundle_version": "1.0",
  "contract": {
    "contract_mode": "split_payment"
  },
  "intent": {
    "raw_text": "Payroll distributing fixed salary amounts to predetermined employee lockingBytecode destinations. Owner must authorize each payout. Treasury must be externally pre-funded.",
    "derived_patterns": [
      "split_payment",
      "fixed_amount",
      "recipient_binding"
    ]
  },
  "invariant_matrix": {
    "entries": [
      {
        "invariant_id": "auth_gate",
        "label": "authorization gate (signature)",
        "status": "ENFORCED",
        "tier": "business",
        "detail": "",
        "fact_id": "inv.auth_gate"
      },
      {
        "invariant_id": "recipient_binding",
        "label": "recipient binding",
        "status": "ENFORCED",
        "tier": "business",
        "detail": "",
        "fact_id": "inv.recipient_binding"
      },
      {
        "invariant_id": "value_conservation",
        "label": "value conservation",
        "status": "ENFORCED",
        "tier": "business",
        "detail": "",
        "fact_id": "inv.value_conservation"
      },
      {
        "invariant_id": "fixed_amount_per_recipient",
        "label": "fixed a...
```

### 4. Adversarial semantic judgment
```json
{"judge_version": "2.0", "verdict": "finding", "intent_fidelity_score": 5, "intent_fidelity_notes": "", "finding": {"gap_id": "semantic.treasury_drain", "attacker_gain": true, "authorization_impact": true, "value_impact": "high", "trust_assumption": "none", "affected_invariant": "", "deferred_validation": false, "attacker_controlled_inputs": ["tx.outputs[1]"], "spend_path": {"function": "", "line_hint": 0}, "fact_refs": [], "contradicts_fact_ids": [], "evidence_gaps": [], "uncertainty_reason": "", "reasoning_steps": ["Examined declared intent invariants for this contract pattern.", "Identified attacker-controlled transaction inputs relevant to the spend path.", "Assessed value impact on BCH and token flows.", "Determined whether an attacker gains unauthorized value or authorization."], ...
```

### 5. Final classification

| Field | Value |
|-------|-------|
| Expected kind(s) | deployment_requirement, operational_risk |
| Actual kind | vulnerability |
| Pass/fail | FAIL |
| Severity | HIGH |
| Triggerability | attacker |
| Confidence level | firm |
| Confidence score | 0.9 |
| Semantic rule_id | semantic_vulnerability |
| Deterministic findings | LNC-003, LNC-003, unrestricted_token_transfer, capability_token_continuity_break, capability_hybrid_migration_mismatch |

### 6. Correctness

**Ground truth:** Treasury liquidity is deploy/ops, not VULNERABILITY.

**Classification correct:** No — weakness exposed

**Telemetry**
- contradicts_fact_ids: []
- evidence_gaps: []
- uncertainty_reason: (empty)

**Failures:**
- Kind vulnerability not in ground truth ['deployment_requirement', 'operational_risk']
- Forbidden kind vulnerability

## TRUST-2 — Trust Assumption (**FAIL**)

### 1. Contract intent
Swap uses honest oracle price feed on input[1].

### 2. Contract behavior
Correct if oracle honest; trust assumption not auth bypass.

### 3. AuditFactBundle (excerpt)
```json
{
  "bundle_version": "1.0",
  "contract": {
    "contract_mode": "generic"
  },
  "intent": {
    "raw_text": "Swap uses honest oracle price feed on input[1].",
    "derived_patterns": []
  },
  "invariant_matrix": {
    "entries": [
      {
        "invariant_id": "auth_gate",
        "label": "authorization gate (signature)",
        "status": "ENFORCED",
        "tier": "business",
        "detail": "",
        "fact_id": "inv.auth_gate"
      }
    ]
  },
  "capabilities": {
    "by_tier": {
      "Structural": {
        "structurally_valid": true
      },
      "Authorization": {
        "has_signature_auth": true,
        "has_multisig_auth": false,
        "requires_signature": true,
        "requires_multisig": false
      },
      "TokenFlow": {
        "preserves_token_category": false,
        "preserves_token_amount": false,
        "preserves_split_token_supply": false,
        "burns_output_tokens": false,
        "token_category_constrained": false,
        "enforces_supply_cap": false
      },
      "Lifecycle": {
        "reanchors_covenant": false,
        "migratory_output": true,
        "terminating_output": false,
        "capability_retained": false,
    ...
```

### 4. Adversarial semantic judgment
```json
{"judge_version": "2.0", "verdict": "finding", "intent_fidelity_score": 5, "intent_fidelity_notes": "", "finding": {"gap_id": "semantic.oracle_manipulation", "attacker_gain": true, "authorization_impact": true, "value_impact": "high", "trust_assumption": "none", "affected_invariant": "", "deferred_validation": false, "attacker_controlled_inputs": ["tx.outputs[1]"], "spend_path": {"function": "", "line_hint": 0}, "fact_refs": [], "contradicts_fact_ids": [], "evidence_gaps": [], "uncertainty_reason": "", "reasoning_steps": ["Examined declared intent invariants for this contract pattern.", "Identified attacker-controlled transaction inputs relevant to the spend path.", "Assessed value impact on BCH and token flows.", "Determined whether an attacker gains unauthorized value or authorization...
```

### 5. Final classification

| Field | Value |
|-------|-------|
| Expected kind(s) | deployment_requirement, invariant_gap |
| Actual kind | vulnerability |
| Pass/fail | FAIL |
| Severity | HIGH |
| Triggerability | attacker |
| Confidence level | firm |
| Confidence score | 0.9 |
| Semantic rule_id | semantic_vulnerability |
| Deterministic findings | none |

### 6. Correctness

**Ground truth:** Oracle reliance should be trust_assumption=oracle, not blind VULNERABILITY unless auth bypass proven.

**Classification correct:** No — weakness exposed

**Telemetry**
- contradicts_fact_ids: []
- evidence_gaps: []
- uncertainty_reason: (empty)

**Failures:**
- Kind vulnerability not in ground truth ['deployment_requirement', 'invariant_gap']
- Forbidden kind vulnerability

## TRUST-3 — Trust Assumption (**FAIL**)

### 1. Contract intent
Operator rotates keys off-chain; on-chain pubkey fixed at deploy.

### 2. Contract behavior
Security depends on off-chain key ceremony.

### 3. AuditFactBundle (excerpt)
```json
{
  "bundle_version": "1.0",
  "contract": {
    "contract_mode": "generic"
  },
  "intent": {
    "raw_text": "Operator rotates keys off-chain; on-chain pubkey fixed at deploy.",
    "derived_patterns": []
  },
  "invariant_matrix": {
    "entries": [
      {
        "invariant_id": "auth_gate",
        "label": "authorization gate (signature)",
        "status": "ENFORCED",
        "tier": "business",
        "detail": "",
        "fact_id": "inv.auth_gate"
      }
    ]
  },
  "capabilities": {
    "by_tier": {
      "Structural": {
        "structurally_valid": true
      },
      "Authorization": {
        "has_signature_auth": true,
        "has_multisig_auth": false,
        "requires_signature": true,
        "requires_multisig": false
      },
      "TokenFlow": {
        "preserves_token_category": false,
        "preserves_token_amount": false,
        "preserves_split_token_supply": false,
        "burns_output_tokens": false,
        "token_category_constrained": false,
        "enforces_supply_cap": false
      },
      "Lifecycle": {
        "reanchors_covenant": false,
        "migratory_output": false,
        "terminating_output": false,
        "capability_ret...
```

### 4. Adversarial semantic judgment
```json
{"judge_version": "2.0", "verdict": "finding", "intent_fidelity_score": 5, "intent_fidelity_notes": "", "finding": {"gap_id": "semantic.key_rotation", "attacker_gain": true, "authorization_impact": true, "value_impact": "medium", "trust_assumption": "none", "affected_invariant": "", "deferred_validation": false, "attacker_controlled_inputs": ["tx.outputs[1]"], "spend_path": {"function": "", "line_hint": 0}, "fact_refs": [], "contradicts_fact_ids": [], "evidence_gaps": [], "uncertainty_reason": "", "reasoning_steps": ["Examined declared intent invariants for this contract pattern.", "Identified attacker-controlled transaction inputs relevant to the spend path.", "Assessed value impact on BCH and token flows.", "Determined whether an attacker gains unauthorized value or authorization."], ...
```

### 5. Final classification

| Field | Value |
|-------|-------|
| Expected kind(s) | deployment_requirement, operational_risk |
| Actual kind | vulnerability |
| Pass/fail | FAIL |
| Severity | HIGH |
| Triggerability | attacker |
| Confidence level | firm |
| Confidence score | 0.9 |
| Semantic rule_id | semantic_vulnerability |
| Deterministic findings | none |

### 6. Correctness

**Ground truth:** Off-chain rotation is deployment/off-chain_state trust, not on-chain exploit.

**Classification correct:** No — weakness exposed

**Telemetry**
- contradicts_fact_ids: []
- evidence_gaps: []
- uncertainty_reason: (empty)

**Failures:**
- Kind vulnerability not in ground truth ['deployment_requirement', 'operational_risk']
- Forbidden kind vulnerability

## INTENT-1 — Intent vs Security (PASS)

### 1. Contract intent
Payroll distributing fixed salary amounts to predetermined employee lockingBytecode destinations. Owner must authorize each payout.

### 2. Contract behavior
Recipients fixed but salary amounts not enforced.

### 3. AuditFactBundle (excerpt)
```json
{
  "bundle_version": "1.0",
  "contract": {
    "contract_mode": "split_payment"
  },
  "intent": {
    "raw_text": "Payroll distributing fixed salary amounts to predetermined employee lockingBytecode destinations. Owner must authorize each payout.",
    "derived_patterns": [
      "split_payment",
      "fixed_amount",
      "recipient_binding"
    ]
  },
  "invariant_matrix": {
    "entries": [
      {
        "invariant_id": "auth_gate",
        "label": "authorization gate (signature)",
        "status": "ENFORCED",
        "tier": "business",
        "detail": "",
        "fact_id": "inv.auth_gate"
      },
      {
        "invariant_id": "recipient_binding",
        "label": "recipient binding",
        "status": "ENFORCED",
        "tier": "business",
        "detail": "",
        "fact_id": "inv.recipient_binding"
      },
      {
        "invariant_id": "value_conservation",
        "label": "value conservation",
        "status": "ENFORCED",
        "tier": "business",
        "detail": "",
        "fact_id": "inv.value_conservation"
      },
      {
        "invariant_id": "fixed_amount_per_recipient",
        "label": "fixed amount per recipient",
        "status": ...
```

### 4. Adversarial semantic judgment
```json
{"judge_version": "2.0", "verdict": "no_issue", "intent_fidelity_score": 5, "intent_fidelity_notes": ""}
```

### 5. Final classification

| Field | Value |
|-------|-------|
| Expected kind(s) | invariant_gap |
| Actual kind | none |
| Pass/fail | PASS |
| Severity | n/a |
| Triggerability | n/a |
| Confidence level | n/a |
| Confidence score | n/a |
| Semantic rule_id | none |
| Deterministic findings | LNC-003, missing_token_amount_validation.cash, unrestricted_token_transfer, intent_fixed_amount_per_recipient |

### 6. Correctness

**Ground truth:** Missing salary is business invariant gap.

**Classification correct:** Yes

**Telemetry**
- contradicts_fact_ids: []
- evidence_gaps: []
- uncertainty_reason: (empty)

## INTENT-2 — Intent vs Security (PASS)

### 1. Contract intent
Vault with timelock-delayed withdrawal.

### 2. Contract behavior
No timelock check on withdraw path.

### 3. AuditFactBundle (excerpt)
```json
{
  "bundle_version": "1.0",
  "contract": {
    "contract_mode": "vault"
  },
  "intent": {
    "raw_text": "Vault with timelock-delayed withdrawal.",
    "derived_patterns": [
      "timelock"
    ],
    "intent_model": {
      "contract_type": "timelock",
      "features": [
        "timelock"
      ],
      "signers": [
        "owner"
      ],
      "threshold": 1,
      "timeout_days": null,
      "token_id": null,
      "token_class": null,
      "nft_capability": null,
      "expected_category": null,
      "requires_commitment": false,
      "is_genesis": false,
      "purpose": "",
      "ownership_mode": "transferable",
      "lifecycle_mode": "persistent",
      "supply_mode": "fixed",
      "commitment_schema": "opaque"
    }
  },
  "invariant_matrix": {
    "entries": [
      {
        "invariant_id": "auth_gate",
        "label": "authorization gate (signature)",
        "status": "ENFORCED",
        "tier": "business",
        "detail": "",
        "fact_id": "inv.auth_gate"
      }
    ]
  },
  "capabilities": {
    "by_tier": {
      "Structural": {
        "structurally_valid": true
      },
      "Authorization": {
        "has_signature_auth": true,
        ...
```

### 4. Adversarial semantic judgment
```json
{"judge_version": "2.0", "verdict": "no_issue", "intent_fidelity_score": 5, "intent_fidelity_notes": ""}
```

### 5. Final classification

| Field | Value |
|-------|-------|
| Expected kind(s) | vulnerability |
| Actual kind | none |
| Pass/fail | PASS |
| Severity | n/a |
| Triggerability | n/a |
| Confidence level | n/a |
| Confidence score | n/a |
| Semantic rule_id | none |
| Deterministic findings | output_binding_missing, intent_sanity_check |

### 6. Correctness

**Ground truth:** Missing timelock is security control.

**Classification correct:** Yes

**Telemetry**
- contradicts_fact_ids: []
- evidence_gaps: []
- uncertainty_reason: (empty)

## INTENT-3 — Intent vs Security (**FAIL**)

### 1. Contract intent
Payroll with fixed salaries and optional employee metadata records for UI.

### 2. Contract behavior
Metadata not stored on-chain; business-only gap.

### 3. AuditFactBundle (excerpt)
```json
{
  "bundle_version": "1.0",
  "contract": {
    "contract_mode": "split_payment"
  },
  "intent": {
    "raw_text": "Payroll with fixed salaries and optional employee metadata records for UI.",
    "derived_patterns": [
      "split_payment",
      "fixed_amount",
      "recipient_binding"
    ]
  },
  "invariant_matrix": {
    "entries": [
      {
        "invariant_id": "auth_gate",
        "label": "authorization gate (signature)",
        "status": "ENFORCED",
        "tier": "business",
        "detail": "",
        "fact_id": "inv.auth_gate"
      },
      {
        "invariant_id": "recipient_binding",
        "label": "recipient binding",
        "status": "ENFORCED",
        "tier": "business",
        "detail": "",
        "fact_id": "inv.recipient_binding"
      },
      {
        "invariant_id": "value_conservation",
        "label": "value conservation",
        "status": "ENFORCED",
        "tier": "business",
        "detail": "",
        "fact_id": "inv.value_conservation"
      },
      {
        "invariant_id": "fixed_amount_per_recipient",
        "label": "fixed amount per recipient",
        "status": "ENFORCED",
        "tier": "business",
        "detail":...
```

### 4. Adversarial semantic judgment
```json
{"judge_version": "2.0", "verdict": "finding", "intent_fidelity_score": 5, "intent_fidelity_notes": "", "finding": {"gap_id": "semantic.metadata_missing", "attacker_gain": true, "authorization_impact": true, "value_impact": "high", "trust_assumption": "none", "affected_invariant": "", "deferred_validation": false, "attacker_controlled_inputs": ["tx.outputs[1]"], "spend_path": {"function": "", "line_hint": 0}, "fact_refs": [], "contradicts_fact_ids": [], "evidence_gaps": [], "uncertainty_reason": "", "reasoning_steps": ["Examined declared intent invariants for this contract pattern.", "Identified attacker-controlled transaction inputs relevant to the spend path.", "Assessed value impact on BCH and token flows.", "Determined whether an attacker gains unauthorized value or authorization."]...
```

### 5. Final classification

| Field | Value |
|-------|-------|
| Expected kind(s) | design_trade_off, invariant_gap, observation |
| Actual kind | vulnerability |
| Pass/fail | FAIL |
| Severity | HIGH |
| Triggerability | attacker |
| Confidence level | firm |
| Confidence score | 0.9 |
| Semantic rule_id | semantic_vulnerability |
| Deterministic findings | LNC-003, LNC-003, unrestricted_token_transfer, capability_token_continuity_break, capability_hybrid_migration_mismatch |

### 6. Correctness

**Ground truth:** Metadata is business/policy; must not escalate to VULNERABILITY.

**Classification correct:** No — weakness exposed

**Telemetry**
- contradicts_fact_ids: []
- evidence_gaps: []
- uncertainty_reason: (empty)

**Failures:**
- Kind vulnerability not in ground truth ['design_trade_off', 'invariant_gap', 'observation']
- Forbidden kind vulnerability

## CONTRA-1 — Contradiction (**FAIL**)

### 1. Contract intent
Payroll distributing fixed salary amounts to predetermined employee lockingBytecode destinations. Owner must authorize each payout. Signed payroll.

### 2. Contract behavior
Bundle proves has_signature_auth; judge denies auth.

### 3. AuditFactBundle (excerpt)
```json
{
  "bundle_version": "1.0",
  "contract": {
    "contract_mode": "split_payment"
  },
  "intent": {
    "raw_text": "Payroll distributing fixed salary amounts to predetermined employee lockingBytecode destinations. Owner must authorize each payout. Signed payroll.",
    "derived_patterns": [
      "split_payment",
      "fixed_amount",
      "recipient_binding"
    ]
  },
  "invariant_matrix": {
    "entries": [
      {
        "invariant_id": "auth_gate",
        "label": "authorization gate (signature)",
        "status": "ENFORCED",
        "tier": "business",
        "detail": "",
        "fact_id": "inv.auth_gate"
      },
      {
        "invariant_id": "recipient_binding",
        "label": "recipient binding",
        "status": "ENFORCED",
        "tier": "business",
        "detail": "",
        "fact_id": "inv.recipient_binding"
      },
      {
        "invariant_id": "value_conservation",
        "label": "value conservation",
        "status": "ENFORCED",
        "tier": "business",
        "detail": "",
        "fact_id": "inv.value_conservation"
      },
      {
        "invariant_id": "fixed_amount_per_recipient",
        "label": "fixed amount per recipient",
  ...
```

### 4. Adversarial semantic judgment
```json
{"judge_version": "2.0", "verdict": "finding", "intent_fidelity_score": 5, "intent_fidelity_notes": "", "finding": {"gap_id": "semantic.auth_missing", "attacker_gain": true, "authorization_impact": true, "value_impact": "high", "trust_assumption": "none", "affected_invariant": "", "deferred_validation": false, "attacker_controlled_inputs": ["tx.outputs[1]"], "spend_path": {"function": "", "line_hint": 0}, "fact_refs": [], "contradicts_fact_ids": [], "evidence_gaps": [], "uncertainty_reason": "", "reasoning_steps": ["Examined declared intent invariants for this contract pattern.", "Identified attacker-controlled transaction inputs relevant to the spend path.", "Assessed value impact on BCH and token flows.", "Determined whether an attacker gains unauthorized value or authorization."], "s...
```

### 5. Final classification

| Field | Value |
|-------|-------|
| Expected kind(s) | deployment_requirement, invariant_gap, observation |
| Actual kind | vulnerability |
| Pass/fail | FAIL |
| Severity | MEDIUM |
| Triggerability | attacker |
| Confidence level | speculative |
| Confidence score | 0.5 |
| Semantic rule_id | semantic_vulnerability |
| Deterministic findings | LNC-003, LNC-003, unrestricted_token_transfer, capability_token_continuity_break, capability_hybrid_migration_mismatch |

### 6. Correctness

**Ground truth:** Must populate contradicts_fact_ids and cap confidence.

**Classification correct:** No — weakness exposed

**Telemetry**
- contradicts_fact_ids: ['cap.has_signature_auth']
- evidence_gaps: []
- uncertainty_reason: (empty)

**Failures:**
- Kind vulnerability not in ground truth ['deployment_requirement', 'invariant_gap', 'observation']
- Forbidden kind vulnerability

## CONTRA-2 — Contradiction (**FAIL**)

### 1. Contract intent
Payroll distributing fixed salary amounts to predetermined employee lockingBytecode destinations. Owner must authorize each payout. Split with value conservation.

### 2. Contract behavior
Bundle shows value conservation enforced; judge claims leak.

### 3. AuditFactBundle (excerpt)
```json
{
  "bundle_version": "1.0",
  "contract": {
    "contract_mode": "split_payment"
  },
  "intent": {
    "raw_text": "Payroll distributing fixed salary amounts to predetermined employee lockingBytecode destinations. Owner must authorize each payout. Split with value conservation.",
    "derived_patterns": [
      "split_payment",
      "fixed_amount",
      "recipient_binding"
    ]
  },
  "invariant_matrix": {
    "entries": [
      {
        "invariant_id": "value_conservation",
        "label": "value conservation",
        "status": "ENFORCED",
        "tier": "security",
        "fact_id": "inv.value_conservation"
      }
    ]
  },
  "capabilities": {
    "by_tier": {
      "Structural": {
        "structurally_valid": true
      },
      "Authorization": {
        "has_signature_auth": true,
        "has_multisig_auth": false,
        "requires_signature": true,
        "requires_multisig": false
      },
      "TokenFlow": {
        "preserves_token_category": false,
        "preserves_token_amount": true,
        "preserves_split_token_supply": true,
        "burns_output_tokens": false,
        "token_category_constrained": false,
        "enforces_supply_cap": false
 ...
```

### 4. Adversarial semantic judgment
```json
{"judge_version": "2.0", "verdict": "finding", "intent_fidelity_score": 5, "intent_fidelity_notes": "", "finding": {"gap_id": "semantic.value_leak", "attacker_gain": true, "authorization_impact": false, "value_impact": "high", "trust_assumption": "none", "affected_invariant": "", "deferred_validation": false, "attacker_controlled_inputs": ["tx.outputs[1]"], "spend_path": {"function": "", "line_hint": 0}, "fact_refs": ["inv.value_conservation"], "contradicts_fact_ids": [], "evidence_gaps": [], "uncertainty_reason": "", "reasoning_steps": ["Examined declared intent invariants for this contract pattern.", "Identified attacker-controlled transaction inputs relevant to the spend path.", "Assessed value impact on BCH and token flows.", "Determined whether an attacker gains unauthorized value ...
```

### 5. Final classification

| Field | Value |
|-------|-------|
| Expected kind(s) | invariant_gap, observation |
| Actual kind | vulnerability |
| Pass/fail | FAIL |
| Severity | HIGH |
| Triggerability | attacker |
| Confidence level | firm |
| Confidence score | 0.9 |
| Semantic rule_id | semantic_vulnerability |
| Deterministic findings | LNC-003, LNC-003, unrestricted_token_transfer, capability_token_continuity_break, capability_hybrid_migration_mismatch |

### 6. Correctness

**Ground truth:** Judge contradicts inv.value_conservation=ENFORCED.

**Classification correct:** No — weakness exposed

**Telemetry**
- contradicts_fact_ids: []
- evidence_gaps: []
- uncertainty_reason: (empty)

**Failures:**
- Kind vulnerability not in ground truth ['invariant_gap', 'observation']
- Forbidden kind vulnerability

## CONTRA-3 — Contradiction (**FAIL**)

### 1. Contract intent
Payroll distributing fixed salary amounts to predetermined employee lockingBytecode destinations. Owner must authorize each payout. Recipient binding enforced.

### 2. Contract behavior
Judge claims recipient redirection despite ENFORCED binding.

### 3. AuditFactBundle (excerpt)
```json
{
  "bundle_version": "1.0",
  "contract": {
    "contract_mode": "split_payment"
  },
  "intent": {
    "raw_text": "Payroll distributing fixed salary amounts to predetermined employee lockingBytecode destinations. Owner must authorize each payout. Recipient binding enforced.",
    "derived_patterns": [
      "split_payment",
      "fixed_amount",
      "recipient_binding"
    ]
  },
  "invariant_matrix": {
    "entries": [
      {
        "invariant_id": "recipient_binding",
        "label": "recipient binding",
        "status": "ENFORCED",
        "tier": "business",
        "fact_id": "inv.recipient_binding"
      }
    ]
  },
  "capabilities": {
    "by_tier": {
      "Structural": {
        "structurally_valid": true
      },
      "Authorization": {
        "has_signature_auth": true,
        "has_multisig_auth": false,
        "requires_signature": true,
        "requires_multisig": false
      },
      "TokenFlow": {
        "preserves_token_category": false,
        "preserves_token_amount": true,
        "preserves_split_token_supply": true,
        "burns_output_tokens": false,
        "token_category_constrained": false,
        "enforces_supply_cap": false
      }...
```

### 4. Adversarial semantic judgment
```json
{"judge_version": "2.0", "verdict": "finding", "intent_fidelity_score": 5, "intent_fidelity_notes": "", "finding": {"gap_id": "semantic.recipient_redirect", "attacker_gain": true, "authorization_impact": true, "value_impact": "medium", "trust_assumption": "none", "affected_invariant": "", "deferred_validation": false, "attacker_controlled_inputs": ["tx.outputs[1]"], "spend_path": {"function": "", "line_hint": 0}, "fact_refs": ["inv.recipient_binding"], "contradicts_fact_ids": [], "evidence_gaps": [], "uncertainty_reason": "", "reasoning_steps": ["Examined declared intent invariants for this contract pattern.", "Identified attacker-controlled transaction inputs relevant to the spend path.", "Assessed value impact on BCH and token flows.", "Determined whether an attacker gains unauthorize...
```

### 5. Final classification

| Field | Value |
|-------|-------|
| Expected kind(s) | invariant_gap, observation |
| Actual kind | vulnerability |
| Pass/fail | FAIL |
| Severity | HIGH |
| Triggerability | attacker |
| Confidence level | firm |
| Confidence score | 0.9 |
| Semantic rule_id | semantic_vulnerability |
| Deterministic findings | LNC-003, LNC-003, unrestricted_token_transfer, capability_token_continuity_break, capability_hybrid_migration_mismatch |

### 6. Correctness

**Ground truth:** Should not classify as VULNERABILITY when binding enforced in bundle.

**Classification correct:** No — weakness exposed

**Telemetry**
- contradicts_fact_ids: []
- evidence_gaps: []
- uncertainty_reason: (empty)

**Failures:**
- Kind vulnerability not in ground truth ['invariant_gap', 'observation']
- Forbidden kind vulnerability

## CONF-1 — Confidence (PASS)

### 1. Contract intent
Generic contract.

### 2. Contract behavior
Judge admits evidence gaps.

### 3. AuditFactBundle (excerpt)
```json
{
  "bundle_version": "1.0",
  "contract": {
    "contract_mode": "generic"
  },
  "intent": {
    "raw_text": "Generic contract.",
    "derived_patterns": []
  },
  "invariant_matrix": {
    "entries": [
      {
        "invariant_id": "auth_gate",
        "label": "authorization gate (signature)",
        "status": "ENFORCED",
        "tier": "business",
        "detail": "",
        "fact_id": "inv.auth_gate"
      }
    ]
  },
  "capabilities": {
    "by_tier": {
      "Structural": {
        "structurally_valid": true
      },
      "Authorization": {
        "has_signature_auth": true,
        "has_multisig_auth": false,
        "requires_signature": true,
        "requires_multisig": false
      },
      "TokenFlow": {
        "preserves_token_category": false,
        "preserves_token_amount": true,
        "preserves_split_token_supply": true,
        "burns_output_tokens": false,
        "token_category_constrained": false,
        "enforces_supply_cap": false
      },
      "Lifecycle": {
        "reanchors_covenant": false,
        "migratory_output": true,
        "terminating_output": false,
        "capability_retained": false,
        "capability_escaped": false
...
```

### 4. Adversarial semantic judgment
```json
{"judge_version": "2.0", "verdict": "finding", "intent_fidelity_score": 5, "intent_fidelity_notes": "", "finding": {"gap_id": "semantic.speculative_gap", "attacker_gain": false, "authorization_impact": false, "value_impact": "none", "trust_assumption": "external_funding", "affected_invariant": "", "deferred_validation": false, "attacker_controlled_inputs": [], "spend_path": {"function": "", "line_hint": 0}, "fact_refs": [], "contradicts_fact_ids": [], "evidence_gaps": ["treasury balance not visible on-chain"], "uncertainty_reason": "requires off-chain assumptions", "reasoning_steps": ["Examined declared intent invariants for this contract pattern.", "Identified attacker-controlled transaction inputs relevant to the spend path.", "Assessed value impact on BCH and token flows.", "Determin...
```

### 5. Final classification

| Field | Value |
|-------|-------|
| Expected kind(s) | deployment_requirement, operational_risk |
| Actual kind | deployment_requirement |
| Pass/fail | PASS |
| Severity | LOW |
| Triggerability | non_attacker |
| Confidence level | likely |
| Confidence score | 0.6 |
| Semantic rule_id | semantic_deployment_requirement |
| Deterministic findings | unrestricted_token_transfer, capability_token_continuity_break, capability_hybrid_migration_mismatch |

### 6. Correctness

**Ground truth:** evidence_gaps must cap confidence at 0.6.

**Classification correct:** Yes

**Telemetry**
- contradicts_fact_ids: []
- evidence_gaps: ['treasury balance not visible on-chain']
- uncertainty_reason: requires off-chain assumptions

## CONF-2 — Confidence (**FAIL**)

### 1. Contract intent
Signed payroll.

### 2. Contract behavior
Judge explicitly contradicts bundle auth fact.

### 3. AuditFactBundle (excerpt)
```json
{
  "bundle_version": "1.0",
  "contract": {
    "contract_mode": "generic"
  },
  "intent": {
    "raw_text": "Signed payroll.",
    "derived_patterns": [
      "split_payment",
      "recipient_binding"
    ]
  },
  "invariant_matrix": {
    "entries": [
      {
        "invariant_id": "auth_gate",
        "label": "authorization gate (signature)",
        "status": "ENFORCED",
        "tier": "business",
        "detail": "",
        "fact_id": "inv.auth_gate"
      },
      {
        "invariant_id": "recipient_binding",
        "label": "recipient binding",
        "status": "ENFORCED",
        "tier": "business",
        "detail": "",
        "fact_id": "inv.recipient_binding"
      },
      {
        "invariant_id": "value_conservation",
        "label": "value conservation",
        "status": "ENFORCED",
        "tier": "business",
        "detail": "",
        "fact_id": "inv.value_conservation"
      }
    ]
  },
  "capabilities": {
    "by_tier": {
      "Structural": {
        "structurally_valid": true
      },
      "Authorization": {
        "has_signature_auth": true,
        "has_multisig_auth": false,
        "requires_signature": true,
        "requires_multisi...
```

### 4. Adversarial semantic judgment
```json
{"judge_version": "2.0", "verdict": "finding", "intent_fidelity_score": 5, "intent_fidelity_notes": "", "finding": {"gap_id": "semantic.contra_auth", "attacker_gain": true, "authorization_impact": true, "value_impact": "high", "trust_assumption": "none", "affected_invariant": "", "deferred_validation": false, "attacker_controlled_inputs": ["tx.outputs[1]"], "spend_path": {"function": "", "line_hint": 0}, "fact_refs": [], "contradicts_fact_ids": ["cap.has_signature_auth"], "evidence_gaps": [], "uncertainty_reason": "", "reasoning_steps": ["Examined declared intent invariants for this contract pattern.", "Identified attacker-controlled transaction inputs relevant to the spend path.", "Assessed value impact on BCH and token flows.", "Determined whether an attacker gains unauthorized value ...
```

### 5. Final classification

| Field | Value |
|-------|-------|
| Expected kind(s) | invariant_gap, observation |
| Actual kind | vulnerability |
| Pass/fail | FAIL |
| Severity | MEDIUM |
| Triggerability | attacker |
| Confidence level | speculative |
| Confidence score | 0.5 |
| Semantic rule_id | semantic_vulnerability |
| Deterministic findings | unrestricted_token_transfer, capability_token_continuity_break, capability_hybrid_migration_mismatch |

### 6. Correctness

**Ground truth:** contradicts_fact_ids must cap confidence at 0.5.

**Classification correct:** No — weakness exposed

**Telemetry**
- contradicts_fact_ids: ['cap.has_signature_auth']
- evidence_gaps: []
- uncertainty_reason: (empty)

**Failures:**
- Kind vulnerability not in ground truth ['invariant_gap', 'observation']
- Forbidden kind vulnerability

## CONF-3 — Confidence (PASS)

### 1. Contract intent
Generic.

### 2. Contract behavior
Speculative reasoning, no fact refs, high confidence.

### 3. AuditFactBundle (excerpt)
```json
{
  "bundle_version": "1.0",
  "contract": {
    "contract_mode": "generic"
  },
  "intent": {
    "raw_text": "Generic.",
    "derived_patterns": []
  },
  "invariant_matrix": {
    "entries": [
      {
        "invariant_id": "auth_gate",
        "label": "authorization gate (signature)",
        "status": "ENFORCED",
        "tier": "business",
        "detail": "",
        "fact_id": "inv.auth_gate"
      }
    ]
  },
  "capabilities": {
    "by_tier": {
      "Structural": {
        "structurally_valid": true
      },
      "Authorization": {
        "has_signature_auth": true,
        "has_multisig_auth": false,
        "requires_signature": true,
        "requires_multisig": false
      },
      "TokenFlow": {
        "preserves_token_category": false,
        "preserves_token_amount": true,
        "preserves_split_token_supply": true,
        "burns_output_tokens": false,
        "token_category_constrained": false,
        "enforces_supply_cap": false
      },
      "Lifecycle": {
        "reanchors_covenant": false,
        "migratory_output": true,
        "terminating_output": false,
        "capability_retained": false,
        "capability_escaped": false
      }
 ...
```

### 4. Adversarial semantic judgment
```json
{"judge_version": "2.0", "verdict": "finding", "intent_fidelity_score": 5, "intent_fidelity_notes": "", "finding": {"gap_id": "semantic.speculation", "attacker_gain": true, "authorization_impact": true, "value_impact": "high", "trust_assumption": "none", "affected_invariant": "", "deferred_validation": false, "attacker_controlled_inputs": ["tx.outputs[1]"], "spend_path": {"function": "", "line_hint": 0}, "fact_refs": [], "contradicts_fact_ids": [], "evidence_gaps": ["no concrete spend path cited"], "uncertainty_reason": "", "reasoning_steps": ["Examined declared intent invariants for this contract pattern.", "Identified attacker-controlled transaction inputs relevant to the spend path.", "Assessed value impact on BCH and token flows.", "Determined whether an attacker gains unauthorized ...
```

### 5. Final classification

| Field | Value |
|-------|-------|
| Expected kind(s) | invariant_gap, observation, vulnerability |
| Actual kind | vulnerability |
| Pass/fail | PASS |
| Severity | HIGH |
| Triggerability | attacker |
| Confidence level | likely |
| Confidence score | 0.6 |
| Semantic rule_id | semantic_vulnerability |
| Deterministic findings | unrestricted_token_transfer, capability_token_continuity_break, capability_hybrid_migration_mismatch |

### 6. Correctness

**Ground truth:** High confidence speculative claim should be capped (uncertainty + contradiction rules).

**Classification correct:** Yes

**Telemetry**
- contradicts_fact_ids: []
- evidence_gaps: ['no concrete spend path cited']
- uncertainty_reason: (empty)

## BCH-1 — BCH/CashToken (PASS)

### 1. Contract intent
Preserve token category on transfer.

### 2. Contract behavior
tokenCategory not checked on output.

### 3. AuditFactBundle (excerpt)
```json
{
  "bundle_version": "1.0",
  "contract": {
    "contract_mode": "ft_transfer"
  },
  "intent": {
    "raw_text": "Preserve token category on transfer.",
    "derived_patterns": []
  },
  "invariant_matrix": {
    "entries": []
  },
  "capabilities": {
    "by_tier": {
      "Structural": {
        "structurally_valid": true
      },
      "Authorization": {
        "has_signature_auth": false,
        "has_multisig_auth": false,
        "requires_signature": false,
        "requires_multisig": false
      },
      "TokenFlow": {
        "preserves_token_category": false,
        "preserves_token_amount": true,
        "preserves_split_token_supply": false,
        "burns_output_tokens": false,
        "token_category_constrained": false,
        "enforces_supply_cap": false
      },
      "Lifecycle": {
        "reanchors_covenant": false,
        "migratory_output": false,
        "terminating_output": false,
        "capability_retained": false,
        "capability_escaped": false
      }
    },
    "evidence": [
      {
        "fact_id": "cap.structurally_valid",
        "key": "structurally_valid",
        "value": true,
        "tier": "Structural",
        "source": "st...
```

### 4. Adversarial semantic judgment
```json
{"judge_version": "2.0", "verdict": "finding", "intent_fidelity_score": 5, "intent_fidelity_notes": "", "finding": {"gap_id": "semantic.category_drift", "attacker_gain": true, "authorization_impact": false, "value_impact": "medium", "trust_assumption": "none", "affected_invariant": "", "deferred_validation": false, "attacker_controlled_inputs": ["tx.outputs[0].tokenCategory"], "spend_path": {"function": "", "line_hint": 0}, "fact_refs": [], "contradicts_fact_ids": [], "evidence_gaps": [], "uncertainty_reason": "", "reasoning_steps": ["Examined declared intent invariants for this contract pattern.", "Identified attacker-controlled transaction inputs relevant to the spend path.", "Assessed value impact on BCH and token flows.", "Determined whether an attacker gains unauthorized value or a...
```

### 5. Final classification

| Field | Value |
|-------|-------|
| Expected kind(s) | invariant_gap, vulnerability |
| Actual kind | vulnerability |
| Pass/fail | PASS |
| Severity | HIGH |
| Triggerability | attacker |
| Confidence level | firm |
| Confidence score | 0.9 |
| Semantic rule_id | semantic_vulnerability |
| Deterministic findings | LNC-003, LNC-003, capability_token_continuity_break |

### 6. Correctness

**Ground truth:** Category preservation missing is security-relevant.

**Classification correct:** Yes

**Telemetry**
- contradicts_fact_ids: []
- evidence_gaps: []
- uncertainty_reason: (empty)

## BCH-2 — BCH/CashToken (PASS)

### 1. Contract intent
NFT commitment must be preserved.

### 2. Contract behavior
nftCommitment not checked.

### 3. AuditFactBundle (excerpt)
```json
{
  "bundle_version": "1.0",
  "contract": {
    "contract_mode": "nft_immutable"
  },
  "intent": {
    "raw_text": "NFT commitment must be preserved.",
    "derived_patterns": []
  },
  "invariant_matrix": {
    "entries": []
  },
  "capabilities": {
    "by_tier": {
      "Structural": {
        "structurally_valid": true
      },
      "Authorization": {
        "has_signature_auth": false,
        "has_multisig_auth": false,
        "requires_signature": false,
        "requires_multisig": false
      },
      "TokenFlow": {
        "preserves_token_category": true,
        "preserves_token_amount": false,
        "preserves_split_token_supply": false,
        "burns_output_tokens": false,
        "token_category_constrained": false,
        "enforces_supply_cap": false
      },
      "Lifecycle": {
        "reanchors_covenant": false,
        "migratory_output": false,
        "terminating_output": false,
        "capability_retained": false,
        "capability_escaped": false
      }
    },
    "evidence": [
      {
        "fact_id": "cap.structurally_valid",
        "key": "structurally_valid",
        "value": true,
        "tier": "Structural",
        "source": "str...
```

### 4. Adversarial semantic judgment
```json
{"judge_version": "2.0", "verdict": "finding", "intent_fidelity_score": 5, "intent_fidelity_notes": "", "finding": {"gap_id": "semantic.nft_commitment", "attacker_gain": true, "authorization_impact": false, "value_impact": "medium", "trust_assumption": "none", "affected_invariant": "", "deferred_validation": false, "attacker_controlled_inputs": ["tx.outputs[0].nftCommitment"], "spend_path": {"function": "", "line_hint": 0}, "fact_refs": [], "contradicts_fact_ids": [], "evidence_gaps": [], "uncertainty_reason": "", "reasoning_steps": ["Examined declared intent invariants for this contract pattern.", "Identified attacker-controlled transaction inputs relevant to the spend path.", "Assessed value impact on BCH and token flows.", "Determined whether an attacker gains unauthorized value or a...
```

### 5. Final classification

| Field | Value |
|-------|-------|
| Expected kind(s) | invariant_gap, vulnerability |
| Actual kind | vulnerability |
| Pass/fail | PASS |
| Severity | HIGH |
| Triggerability | attacker |
| Confidence level | firm |
| Confidence score | 0.9 |
| Semantic rule_id | semantic_vulnerability |
| Deterministic findings | LNC-003, LNC-003 |

### 6. Correctness

**Ground truth:** Commitment break is security issue.

**Classification correct:** Yes

**Telemetry**
- contradicts_fact_ids: []
- evidence_gaps: []
- uncertainty_reason: (empty)

## BCH-3 — BCH/CashToken (**FAIL**)

### 1. Contract intent
Owner may update mutable NFT metadata intentionally.

### 2. Contract behavior
Signed metadata update by design.

### 3. AuditFactBundle (excerpt)
```json
{
  "bundle_version": "1.0",
  "contract": {
    "contract_mode": "nft_mutable"
  },
  "intent": {
    "raw_text": "Owner may update mutable NFT metadata intentionally.",
    "derived_patterns": []
  },
  "invariant_matrix": {
    "entries": [
      {
        "invariant_id": "auth_gate",
        "label": "authorization gate (signature)",
        "status": "ENFORCED",
        "tier": "business",
        "detail": "",
        "fact_id": "inv.auth_gate"
      }
    ]
  },
  "capabilities": {
    "by_tier": {
      "Structural": {
        "structurally_valid": true
      },
      "Authorization": {
        "has_signature_auth": true,
        "has_multisig_auth": false,
        "requires_signature": true,
        "requires_multisig": false
      },
      "TokenFlow": {
        "preserves_token_category": true,
        "preserves_token_amount": false,
        "preserves_split_token_supply": false,
        "burns_output_tokens": false,
        "token_category_constrained": false,
        "enforces_supply_cap": false
      },
      "Lifecycle": {
        "reanchors_covenant": false,
        "migratory_output": false,
        "terminating_output": false,
        "capability_retained": fa...
```

### 4. Adversarial semantic judgment
```json
{"judge_version": "2.0", "verdict": "finding", "intent_fidelity_score": 5, "intent_fidelity_notes": "", "finding": {"gap_id": "semantic.mutable_metadata", "attacker_gain": true, "authorization_impact": true, "value_impact": "high", "trust_assumption": "none", "affected_invariant": "", "deferred_validation": false, "attacker_controlled_inputs": ["tx.outputs[1]"], "spend_path": {"function": "", "line_hint": 0}, "fact_refs": [], "contradicts_fact_ids": [], "evidence_gaps": [], "uncertainty_reason": "", "reasoning_steps": ["Examined declared intent invariants for this contract pattern.", "Identified attacker-controlled transaction inputs relevant to the spend path.", "Assessed value impact on BCH and token flows.", "Determined whether an attacker gains unauthorized value or authorization."]...
```

### 5. Final classification

| Field | Value |
|-------|-------|
| Expected kind(s) | design_trade_off, invariant_gap, observation |
| Actual kind | vulnerability |
| Pass/fail | FAIL |
| Severity | HIGH |
| Triggerability | attacker |
| Confidence level | firm |
| Confidence score | 0.9 |
| Semantic rule_id | semantic_vulnerability |
| Deterministic findings | LNC-003, LNC-003 |

### 6. Correctness

**Ground truth:** Signed mutable metadata is intentional; not VULNERABILITY.

**Classification correct:** No — weakness exposed

**Telemetry**
- contradicts_fact_ids: []
- evidence_gaps: []
- uncertainty_reason: (empty)

**Failures:**
- Kind vulnerability not in ground truth ['design_trade_off', 'invariant_gap', 'observation']
- Forbidden kind vulnerability

## MIXED-1 — Mixed Issues (PASS)

### 1. Contract intent
Payroll with treasury pre-funding and owner authorization.

### 2. Contract behavior
No auth + no change output + treasury assumption.

### 3. AuditFactBundle (excerpt)
```json
{
  "bundle_version": "1.0",
  "contract": {
    "contract_mode": "split_payment"
  },
  "intent": {
    "raw_text": "Payroll with treasury pre-funding and owner authorization.",
    "derived_patterns": [
      "split_payment",
      "recipient_binding"
    ]
  },
  "invariant_matrix": {
    "entries": [
      {
        "invariant_id": "recipient_binding",
        "label": "recipient binding",
        "status": "ENFORCED",
        "tier": "business",
        "detail": "",
        "fact_id": "inv.recipient_binding"
      },
      {
        "invariant_id": "value_conservation",
        "label": "value conservation",
        "status": "ENFORCED",
        "tier": "business",
        "detail": "",
        "fact_id": "inv.value_conservation"
      },
      {
        "invariant_id": "auth_gate",
        "label": "authorization gate (signature)",
        "status": "MISSING",
        "tier": "security",
        "detail": "Intent requires signer but no checkSig/checkMultiSig found.",
        "fact_id": "inv.auth_gate"
      }
    ]
  },
  "capabilities": {
    "by_tier": {
      "Structural": {
        "structurally_valid": true
      },
      "Authorization": {
        "has_signature_aut...
```

### 4. Adversarial semantic judgment
```json
{"judge_version": "2.0", "verdict": "finding", "intent_fidelity_score": 5, "intent_fidelity_notes": "", "finding": {"gap_id": "semantic.treasury_only", "attacker_gain": false, "authorization_impact": false, "value_impact": "none", "trust_assumption": "external_funding", "affected_invariant": "", "deferred_validation": false, "attacker_controlled_inputs": [], "spend_path": {"function": "", "line_hint": 0}, "fact_refs": [], "contradicts_fact_ids": [], "evidence_gaps": [], "uncertainty_reason": "", "reasoning_steps": ["Examined declared intent invariants for this contract pattern.", "Identified attacker-controlled transaction inputs relevant to the spend path.", "Assessed value impact on BCH and token flows.", "Determined whether an attacker gains unauthorized value or authorization."], "s...
```

### 5. Final classification

| Field | Value |
|-------|-------|
| Expected kind(s) | deployment_requirement, vulnerability |
| Actual kind | deployment_requirement |
| Pass/fail | PASS |
| Severity | LOW |
| Triggerability | non_attacker |
| Confidence level | firm |
| Confidence score | 0.9 |
| Semantic rule_id | semantic_minor_design_risk |
| Deterministic findings | intent_auth_gate |

### 6. Correctness

**Ground truth:** Single semantic slot surfaces treasury; auth gap must appear deterministically.

**Classification correct:** Yes

**Telemetry**
- contradicts_fact_ids: []
- evidence_gaps: []
- uncertainty_reason: (empty)

## MIXED-2 — Mixed Issues (PASS)

### 1. Contract intent
2-of-3 multisig payroll with fixed salary per employee; liquidity provider funds UTXO.

### 2. Contract behavior
Single sig + missing salary + deploy assumption.

### 3. AuditFactBundle (excerpt)
```json
{
  "bundle_version": "1.0",
  "contract": {
    "contract_mode": "multisig"
  },
  "intent": {
    "raw_text": "2-of-3 multisig payroll with fixed salary per employee; liquidity provider funds UTXO.",
    "derived_patterns": [
      "split_payment",
      "fixed_amount",
      "recipient_binding",
      "multisig"
    ],
    "intent_model": {
      "contract_type": "multisig",
      "features": [
        "multisig",
        "split"
      ],
      "signers": [
        "alice",
        "bob",
        "carol"
      ],
      "threshold": 2,
      "timeout_days": null,
      "token_id": null,
      "token_class": null,
      "nft_capability": null,
      "expected_category": null,
      "requires_commitment": false,
      "is_genesis": false,
      "purpose": "",
      "ownership_mode": "transferable",
      "lifecycle_mode": "persistent",
      "supply_mode": "fixed",
      "commitment_schema": "opaque"
    }
  },
  "invariant_matrix": {
    "entries": [
      {
        "invariant_id": "auth_gate",
        "label": "authorization gate (signature)",
        "status": "ENFORCED",
        "tier": "business",
        "detail": "",
        "fact_id": "inv.auth_gate"
      },
      {
   ...
```

### 4. Adversarial semantic judgment
```json
{"judge_version": "2.0", "verdict": "finding", "intent_fidelity_score": 5, "intent_fidelity_notes": "", "finding": {"gap_id": "semantic.deploy_liquidity", "attacker_gain": false, "authorization_impact": false, "value_impact": "none", "trust_assumption": "external_funding", "affected_invariant": "", "deferred_validation": false, "attacker_controlled_inputs": [], "spend_path": {"function": "", "line_hint": 0}, "fact_refs": [], "contradicts_fact_ids": [], "evidence_gaps": [], "uncertainty_reason": "", "reasoning_steps": ["Examined declared intent invariants for this contract pattern.", "Identified attacker-controlled transaction inputs relevant to the spend path.", "Assessed value impact on BCH and token flows.", "Determined whether an attacker gains unauthorized value or authorization."],...
```

### 5. Final classification

| Field | Value |
|-------|-------|
| Expected kind(s) | deployment_requirement, invariant_gap, vulnerability |
| Actual kind | deployment_requirement |
| Pass/fail | PASS |
| Severity | LOW |
| Triggerability | non_attacker |
| Confidence level | firm |
| Confidence score | 0.9 |
| Semantic rule_id | semantic_minor_design_risk |
| Deterministic findings | intent_value_conservation, intent_fixed_amount_per_recipient, intent_sanity_check |

### 6. Correctness

**Ground truth:** Semantic picks deploy note; multisig bypass and salary gap must still appear deterministically.

**Classification correct:** Yes

**Telemetry**
- contradicts_fact_ids: []
- evidence_gaps: []
- uncertainty_reason: (empty)

## Findings summary

### 1. False positives found

- AUTH-2: classified as VULNERABILITY despite non-exploit ground truth (confidence=0.5, contradicts=['cap.has_signature_auth'])
- TRUST-1: classified as VULNERABILITY despite non-exploit ground truth (confidence=0.9, contradicts=[])
- TRUST-2: classified as VULNERABILITY despite non-exploit ground truth (confidence=0.9, contradicts=[])
- TRUST-3: classified as VULNERABILITY despite non-exploit ground truth (confidence=0.9, contradicts=[])
- INTENT-3: classified as VULNERABILITY despite non-exploit ground truth (confidence=0.9, contradicts=[])
- CONTRA-1: classified as VULNERABILITY despite non-exploit ground truth (confidence=0.5, contradicts=['cap.has_signature_auth'])
- CONTRA-2: classified as VULNERABILITY despite non-exploit ground truth (confidence=0.9, contradicts=[])
- CONTRA-3: classified as VULNERABILITY despite non-exploit ground truth (confidence=0.9, contradicts=[])
- CONF-2: classified as VULNERABILITY despite non-exploit ground truth (confidence=0.5, contradicts=['cap.has_signature_auth'])
- BCH-3: classified as VULNERABILITY despite non-exploit ground truth (confidence=0.9, contradicts=[])

### 2. False negatives found

- AG-1: downgraded real security issue to operational_risk (adversarial judgment minimized attacker_gain/value_impact)
- AG-2: downgraded real security issue to design_trade_off (adversarial judgment minimized attacker_gain/value_impact)

### 3. Misclassifications

- None

### 4. Confidence inflation cases

- None

### 5. Recommended fixes (no code changes in this pass)

1. **Contradiction → kind downgrade:** When `contradicts_fact_ids` is non-empty after guards, cap confidence *and* suppress VULNERABILITY (map to OBSERVATION or reject finding). AUTH-2, CONTRA-1, CONF-2 all cap confidence but still emit VULNERABILITY.
2. **AG-1 / small-value redirects:** Policy trusts LLM `attacker_gain=false` + `value_impact=none` → OPERATIONAL_RISK. Add policy path: unconstrained output + attacker-controlled destination ⇒ minimum INVARIANT_GAP even for dust.
3. **AG-2 / destructive burns:** Unauthorized burn with `attacker_gain=false` maps to DESIGN_TRADE_OFF. Treat unauthorized destructive capability as authorization_impact regardless of profit.
4. **CONTRA-2 / CONTRA-3:** Extend contradiction guard beyond auth-phrase patterns to ENFORCED `inv.value_conservation` and `inv.recipient_binding` when judge claims leak/redirect.
5. **TRUST-1/2/3:** Treasury/oracle/off-chain operator scenarios still map to VULNERABILITY when adversarial judgment sets `attacker_gain=true` without matching `trust_assumption`. Policy should consult bundle trust signals and intent keywords.
6. **INTENT-3 / BCH-3:** Over-escalation to VULNERABILITY on business metadata and signed mutable NFT paths; bundle `cap.has_signature_auth` + intent tier should gate escalation.
7. **CONF-3:** Uncertainty cap via `evidence_gaps` works (PASS); extend same cap when `fact_refs` empty with high confidence.
8. **MIXED-1/2:** Deterministic layer compensates for single semantic slot (PASS today); document as architectural limit until multi-finding Phase 2.
