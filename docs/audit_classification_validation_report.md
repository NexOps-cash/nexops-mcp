# Audit Classification Validation Report

**Generated:** 2026-06-17 09:00 UTC
**Scenarios:** 22 | **Passed:** 22 | **Failed:** 0

## Summary

All classification matrix scenarios passed. Payroll-style false positives are suppressed; deterministic intent gaps classify as `INVARIANT_GAP` / `PROVEN`.

## Results by suite

| Suite | Pass | Fail | Total |
|-------|------|------|-------|
| CashToken | 2 | 0 | 2 |
| Confidence | 2 | 0 | 2 |
| Design Trade-Off | 2 | 0 | 2 |
| Escrow | 2 | 0 | 2 |
| Multisig | 2 | 0 | 2 |
| Payroll | 4 | 0 | 4 |
| Split Payment | 2 | 0 | 2 |
| Triggerability | 4 | 0 | 4 |
| Vault | 2 | 0 | 2 |

## Scenario detail

### payroll_a — Payroll (PASS)

**Description:** Recipients fixed; salary amounts NOT fixed

**Expected:** rule_id=intent_fixed_amount_per_recipient; kind=invariant_gap; severity=MEDIUM; trigger=attacker; confidence=proven; title_prefix=Policy Gap

| Field | Actual |
|-------|--------|
| rule_id | `intent_fixed_amount_per_recipient` |
| FindingKind | `invariant_gap` |
| Severity | `MEDIUM` |
| Triggerability | `attacker` |
| Confidence | `proven` |
| Provenance | `deterministic` |
| Title | Policy Gap: fixed amount per recipient |

<details><summary>All findings</summary>

- `LNC-003 | observation | INFO | unknown | informational | deterministic | Observation: DSL Structure Warning (LNC-003)`
- `missing_token_amount_validation.cash | vulnerability | HIGH | attacker | proven | deterministic | Security Vulnerability: missing token amount validation`
- `unrestricted_token_transfer | vulnerability | CRITICAL | attacker | proven | deterministic | Security Vulnerability: unrestricted token transfer`
- `intent_fixed_amount_per_recipient | invariant_gap | MEDIUM | attacker | proven | deterministic | Policy Gap: fixed amount per recipient`

</details>

### payroll_b — Payroll (PASS)

**Description:** Recipients fixed; salary amounts fixed

**Expected:** no finding with rule_id=intent_fixed_amount_per_recipient

<details><summary>All findings</summary>

- `LNC-003 | observation | INFO | unknown | informational | deterministic | Observation: DSL Structure Warning (LNC-003)`
- `unrestricted_token_transfer | vulnerability | CRITICAL | attacker | proven | deterministic | Security Vulnerability: unrestricted token transfer`
- `capability_token_continuity_break | observation | INFO | unknown | informational | deterministic | Observation: capability token continuity break`
- `capability_hybrid_migration_mismatch | observation | INFO | unknown | informational | deterministic | Observation: capability hybrid migration mismatch`

</details>

### payroll_c — Payroll (PASS)

**Description:** Correct payroll contract; LLM raises treasury underfunding

**Expected:** kind=deployment_requirement|operational_risk; severity=LOW; trigger=non_attacker; confidence=firm|likely

| Field | Actual |
|-------|--------|
| rule_id | `semantic_major_protocol_flaw` |
| FindingKind | `deployment_requirement` |
| Severity | `LOW` |
| Triggerability | `non_attacker` |
| Confidence | `firm` |
| Provenance | `llm` |
| Title | Deployment Requirement: Treasury may be underfunded relative to payroll obligations |

<details><summary>All findings</summary>

- `LNC-003 | observation | INFO | unknown | informational | deterministic | Observation: DSL Structure Warning (LNC-003)`
- `unrestricted_token_transfer | vulnerability | CRITICAL | attacker | proven | deterministic | Security Vulnerability: unrestricted token transfer`
- `capability_token_continuity_break | observation | INFO | unknown | informational | deterministic | Observation: capability token continuity break`
- `capability_hybrid_migration_mismatch | observation | INFO | unknown | informational | deterministic | Observation: capability hybrid migration mismatch`
- `semantic_major_protocol_flaw | deployment_requirement | LOW | non_attacker | firm | llm | Deployment Requirement: Treasury may be underfunded relative to payroll obligations`

</details>

### payroll_d — Payroll (PASS)

**Description:** Missing admin signature on payout path

**Expected:** rule_id=intent_auth_gate; kind=invariant_gap|vulnerability; trigger=attacker; confidence=proven; title_prefix=Policy Gap|Security Vulnerability

| Field | Actual |
|-------|--------|
| rule_id | `intent_auth_gate` |
| FindingKind | `invariant_gap` |
| Severity | `MEDIUM` |
| Triggerability | `attacker` |
| Confidence | `proven` |
| Provenance | `deterministic` |
| Title | Policy Gap: authorization gate (signature) |

<details><summary>All findings</summary>

- `intent_auth_gate | invariant_gap | MEDIUM | attacker | proven | deterministic | Policy Gap: authorization gate (signature)`

</details>

### escrow_a — Escrow (PASS)

**Description:** Refund path missing (semantic)

**Expected:** rule_id=semantic_moderate_logic_risk; kind=invariant_gap|vulnerability; trigger=attacker|unknown

| Field | Actual |
|-------|--------|
| rule_id | `semantic_moderate_logic_risk` |
| FindingKind | `vulnerability` |
| Severity | `HIGH` |
| Triggerability | `unknown` |
| Confidence | `firm` |
| Provenance | `llm` |
| Title | Security Vulnerability: Refund path missing; sender cannot recover funds after timeout |

<details><summary>All findings</summary>

- `LNC-003 | observation | INFO | unknown | informational | deterministic | Observation: DSL Structure Warning (LNC-003)`
- `semantic_moderate_logic_risk | vulnerability | HIGH | unknown | firm | llm | Security Vulnerability: Refund path missing; sender cannot recover funds after timeout`

</details>

### escrow_b — Escrow (PASS)

**Description:** Refund exists but relies on external funding assumption

**Expected:** rule_id=semantic_minor_design_risk; kind=deployment_requirement; severity=LOW; trigger=non_attacker

| Field | Actual |
|-------|--------|
| rule_id | `semantic_minor_design_risk` |
| FindingKind | `deployment_requirement` |
| Severity | `LOW` |
| Triggerability | `non_attacker` |
| Confidence | `firm` |
| Provenance | `llm` |
| Title | Deployment Requirement: Safety relies on external treasury pre-funding the escrow UTXO off-chain |

<details><summary>All findings</summary>

- `LNC-003 | observation | INFO | unknown | informational | deterministic | Observation: DSL Structure Warning (LNC-003)`
- `semantic_minor_design_risk | deployment_requirement | LOW | non_attacker | firm | llm | Deployment Requirement: Safety relies on external treasury pre-funding the escrow UTXO off-chain`

</details>

### multisig_a — Multisig (PASS)

**Description:** Threshold bypass — single signature on 2-of-3 intent

**Expected:** rule_id=intent_sanity_check; kind=invariant_gap|vulnerability; trigger=attacker|unknown; confidence=proven

| Field | Actual |
|-------|--------|
| rule_id | `intent_sanity_check` |
| FindingKind | `invariant_gap` |
| Severity | `MEDIUM` |
| Triggerability | `attacker` |
| Confidence | `proven` |
| Provenance | `deterministic` |
| Title | Policy Gap: intent sanity check |

<details><summary>All findings</summary>

- `intent_value_conservation | invariant_gap | MEDIUM | attacker | proven | deterministic | Policy Gap: value conservation`
- `intent_sanity_check | invariant_gap | MEDIUM | attacker | proven | deterministic | Policy Gap: intent sanity check`

</details>

### multisig_b — Multisig (PASS)

**Description:** Threshold enforced — dual checkSig

**Expected:** no finding with rule_id=intent_sanity_check

<details><summary>All findings</summary>

- `intent_value_conservation | invariant_gap | MEDIUM | attacker | proven | deterministic | Policy Gap: value conservation`

</details>

### vault_a — Vault (PASS)

**Description:** Missing timelock on delayed withdrawal intent

**Expected:** rule_id=intent_sanity_check; kind=invariant_gap; confidence=proven

| Field | Actual |
|-------|--------|
| rule_id | `intent_sanity_check` |
| FindingKind | `invariant_gap` |
| Severity | `MEDIUM` |
| Triggerability | `attacker` |
| Confidence | `proven` |
| Provenance | `deterministic` |
| Title | Policy Gap: intent sanity check |

<details><summary>All findings</summary>

- `output_binding_missing | invariant_gap | MEDIUM | attacker | proven | deterministic | Policy Gap: output binding missing`
- `intent_sanity_check | invariant_gap | MEDIUM | attacker | proven | deterministic | Policy Gap: intent sanity check`

</details>

### vault_b — Vault (PASS)

**Description:** Timelock enforced

**Expected:** no finding with rule_id=intent_sanity_check

<details><summary>All findings</summary>

- `output_binding_missing | invariant_gap | MEDIUM | attacker | proven | deterministic | Policy Gap: output binding missing`

</details>

### split_a — Split Payment (PASS)

**Description:** Recipient binding only; fixed amounts missing

**Expected:** rule_id=intent_fixed_amount_per_recipient; kind=invariant_gap; severity=MEDIUM; trigger=attacker; confidence=proven; title_prefix=Policy Gap

| Field | Actual |
|-------|--------|
| rule_id | `intent_fixed_amount_per_recipient` |
| FindingKind | `invariant_gap` |
| Severity | `MEDIUM` |
| Triggerability | `attacker` |
| Confidence | `proven` |
| Provenance | `deterministic` |
| Title | Policy Gap: fixed amount per recipient |

<details><summary>All findings</summary>

- `intent_fixed_amount_per_recipient | invariant_gap | MEDIUM | attacker | proven | deterministic | Policy Gap: fixed amount per recipient`

</details>

### split_b — Split Payment (PASS)

**Description:** Recipient and amount binding present

**Expected:** no finding with rule_id=intent_fixed_amount_per_recipient

### token_a — CashToken (PASS)

**Description:** Unauthorized mint path (no auth category check)

**Expected:** rule_id=unbounded_mint; kind=vulnerability; trigger=attacker; title_prefix=Security Vulnerability

| Field | Actual |
|-------|--------|
| rule_id | `unbounded_mint` |
| FindingKind | `vulnerability` |
| Severity | `CRITICAL` |
| Triggerability | `attacker` |
| Confidence | `proven` |
| Provenance | `deterministic` |
| Title | Security Vulnerability: unbounded mint |

<details><summary>All findings</summary>

- `unbounded_mint | vulnerability | CRITICAL | attacker | proven | deterministic | Security Vulnerability: unbounded mint`

</details>

### token_b — CashToken (PASS)

**Description:** Supply cap not enforced on-chain (semantic)

**Expected:** rule_id=semantic_moderate_logic_risk; kind=invariant_gap|vulnerability; trigger=attacker|unknown

| Field | Actual |
|-------|--------|
| rule_id | `semantic_moderate_logic_risk` |
| FindingKind | `vulnerability` |
| Severity | `HIGH` |
| Triggerability | `unknown` |
| Confidence | `firm` |
| Provenance | `llm` |
| Title | Security Vulnerability: Mint path does not enforce maxSupply cap on-chain |

<details><summary>All findings</summary>

- `unbounded_mint | vulnerability | CRITICAL | attacker | proven | deterministic | Security Vulnerability: unbounded mint`
- `semantic_moderate_logic_risk | vulnerability | HIGH | unknown | firm | llm | Security Vulnerability: Mint path does not enforce maxSupply cap on-chain`

</details>

### design_exact_equality — Design Trade-Off (PASS)

**Description:** Exact equality constraint (semantic)

**Expected:** rule_id=semantic_moderate_logic_risk; kind=design_trade_off; severity=INFO; trigger=non_attacker; title_prefix=Design Trade-off

| Field | Actual |
|-------|--------|
| rule_id | `semantic_moderate_logic_risk` |
| FindingKind | `design_trade_off` |
| Severity | `INFO` |
| Triggerability | `non_attacker` |
| Confidence | `informational` |
| Provenance | `llm` |
| Title | Design Trade-off: Exact equality constraints on output amounts may cause operational failure if fe |

<details><summary>All findings</summary>

- `LNC-003 | observation | INFO | unknown | informational | deterministic | Observation: DSL Structure Warning (LNC-003)`
- `unrestricted_token_transfer | vulnerability | CRITICAL | attacker | proven | deterministic | Security Vulnerability: unrestricted token transfer`
- `capability_token_continuity_break | observation | INFO | unknown | informational | deterministic | Observation: capability token continuity break`
- `capability_hybrid_migration_mismatch | observation | INFO | unknown | informational | deterministic | Observation: capability hybrid migration mismatch`
- `semantic_moderate_logic_risk | design_trade_off | INFO | non_attacker | informational | llm | Design Trade-off: Exact equality constraints on output amounts may cause operational failure if fe`

</details>

### design_no_change — Design Trade-Off (PASS)

**Description:** No change output support (semantic)

**Expected:** rule_id=semantic_moderate_logic_risk; kind=design_trade_off; severity=INFO; trigger=non_attacker

| Field | Actual |
|-------|--------|
| rule_id | `semantic_moderate_logic_risk` |
| FindingKind | `design_trade_off` |
| Severity | `INFO` |
| Triggerability | `non_attacker` |
| Confidence | `informational` |
| Provenance | `llm` |
| Title | Design Trade-off: Contract does not handle change outputs or dust change |

<details><summary>All findings</summary>

- `LNC-003 | observation | INFO | unknown | informational | deterministic | Observation: DSL Structure Warning (LNC-003)`
- `unrestricted_token_transfer | vulnerability | CRITICAL | attacker | proven | deterministic | Security Vulnerability: unrestricted token transfer`
- `capability_token_continuity_break | observation | INFO | unknown | informational | deterministic | Observation: capability token continuity break`
- `capability_hybrid_migration_mismatch | observation | INFO | unknown | informational | deterministic | Observation: capability hybrid migration mismatch`
- `semantic_moderate_logic_risk | design_trade_off | INFO | non_attacker | informational | llm | Design Trade-off: Contract does not handle change outputs or dust change`

</details>

### confidence_deterministic — Confidence (PASS)

**Description:** Deterministic intent finding is PROVEN

**Expected:** rule_id=intent_fixed_amount_per_recipient; confidence=proven

| Field | Actual |
|-------|--------|
| rule_id | `intent_fixed_amount_per_recipient` |
| FindingKind | `invariant_gap` |
| Severity | `MEDIUM` |
| Triggerability | `attacker` |
| Confidence | `proven` |
| Provenance | `deterministic` |
| Title | Policy Gap: fixed amount per recipient |

<details><summary>All findings</summary>

- `LNC-003 | observation | INFO | unknown | informational | deterministic | Observation: DSL Structure Warning (LNC-003)`
- `missing_token_amount_validation.cash | vulnerability | HIGH | attacker | proven | deterministic | Security Vulnerability: missing token amount validation`
- `unrestricted_token_transfer | vulnerability | CRITICAL | attacker | proven | deterministic | Security Vulnerability: unrestricted token transfer`
- `intent_fixed_amount_per_recipient | invariant_gap | MEDIUM | attacker | proven | deterministic | Policy Gap: fixed amount per recipient`

</details>

### confidence_llm_only — Confidence (PASS)

**Description:** LLM-only finding is never PROVEN

**Expected:** rule_id=semantic_moderate_logic_risk

| Field | Actual |
|-------|--------|
| rule_id | `semantic_moderate_logic_risk` |
| FindingKind | `vulnerability` |
| Severity | `HIGH` |
| Triggerability | `unknown` |
| Confidence | `likely` |
| Provenance | `llm` |
| Title | Security Vulnerability: Edge case in payout ordering may confuse operators |

<details><summary>All findings</summary>

- `LNC-003 | observation | INFO | unknown | informational | deterministic | Observation: DSL Structure Warning (LNC-003)`
- `unrestricted_token_transfer | vulnerability | CRITICAL | attacker | proven | deterministic | Security Vulnerability: unrestricted token transfer`
- `capability_token_continuity_break | observation | INFO | unknown | informational | deterministic | Observation: capability token continuity break`
- `capability_hybrid_migration_mismatch | observation | INFO | unknown | informational | deterministic | Observation: capability hybrid migration mismatch`
- `semantic_moderate_logic_risk | vulnerability | HIGH | unknown | likely | llm | Security Vulnerability: Edge case in payout ordering may confuse operators`

</details>

### trigger_attacker_payout — Triggerability (PASS)

**Description:** Unrestricted payout path

**Expected:** rule_id=intent_auth_gate; kind=invariant_gap|vulnerability; trigger=attacker

| Field | Actual |
|-------|--------|
| rule_id | `intent_auth_gate` |
| FindingKind | `invariant_gap` |
| Severity | `MEDIUM` |
| Triggerability | `attacker` |
| Confidence | `proven` |
| Provenance | `deterministic` |
| Title | Policy Gap: authorization gate (signature) |

<details><summary>All findings</summary>

- `intent_auth_gate | invariant_gap | MEDIUM | attacker | proven | deterministic | Policy Gap: authorization gate (signature)`

</details>

### trigger_non_attacker_treasury — Triggerability (PASS)

**Description:** Treasury underfunding narrative

**Expected:** trigger=non_attacker; max_severity=LOW

| Field | Actual |
|-------|--------|
| rule_id | `semantic_major_protocol_flaw` |
| FindingKind | `deployment_requirement` |
| Severity | `LOW` |
| Triggerability | `non_attacker` |
| Confidence | `firm` |
| Provenance | `llm` |
| Title | Deployment Requirement: Treasury may be underfunded; insufficient funds could block payroll |

<details><summary>All findings</summary>

- `LNC-003 | observation | INFO | unknown | informational | deterministic | Observation: DSL Structure Warning (LNC-003)`
- `unrestricted_token_transfer | vulnerability | CRITICAL | attacker | proven | deterministic | Security Vulnerability: unrestricted token transfer`
- `capability_token_continuity_break | observation | INFO | unknown | informational | deterministic | Observation: capability token continuity break`
- `capability_hybrid_migration_mismatch | observation | INFO | unknown | informational | deterministic | Observation: capability hybrid migration mismatch`
- `semantic_major_protocol_flaw | deployment_requirement | LOW | non_attacker | firm | llm | Deployment Requirement: Treasury may be underfunded; insufficient funds could block payroll`

</details>

### trigger_non_attacker_dust — Triggerability (PASS)

**Description:** Dust and fee assumptions

**Expected:** kind=design_trade_off|operational_risk; trigger=non_attacker; max_severity=INFO

| Field | Actual |
|-------|--------|
| rule_id | `semantic_moderate_logic_risk` |
| FindingKind | `design_trade_off` |
| Severity | `INFO` |
| Triggerability | `non_attacker` |
| Confidence | `informational` |
| Provenance | `llm` |
| Title | Design Trade-off: Fee assumptions and dust outputs are not handled; honest spends may fail |

<details><summary>All findings</summary>

- `LNC-003 | observation | INFO | unknown | informational | deterministic | Observation: DSL Structure Warning (LNC-003)`
- `unrestricted_token_transfer | vulnerability | CRITICAL | attacker | proven | deterministic | Security Vulnerability: unrestricted token transfer`
- `capability_token_continuity_break | observation | INFO | unknown | informational | deterministic | Observation: capability token continuity break`
- `capability_hybrid_migration_mismatch | observation | INFO | unknown | informational | deterministic | Observation: capability hybrid migration mismatch`
- `semantic_moderate_logic_risk | design_trade_off | INFO | non_attacker | informational | llm | Design Trade-off: Fee assumptions and dust outputs are not handled; honest spends may fail`

</details>

### trigger_unknown_capped — Triggerability (PASS)

**Description:** Ambiguous edge case must not exceed MEDIUM

**Expected:** trigger=attacker|unknown; max_severity=MEDIUM

| Field | Actual |
|-------|--------|
| rule_id | `semantic_moderate_logic_risk` |
| FindingKind | `vulnerability` |
| Severity | `MEDIUM` |
| Triggerability | `unknown` |
| Confidence | `speculative` |
| Provenance | `llm` |
| Title | Security Vulnerability: Output ordering edge case under rare transaction layouts |

<details><summary>All findings</summary>

- `LNC-003 | observation | INFO | unknown | informational | deterministic | Observation: DSL Structure Warning (LNC-003)`
- `unrestricted_token_transfer | vulnerability | CRITICAL | attacker | proven | deterministic | Security Vulnerability: unrestricted token transfer`
- `capability_token_continuity_break | observation | INFO | unknown | informational | deterministic | Observation: capability token continuity break`
- `capability_hybrid_migration_mismatch | observation | INFO | unknown | informational | deterministic | Observation: capability hybrid migration mismatch`
- `semantic_moderate_logic_risk | vulnerability | MEDIUM | unknown | speculative | llm | Security Vulnerability: Output ordering edge case under rare transaction layouts`

</details>

## Remaining false positives / severity inflation

No matrix failures detected. Known limitations (outside this matrix):
- `UNKNOWN` triggerability on deterministic paths may still default permissive in `is_exploitable()`
- Intent fixed-amount detection is text-heuristic; proportional splits without literal amounts are not flagged
- Semantic `rule_id` may retain legacy `semantic_major_protocol_flaw` label while kind/severity are policy-correct
- Token-based payroll fixtures may emit incidental `unrestricted_token_transfer` (CRITICAL) from deterministic detectors; primary scenario assertions still pass but real audits should use cleaner fixtures or mode profiles

## Forbidden classification checks

Matrix enforces, per scenario:
- Forbidden `FindingKind` (e.g. `VULNERABILITY` on treasury underfunding)
- Forbidden severities (`CRITICAL` / `HIGH` on non-attacker findings)
- Forbidden title substrings (`Security`, `Major Protocol Flaw`)
- `PROVEN` confidence only on deterministic findings
- `max_severity` cap for `UNKNOWN` / non-attacker cases

---

*Generated by `scripts/generate_audit_classification_report.py` from 22 scenarios.*