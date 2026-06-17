# Invariant Classification Refinement Report

**Date:** 2026-06-17  
**Scope:** Security-critical vs business/policy intent invariants only. No sessions, storage, or scoring changes.

---

## 1. Classification changes made

### Mechanism: `InvariantTier`

Added to [`src/services/intent_invariants.py`](../src/services/intent_invariants.py):

- `InvariantTier.SECURITY` — missing control enables unauthorized value movement or threshold bypass
- `InvariantTier.BUSINESS` — policy/workflow rules (amounts, recipients, metadata)

Each missing invariant carries a tier. Emission maps:

| Tier | FindingKind | Severity | ExploitSeverity | Title prefix |
|------|-------------|----------|-----------------|--------------|
| SECURITY | `VULNERABILITY` | HIGH | `direct_fund_loss` | Security Vulnerability |
| BUSINESS | `INVARIANT_GAP` | MEDIUM | `partial_violation` | Policy Gap |

`SanityChecker` violations are classified by message content via `_tier_for_sanity_violation()`:

- **SECURITY:** multisig threshold, timelock, covenant/`activeBytecode`, sum-preservation, output-count
- **BUSINESS:** generic missing-feature evidence (default)

[`finding_policy.py`](../src/services/finding_policy.py) fallback: `intent_auth_gate` and `intent_value_conservation` map to `VULNERABILITY`; other `intent_*` remain `INVARIANT_GAP`.

---

## 2. Security-critical invariants (tier = SECURITY)

| Invariant ID | Rationale |
|--------------|-----------|
| `auth_gate` | Missing `checkSig`/`checkMultiSig` → anyone can trigger payout |
| `value_conservation` | Missing sum-preservation on split → fund diversion |
| Sanity: multisig threshold | 1-of-N when M-of-N required → authorization bypass |
| Sanity: timelock | Missing `tx.time`/`this.age` when delay is security control |
| Sanity: covenant continuation | Missing `activeBytecode` on vault/covenant paths |
| Sanity: split structural guards | Missing output-count or sum-preservation |

## Business/policy invariants (tier = BUSINESS)

| Invariant ID | Rationale |
|--------------|-----------|
| `fixed_amount_per_recipient` | Payroll policy; misuse is mis-payment not unsigned spend |
| `recipient_binding` | Declared destination policy |
| `token_category_preservation` | Token metadata policy on splits |
| Sanity: generic feature evidence | Non-auth workflow features |

---

## 3. Updated validation results

**Matrix:** 22/22 PASS (regenerated [`audit_classification_validation_report.md`](audit_classification_validation_report.md))

| Scenario | Before | After |
|----------|--------|-------|
| Payroll A (missing salary) | INVARIANT_GAP / MEDIUM | **unchanged** |
| Payroll D (no signature) | INVARIANT_GAP / MEDIUM | **VULNERABILITY / HIGH** |
| Multisig A (threshold bypass) | INVARIANT_GAP / MEDIUM | **VULNERABILITY / HIGH** |
| Vault A (timelock absent) | INVARIANT_GAP / MEDIUM | **VULNERABILITY / HIGH** |
| Payroll C (treasury underfunded) | DEPLOYMENT_REQUIREMENT / LOW | **unchanged** |
| Design trade-offs (dust, equality) | DESIGN_TRADE_OFF / INFO | **unchanged** |

**Unit tests:** 37 classification-matrix + intent tests; 86+ audit_engine suite — all passing.

---

## 4. Ambiguous / remaining cases

| Case | Classification | Notes |
|------|----------------|-------|
| `recipient_binding` missing | INVARIANT_GAP / MEDIUM | Could be SECURITY if intent frames destination as auth control; currently business policy |
| `token_category_preservation` missing | INVARIANT_GAP / MEDIUM | Category drift can be exploitable; kept business until tied to detector corroboration |
| Generic sanity feature miss | INVARIANT_GAP / MEDIUM | e.g. "escrow feature evidence" without timelock/multisig keywords |
| `intent_sanity_check` rule_id | Same ID for security and business | Tier resolved at emission from violation text; ambiguous only if message is generic |
| Token payroll fixtures | Incidental `unrestricted_token_transfer` CRITICAL | Separate detector noise; not intent classification |
| Semantic `rule_id` legacy labels | `semantic_major_protocol_flaw` on treasury | Kind/severity correct; label cosmetic (prior report) |

---

## Files changed

- `src/services/intent_invariants.py` — `InvariantTier`, tier maps, `_emit_invariant_issue()`
- `src/services/finding_policy.py` — `INTENT_SECURITY_RULE_IDS` fallback
- `tests/audit_classification_matrix/scenarios.py` — payroll D, multisig A, vault A expectations
- `tests/test_intent_invariants.py` — auth gate HIGH test
- `docs/audit_classification_validation_report.md` — regenerated

**Not pushed or merged.**
