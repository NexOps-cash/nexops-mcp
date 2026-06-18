# NexOps False Positive Playbook

**Workstream:** E  
**Purpose:** Institutional memory preventing repeated audit classification mistakes.  
**Feeds:** Benchmark negative expectations (A), adversarial traps (B), replay corpus (I).

---

## How to Use

Each entry documents a **symptom → root cause → correct classification → prevention** chain. When authoring benchmarks, any scenario matching a symptom must assert the **correct classification**, not merely "no finding."

---

## Category 1: Severity Inflation

### FP-001: Treasury Prefunding as Critical Exploit

**Symptoms:** CRITICAL/HIGH `VULNERABILITY`; title like "Major Protocol Flaw"; treasury underfunding narrative.

**Root cause:** Semantic judge treats off-chain deployment assumption (`treasury must be pre-funded`) as on-chain exploitable flaw. Policy lacked `trust_assumption` check before V2.1.

**Correct classification:** `DEPLOYMENT_REQUIREMENT` or `OPERATIONAL_RISK` / LOW / `NON_ATTACKER`

**Distinguishing signals:** Bundle shows `inv.treasury_prefunding: NOT_ENFORCEABLE_ONCHAIN`; no `attacker_gain` without external trust failure.

**Example contracts:** Classification `payroll_c`, `trigger_non_attacker_treasury`; adversarial TRUST-1

**Prevention:** Benchmark `bench_payroll_003` — expect zero vulnerability findings; replay `replay_payroll_treasury_001`

---

### FP-002: Attacker Gain on Dust Redirect Without Material Impact

**Symptoms:** `VULNERABILITY` for 1-satoshi or dust output redirection; `operational_risk` before policy fix.

**Root cause:** Judge flags any unconstrained output as attacker gain without assessing material value impact.

**Correct classification:** `VULNERABILITY` only if remainder/dust is materially stealable OR intent binds all outputs; else `INVARIANT_GAP` or no finding.

**Distinguishing signals:** `value_impact: negligible`; victim output fully bound; conservation holds.

**Example contracts:** Adversarial AG-1 (`ONE_SATOSHI_REDIRECT`)

**Prevention:** Adversarial AG-1; benchmark with partial output binding

---

### FP-003: Destruction/Locking Without Attacker Gain

**Symptoms:** `VULNERABILITY` on `require(false)` deposit-only or burn-to-zero paths.

**Root cause:** Judge equates fund destruction with attacker benefit.

**Correct classification:** No finding OR `DESIGN_TRADE_OFF` / INFO if intent-allowed burn

**Distinguishing signals:** No alternate spend path; `attacker_gain: false`; `authorization_impact: false`

**Example contracts:** Adversarial AG-2 (`PERMANENT_LOCK`), AG-3 (`TOKEN_BURN_NO_GAIN`)

**Prevention:** Adversarial AG-2, AG-3

---

## Category 2: Exploit Hallucination

### FP-004: Hallucinated Missing Auth

**Symptoms:** `VULNERABILITY` claiming missing `checkSig` when bundle proves `cap.has_checksig: true` and `inv.auth_gate: ENFORCED`.

**Root cause:** LLM ignores bundle facts; no `contradicts_fact_ids` emitted.

**Correct classification:** No finding; judgment suppressed or logged as contradiction

**Distinguishing signals:** `contradicts_fact_ids` includes `cap.has_checksig`, `inv.auth_gate`

**Example contracts:** Adversarial AUTH-2; classification payroll with signed distribute

**Prevention:** Adversarial AUTH-2, CONTRA-1; replay `replay_auth_hallucination_001`

---

### FP-005: Duplicate Invariant Re-discovery

**Symptoms:** Semantic finding repeats deterministic `intent_*` issue already in `existing_findings`.

**Root cause:** Judge not scoped to delta-only; duplicate prefix not enforced.

**Correct classification:** Suppressed by `apply_judgment_guards()` dedup

**Distinguishing signals:** `existing_findings` contains matching `intent.fixed_amount_per_recipient`

**Example contracts:** Payroll D after salary fix (audit enhancement report)

**Prevention:** Bundle `judge_instructions.scope: delta_only`

---

### FP-006: Fabricated Oracle Exploit

**Symptoms:** CRITICAL finding on oracle contract where oracle input IS bound to `oracleLock`.

**Root cause:** Judge over-reads intent fear without tracing `tx.inputs[N].lockingBytecode` requires.

**Correct classification:** No finding OR `OPERATIONAL_RISK` for off-chain staleness only

**Example contracts:** Adversarial BCH-3

**Prevention:** Benchmark `bench_oracle_*` secure baselines

---

## Category 3: Trust-Assumption Confusion

### FP-007: Off-Chain Key Rotation as On-Chain Vuln

**Symptoms:** `VULNERABILITY` because "operator may rotate keys off-chain."

**Root cause:** Off-chain governance modeled as exploitable protocol flaw.

**Correct classification:** `DEPLOYMENT_REQUIREMENT` / LOW / `NON_ATTACKER`

**Distinguishing signals:** `trust_assumption: true`; on-chain `checkSig(operator)` enforced

**Example contracts:** Adversarial TRUST-2 (`OFFCHAIN_KEY_ROTATION`)

**Prevention:** Adversarial TRUST-2; V2.1 mandatory trust check

---

### FP-008: External Liquidity Provider Assumption

**Symptoms:** Exploit finding when intent declares LP/treasury funds UTXO externally.

**Root cause:** Confusion between "who funds" (deployment) vs "who can steal" (auth bypass).

**Correct classification:** `DEPLOYMENT_REQUIREMENT` / LOW

**Example contracts:** Adversarial TRUST-3, MIXED-2; classification `escrow_b`

**Prevention:** Classification escrow_b; replay `replay_treasury_lp_001`

---

### FP-009: Oracle Price Trust Boundary

**Symptoms:** `VULNERABILITY` for "oracle may report wrong price."

**Root cause:** Off-chain oracle honesty is trust assumption, not covenant bug.

**Correct classification:** `DEPLOYMENT_REQUIREMENT` / LOW / `NON_ATTACKER`

**Example contracts:** Adversarial TRUST-1 (`ORACLE_PRICE`)

**Prevention:** Adversarial TRUST-1; BCH-2 partial binding cases

---

## Category 4: Metadata / Intent Confusion

### FP-010: Business Metadata as Security Flaw

**Symptoms:** `VULNERABILITY` for optional employee metadata, UI fields, or non-enforceable records.

**Root cause:** Intent tier (business) conflated with security tier (auth/timelock/token integrity).

**Correct classification:** No finding

**Example contracts:** Adversarial INTENT-3

**Prevention:** Adversarial INTENT-3; judge prompt intent-tier rule

---

### FP-011: Exact Equality Rigidity as Exploit

**Symptoms:** HIGH finding on `==` vs `>=` design choice for amounts.

**Root cause:** Design trade-off classified as logic flaw.

**Correct classification:** `DESIGN_TRADE_OFF` / INFO / `NON_ATTACKER`

**Example contracts:** Classification `design_exact_equality`

**Prevention:** Classification matrix design suite

---

### FP-012: No-Change Output as Vulnerability

**Symptoms:** Security finding when contract intentionally requires identical output structure.

**Root cause:** State preservation mistaken for missing payout path.

**Correct classification:** `DESIGN_TRADE_OFF` / INFO

**Example contracts:** Classification `design_no_change`

**Prevention:** Classification design_no_change

---

## Category 5: Deployment Confusion

### FP-013: Compile/Toolchain as Security Finding

**Symptoms:** CRITICAL audit finding for `cashc` syntax errors.

**Root cause:** Pre-policy mapping treated compile failure as vulnerability.

**Correct classification:** `OPERATIONAL_RISK` with severity cap; blocks deployment, not attacker path

**Example contracts:** Any non-compiling input

**Prevention:** `finding_policy.RULE_SEVERITY_CAP_OVERRIDES`

---

### FP-014: External Escrow Funding Note

**Symptoms:** Finding that buyer must fund escrow UTXO (operational setup).

**Root cause:** UTXO funding model vs contract logic conflated.

**Correct classification:** `DEPLOYMENT_REQUIREMENT` or `OPERATIONAL_RISK` / LOW

**Example contracts:** Classification `escrow_b`

**Prevention:** Classification escrow_b

---

## Category 6: Detector Noise

### FP-015: Unrestricted Token Transfer on Secure Payroll

**Symptoms:** CRITICAL `unrestricted_token_transfer` on payroll that correctly binds recipients and categories.

**Root cause:** Detector fires on any external output without intent-aware gating.

**Correct classification:** Suppress or downgrade to observation when intent is split/payroll with binding

**Example contracts:** Token payroll fixtures (invariant refinement report)

**Prevention:** Pattern profile detector disable list; benchmark negative expectation

---

### FP-016: Authorization Classifier as Violation

**Symptoms:** Finding emitted from `authorization_model_classifier` info detector.

**Root cause:** Metadata detector routed as violation in generation path.

**Correct classification:** Observation only; audit profile uses `auth_classifier_metadata_only=True`

**Prevention:** Audit profile in `invariant_engine_core.py`

---

## Category 7: Confidence / Triggerability

### FP-017: UNKNOWN Triggerability Defaults Permissive

**Symptoms:** Griefing or operator-error scenarios scored as exploitable security.

**Root cause:** `is_exploitable()` returns `True` for `UNKNOWN` triggerability.

**Correct classification:** Cap severity; use keyword + rule hints for triggerability

**Example contracts:** Classification `trigger_unknown_capped`

**Prevention:** Classification trigger_unknown_capped; future triggerability enum expansion

---

### FP-018: Low-Confidence LLM Finding Elevated

**Symptoms:** MEDIUM/HIGH severity on `confidence: low` semantic-only finding without deterministic corroboration.

**Root cause:** Severity not capped by confidence in all paths.

**Correct classification:** Cap at MEDIUM or suppress without bundle support

**Example contracts:** Adversarial CONF-2

**Prevention:** Adversarial CONF-2

---

## Quick Reference Matrix

| ID | Pattern | Wrong Kind | Correct Kind | Adversarial ID |
|----|---------|------------|--------------|----------------|
| FP-001 | Treasury prefunding | VULNERABILITY | DEPLOYMENT_REQUIREMENT | TRUST-1 |
| FP-002 | Dust redirect | operational_risk | VULNERABILITY or none | AG-1 |
| FP-003 | Permanent lock | VULNERABILITY | none / DESIGN_TRADE_OFF | AG-2 |
| FP-004 | Auth hallucination | VULNERABILITY | none | AUTH-2 |
| FP-007 | Key rotation | VULNERABILITY | DEPLOYMENT_REQUIREMENT | TRUST-2 |
| FP-009 | Oracle trust | VULNERABILITY | DEPLOYMENT_REQUIREMENT | TRUST-1 |
| FP-010 | Business metadata | VULNERABILITY | none | INTENT-3 |
| FP-015 | Token transfer noise | VULNERABILITY | none / observation | — |

---

## Adding New Patterns

When a false positive is discovered in production or adversarial runs:

1. Assign FP-NNN ID
2. Document symptom, root cause, correct classification
3. Link bundle facts that should prevent it
4. Add benchmark negative expectation OR adversarial scenario
5. Add replay entry in [`audit_replay_strategy.md`](audit_replay_strategy.md)
