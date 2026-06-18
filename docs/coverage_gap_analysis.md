# NexOps Audit Coverage Gap Analysis

**Workstream:** C  
**Method:** Separate **Detector Coverage** and **Reasoning Coverage** matrices.

---

## Summary

| Coverage type | Full | Partial | None |
|---------------|------|---------|------|
| Detector (static) | 12 attack classes | 14 | 11 |
| Reasoning (judge+policy) | 8 | 12 | 9 |

**Highest-priority gaps (P0):** oracle manipulation (detector none), governance/timelock bypass composites, hashlock preimage binding, replay/cross-contract coordination.

---

## Detector Coverage Matrix

Static layers: generation detectors, audit detectors, capability detectors, CashTokens invalid-logic, intent invariants, lint.

| Attack Class | Coverage | Layers | Evidence |
|--------------|----------|--------|----------|
| Authorization bypass (missing checkSig) | **full** | intent_invariants, lint | `intent_auth_gate` |
| Authorization bypass (wrong path) | **partial** | audit only | No dedicated dual-path detector |
| Value redirection (unbound output) | **full** | detectors | `output_binding_missing` |
| Value redirection (dust/remainder) | **partial** | detectors | Conservation yes; remainder binding weak |
| Input index OOB / underflow | **full** | detectors | `index_underflow`, `positive_offset_oob`, `fixed_index_oob` |
| Partial aggregation | **full** | detectors | `partial_aggregation_risk` |
| Input/output coupling | **full** | detectors | `input_output_coupling` |
| Token category drift | **full** | cashtokens | `token_category_drift` |
| Token amount inflation | **full** | cashtokens | `token_amount_inflation`, `unbounded_mint` |
| Token burn (unintended) | **full** | cashtokens | `token_amount_burn` |
| Minting authority escape | **full** | cashtokens | `authority_leak`, `minting_authority_escape` |
| Mutable NFT re-anchor failure | **full** | cashtokens, capability | `mutable_capability_leak`, `capability_mutable_nft_no_reanchor` |
| NFT commitment loss | **full** | cashtokens | `nft_commitment_loss` |
| Hybrid migration break | **full** | cashtokens, capability | `hybrid_continuity_break` |
| Covenant continuation break | **partial** | detectors | `vulnerable_covenant`; complex state forks weak |
| Timelock operator error | **partial** | detectors | `time_validation_error`; not all timeout paths |
| Hashlock preimage binding | **none** | — | No hashlock-specific detector |
| Multisig distinctness / reuse | **full** | detectors | `multisig_distinctness_flaw`, `multisig_signature_reuse` |
| Fee assumption violation | **partial** | detectors | `fee_assumption_violation`; not all fee paths |
| Division by zero | **full** | detectors | `division_by_zero` |
| Escrow role separation | **none** | — | `EscrowRoleEnforcementDetector` unregistered |
| Oracle input validation | **none** | — | No oracle detector |
| Governance / DAO treasury composite | **none** | — | No composite detector |
| Replay / cross-contract | **none** | — | Single-contract analysis only |
| NFT integrity (soulbound) | **partial** | capability | `capability_unrestricted_nft_transfer` |
| Fixed amount per recipient | **full** | intent_invariants | `intent_fixed_amount_per_recipient` |
| Recipient binding | **partial** | intent_invariants | Heuristic; proportional splits weak |
| Treasury prefunding | **n/a** | intent | `NOT_ENFORCEABLE_ONCHAIN` (by design) |
| Tautological / dead guards | **partial** | detectors | `tautological_guard`; dead-code auth **none** |
| Misleading comments | **none** | — | Not static |
| Trust-boundary (off-chain) | **none** | — | Not static |

---

## Reasoning Coverage Matrix

LLM judge + AuditFactBundle + finding policy + adversarial validation.

| Attack Class | Coverage | Layers | Evidence |
|--------------|----------|--------|----------|
| Authorization bypass | **full** | judge, invariants | AUTH-3, payroll_d |
| Value redirection (material) | **partial** | judge | AG-1 fixed in V2.1; edge cases remain |
| Trust assumption (treasury, oracle) | **full** | judge V2.1, policy | TRUST-1..3 pass |
| Bundle contradiction | **full** | judge guards | CONTRA-1..3 pass |
| Intent tier vs security | **full** | judge V2.1 | INTENT-3 pass |
| Attacker gain without profit | **full** | judge V2.1 | AG-2, AG-3 pass |
| Auth hallucination | **partial** | judge | AUTH-2 pass with compliant mock; LLM compliance risk |
| Oracle manipulation (economic) | **partial** | judge | TRUST-1; stale price, median oracle **untested** |
| Covenant escape (semantic) | **partial** | judge | No dedicated adversarial family |
| Hashlock wrong preimage | **none** | — | No scenarios |
| Governance timelock bypass | **untested** | — | No scenarios |
| NFT category drift (semantic) | **partial** | judge, detectors | BCH-1 |
| Replay / cross-contract | **none** | — | Out of scope for judge |
| Deployment vs exploit | **full** | policy | Payroll treasury, escrow_b |
| Confidence calibration | **partial** | policy | CONF-2 pass; live model untested |
| Design trade-offs | **full** | policy | design_* classification scenarios |
| Triggerability (non-attacker) | **full** | policy | trigger_* scenarios |
| Delta-only dedup | **partial** | judge guards | Payroll D; multi-finding untested |
| Escrow refund path missing | **partial** | semantic gap | escrow_a scenario |
| Multisig sanity (intent vs code) | **full** | intent + sanity | multisig_a/b |

---

## Combined Gap Rankings

### P0 — Critical (address in next benchmark + adversarial sprint)

| Gap | Detector | Reasoning | Recommended benchmarks |
|-----|----------|-----------|------------------------|
| Oracle manipulation | none | partial | `bench_oracle_001`–`006` |
| Hashlock preimage binding | none | none | Migrate `hl_001`–`hl_005` |
| Dead-code / fake auth | none | partial | `FAKE_AUTH-*` adversarial |
| Dual-path auth bypass | partial | partial | AUTH-1, `HIDDEN_AUTH-*` |

### P1 — High

| Gap | Detector | Reasoning | Action |
|-----|----------|-----------|--------|
| Covenant state fork | partial | partial | `cov_001`–`003` audit migration |
| Escrow role enforcement | none | partial | Register or deprecate detector |
| Governance composite | none | untested | `bench_dao_treasury_*` |
| Judge LLM compliance | n/a | partial | Tier 3 E2E + replay corpus |

### P2 — Medium

| Gap | Detector | Reasoning | Action |
|-----|----------|-----------|--------|
| Fee edge cases | partial | partial | Expand UTXO adversarial |
| Proportional split amounts | partial | partial | Intent model structured amounts |
| Replay cross-contract | none | none | Document out-of-scope |

---

## Families: Generation vs Audit Coverage

| Family | Generation cases | Audit matrix | Gap |
|--------|------------------|--------------|-----|
| hashlock | 5 | 0 | **P0** |
| decay | 3 + vesting | 0 | **P1** |
| refundable | 6 | 0 | **P1** |
| conditional_spend | 5 | 0 | **P1** |
| covenant | 3 | 0 | **P1** |
| escrow | 16 | 2 | partial |
| payroll/split | 14 | 6 | partial |
| cashtokens | 50+ | 2 | partial |

---

## Layer Inventory Reference

| Layer | Count | Module |
|-------|-------|--------|
| Generation detectors | 24 + 8 token | `anti_pattern_detectors.py`, `cashtokens_token_detectors.py` |
| Audit-native detectors | 8 | `audit_detectors.py` |
| Capability detectors | 7 | `capability_detectors.py` |
| Intent invariants | 6 IDs | `intent_invariants.py` |
| Judge signals | 4 booleans + trust | `semantic_judge.py` |
| Unregistered detectors | 5 | See detector roadmap |

---

## Recommendations

1. **Benchmark first** — Close hashlock, decay, covenant gaps via Workstream A migration
2. **Do not build oracle detector yet** — Extend reasoning coverage via adversarial + Tier 3
3. **Register or delete** `EscrowRoleEnforcementDetector`, `SpendingPathSecurityDetector`
4. **Track detector vs reasoning separately** in CI dashboards
