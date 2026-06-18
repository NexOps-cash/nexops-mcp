# Adversarial Registry Quality Audit

**Date:** 2026-06-18  
**Registry:** [`adversarial_registry.json`](adversarial_registry.json)

## Summary

| Status | Count | Quality |
|--------|-------|---------|
| **Implemented** | 23 | Executable via `tests/adversarial_semantic_judge/` |
| **Planned stubs** | 177 | Metadata only — `contract_ref: TBD` |
| **Recommendation** | Target **50 excellent** before expanding to 200 |

## Implemented (23) — Executable

| ID | Category | Contract source |
|----|----------|-----------------|
| AG-1..3 | FAKE_AUTH | adversarial scenarios.py |
| AUTH-1..3 | HIDDEN_AUTH / FAKE_AUTH | scenarios.py |
| TRUST-1..3 | TRUST | scenarios.py |
| INTENT-1..3 | CONTRA / MISLEAD | scenarios.py |
| CONTRA-1..3 | CONTRA | scenarios.py |
| CONF-1..3 | TRUST / CONTRA | scenarios.py |
| BCH-1..3 | TOKEN / TRUST | scenarios.py |
| MIXED-1..2 | TRUST | scenarios.py |

**Runner:** `tests/adversarial_semantic_judge/runner.py` — policy-only, no LLM when using fixture judgments.

## Planned (177) — Not Executable

Stubs `FAKE_AUTH-04` through `CONTRA-25` have:

- `status: "planned"`
- `contract_ref: "TBD"`
- `family_hint` only

**Do not count toward CI pass rate.**

## Missing High-Priority Cases (materialize next)

| Priority | Category | Scenario | Rationale |
|----------|----------|----------|-----------|
| P0 | FAKE_AUTH | Dead-code checkSig after `require(false)` | `tests/fixtures/audit_benchmark/p0/fake_auth_dead_code.cash` |
| P0 | HIDDEN_AUTH | Dual-path bypass | `p0/dual_path_bypass.cash` |
| P0 | TRUST | Oracle secure + stale price intent | `p0/oracle_secure.cash` |
| P1 | TOKEN | Hashlock missing preimage | `hashlock/vulnerable_no_hash.cash` |
| P1 | UTXO | Index OOB variant | TBD |
| P1 | MISLEAD | Comment claims multisig, single sig | TBD |

## Quality Bar (50 excellent target)

Before promoting a stub to **implemented**:

1. Materialized `.cash` in `tests/fixtures/adversarial_executables/`
2. V2 adversarial + V2.1 compliant judgments in scenario module
3. Entry in `audit_replay_corpus/index.json` if regression-worthy
4. Linked benchmark in `benchmark_registry_executable.json`

## Deprecation Policy

- Remove quantity target of 200 from CI gates
- Keep registry as backlog index
- Promote stubs in P0 → P1 order from coverage gap analysis

## Related

- [`adversarial_strategy.md`](adversarial_strategy.md)
- [`false_positive_playbook.md`](false_positive_playbook.md)
- `scripts/run_replay_suite.py --critical-only`
