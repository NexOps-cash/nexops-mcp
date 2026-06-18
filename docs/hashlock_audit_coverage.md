# Hashlock Audit Coverage Plan

**Gap:** Detector coverage **none**, reasoning coverage **none** (see [`coverage_gap_analysis.md`](coverage_gap_analysis.md)).

**Strategy:** Measure before building detectors.

## Benchmark Family

| ID | Contract | Difficulty | Expected | Status |
|----|----------|------------|----------|--------|
| `bench_hashlock_001` | `hashlock/secure.cash` | 1 | Clean audit | pass |
| `bench_hashlock_002` | `hashlock/vulnerable_no_hash.cash` | 1 | `hash_preimage_binding` | **gap** (probe) |
| `bench_hashlock_003` | `hashlock/htlc_secure.cash` | 3 | Clean audit | pass |

Run: `python scripts/run_benchmark_suite.py --family hashlock --include-coverage-probes`

## Expected Findings (when detector exists)

| Flaw | Expected rule_id | Severity |
|------|------------------|----------|
| Missing `sha256(preimage) == hash` | `hash_preimage_binding` | HIGH |
| Missing preimage length check | `commitment_length_missing` | MEDIUM |
| HTLC refund without timelock | `time_validation_error` | HIGH |

## Adversarial Family (planned)

| ID | Technique | Source |
|----|-----------|--------|
| HASHLOCK-01 | Comment claims hashlock, no verify | TBD |
| HASHLOCK-02 | Hash on wrong spend path | TBD |
| HASHLOCK-03 | RIPEMD160 vs SHA256 confusion | from `hl_003` intent |

## Replay Cases

| ID | Trigger | adversarial_id |
|----|---------|----------------|
| (future) | preimage gap | — |

## Decision Gate

Build hashlock detector **only when**:

1. `bench_hashlock_002` fails Tier 1 consistently
2. Reasoning probes (oracle-style trust) do not cover preimage binding
3. Real-world index includes hashlock contracts

Until then: keep `coverage_probe: true` on `bench_hashlock_002`.

## Migration from Generation

| Generation ID | Intent | Audit benchmark action |
|---------------|--------|------------------------|
| hl_001 | Basic SHA256 hashlock | → secure baseline |
| hl_002 | HTLC | → `bench_hashlock_003` |
| hl_003 | RIPEMD160 | future variant |
| hl_004 | Multi-preimage | difficulty 4 |
| hl_005 | Token mixing failure | cross with TOKEN |
