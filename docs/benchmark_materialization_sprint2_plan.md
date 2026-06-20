# Benchmark Materialization Sprint 2

Goal: grow executable benchmark coverage from **20 → 35+** without OpenRouter, detector redesign, semantic judge, or policy work.

## Coverage report

| Metric | Before | After |
|--------|--------|-------|
| Executable benchmarks (all families) | 20 | **38** |
| Escrow executable | 0 | **6** |
| Vesting / decay executable | 0 | **4** |
| Refundable payment executable | 0 | **4** |
| Conditional spend executable | 0 | **4** |

**Standard-mode suite** (`python scripts/run_benchmark_suite.py --mode standard --include-coverage-probes`):

| Result | Count |
|--------|-------|
| Pass | 35 |
| Gap (coverage probes) | 3 |
| Fail | 0 |

All 18 new family benchmarks **pass**. Pre-existing gaps unchanged (hashlock preimage, fake auth, dual-path).

---

## Materialized benchmarks

### Escrow (+6)

| ID | Fixture | Mutation |
|----|---------|----------|
| `bench_escrow_001` | `escrow/basic_multisig_secure.cash` | secure 2-of-2 |
| `bench_escrow_002` | `escrow/two_of_three_secure.cash` | secure 2-of-3 |
| `bench_escrow_003` | `escrow/timeout_refund_secure.cash` | settle + timed refund |
| `bench_escrow_004` | `escrow/arbiter_dispute_secure.cash` | 3-party release + refund |
| `bench_escrow_005` | `scenarios.py:ESCROW_WITH_REFUND` | classification matrix |
| `bench_escrow_006` | `escrow/no_auth_release.cash` | `intent_auth_gate` |

### Vesting / decay (+4)

| ID | Fixture | Mutation |
|----|---------|----------|
| `bench_vesting_001` | `vesting/cliff_secure.cash` | cliff claim |
| `bench_vesting_002` | `vesting/owner_cancel_secure.cash` | claim + owner cancel |
| `bench_decay_001` | `decay/linear_decay_secure.cash` | linear decay bounds |
| `bench_vesting_003` | `vesting/no_auth_claim.cash` | `intent_auth_gate` |

### Refundable payment (+4)

| ID | Fixture | Mutation |
|----|---------|----------|
| `bench_refundable_001` | `refundable/subscription_secure.cash` | rp_003 |
| `bench_refundable_002` | `refundable/gradual_release_secure.cash` | rp_004 |
| `bench_refundable_003` | `refundable/htlc_refund_secure.cash` | rp_002 HTLC |
| `bench_refundable_004` | `refundable/no_auth_paths.cash` | `intent_auth_gate` |

### Conditional spend (+4)

| ID | Fixture | Mutation |
|----|---------|----------|
| `bench_conditional_001` | `conditional_spend/alice_or_bob_delayed.cash` | cs_001 |
| `bench_conditional_002` | `conditional_spend/will_inheritance.cash` | cs_002 |
| `bench_conditional_003` | `conditional_spend/multi_path_secure.cash` | cs_003 |
| `bench_conditional_004` | `conditional_spend/no_auth_paths.cash` | `intent_auth_gate` |

All use `evaluation_mode: detector_only`, `tier: 1`, `expected_invariants: auth_gate:ENFORCED|MISSING`.

---

## Fixture source strategy

- **Lint-safe minimal `.cash`** under `tests/fixtures/audit_benchmark/{escrow,vesting,decay,refundable,conditional_spend}/`
- Derived from suite YAML intents (`escrow_suite.yaml`, `vesting.yaml`, `decay.yaml`, `refundable_payment.yaml`, `conditional_spend.yaml`) and canonical knowledge templates where compile-safe
- CashScript constraint: comparisons use `>=` only; `tx.time` must appear on left-hand side
- Reused `tests/audit_classification_matrix/scenarios.py:ESCROW_WITH_REFUND` for one escrow baseline

---

## Registry audit (non-executable remainder)

| Family | Defined (registry) | Still spec-only / missing |
|--------|-------------------|---------------------------|
| Escrow | 8 | 2 realworld slots + migration stubs without fixture alias |
| Vesting | 6 | 2 migration auth variants |
| Decay (`dec`) | 8 | dec_002/003 streaming + failure cases |
| Refundable (`rp`) | 14+ | rp_001/005/006, realworld rw_007 |
| Conditional (`cs`) | 11 | cs_004 amount-based, cs_005 failure |

---

## Remaining gaps

1. **Semantic escrow findings** — `escrow_a` (missing refund) and `escrow_b` (external funding) remain policy/semantic tier; not materialized as detector-only
2. **Failure-case YAML intents** — `esc_005`, `rp_005`, `cs_005`, `dec_003`, `tl_004` need vulnerable fixtures + detector or coverage_probe wiring
3. **Knowledge templates** — `knowledge/templates/escrow_2of3.cash`, `vesting_linear.cash`, `auction_dutch.cash` use `this.lockingBytecode` (non-compile); full templates deferred
4. **Realworld collection** — `rw_001`, `rw_007`, `rw_012` slots empty

---

## Verification

```bash
python scripts/build_executable_benchmark_registry.py
python scripts/run_benchmark_suite.py --mode standard --include-coverage-probes
python -m pytest tests/test_benchmark_suite_runner.py -q
python scripts/run_replay_suite.py --critical-only
```

Expected: 38 executable, 35 pass + 3 gap, 0 fail; replay critical suite passes.
