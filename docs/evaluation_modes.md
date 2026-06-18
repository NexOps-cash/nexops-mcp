# CI Evaluation Modes

**Zero OpenRouter credits** for Fast and Standard modes.

## Modes

| Mode | Pipeline | LLM | Use case |
|------|----------|-----|----------|
| **fast** | compile → lint → detectors | No | Detector regression, CI on every PR |
| **standard** | fast + intent invariants + policy fixtures | No | Full deterministic + mocked judge policy |
| **full** | standard + live semantic judge | Yes (opt-in) | Nightly / manual only — **not implemented in default runner** |

## Commands

```bash
# Fast — detectors only
python scripts/run_benchmark_suite.py --mode fast

# Standard — default CI mode (executable registry)
python scripts/run_benchmark_suite.py --mode standard --include-coverage-probes

# Dry-run — check contract resolvability
python scripts/run_benchmark_suite.py --dry-run

# Replay — critical false-positive regressions
python scripts/run_replay_suite.py --critical-only
```

## Registries

| File | Entries | Materialized |
|------|---------|--------------|
| `docs/benchmark_registry_executable.json` | 10 | Yes — CI default |
| `docs/benchmark_registry.json` | 180 | Partial — migration stubs |
| `audit_replay_corpus/index.json` | 33 | Adversarial + classification |

## Coverage Probes

Benchmarks with `"coverage_probe": true` document **known gaps**. They report `status: "gap"` instead of `fail` when expectations are unmet.

Use `--include-coverage-probes` to treat gaps as non-failing in exit code.

## Difficulty Ladder

Each benchmark may include `"difficulty": 1-5`:

| Level | Meaning |
|-------|---------|
| 1 | Simple bug (missing auth, missing hash) |
| 2 | Single invariant failure |
| 3 | Cross-feature (HTLC, oracle trust) |
| 4 | Complex protocol |
| 5 | Adversarial / deceptive |

Added to full registry via `scripts/build_executable_benchmark_registry.py`.

## Pytest

```bash
pytest tests/test_benchmark_suite_runner.py tests/test_replay_suite_runner.py -q
```
