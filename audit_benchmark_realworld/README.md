# Real-World Audit Benchmark Corpus

Index of non-synthetic BCH/CashScript contracts, contracts for NexOps audit evaluation.

## Contents

- [`index.json`](index.json) — Master index with `safe` | `unsafe` | `unknown` classification
- `contracts/` — Materialized `.cash` files (implementation phase copies from provenance paths)

## Usage

1. Read strategy: [`docs/realworld_collection_strategy.md`](../docs/realworld_collection_strategy.md)
2. Each index entry links to a `bench_realworld_*` slot in [`docs/benchmark_registry.json`](../docs/benchmark_registry.json)
3. Tier 3 E2E runs use `safe` entries expecting clean audits; `unsafe` entries expect specific findings

## Status

Phase 1 index: **28 entries** (10 safe, 8 unsafe, 10 unknown).  
Contract files not copied yet — provenance paths reference existing repo artifacts.
