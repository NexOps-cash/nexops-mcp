# Wave 1.5 — CashTokens Semantic Invariant Unification

## In scope

- Tiered `SemanticCapabilities` (`src/services/semantic_capabilities.py`)
- Declarative requirement map (`benchmark/config/semantic_requirement_map.yaml`)
- Benchmark evaluator capability-first satisfaction + trace artifacts
- Capability-backed detectors (`src/services/capability_detectors.py`)
- Unified invariant engine core with `generation` / `audit` profiles
- Audit confidence metadata (compile, structural, semantic, authorization) — **deployment gate unchanged**
- Regression tests under `tests/test_semantic_capabilities.py`

## Out of scope (freeze)

- LP/AMM, cross-contract reasoning, stablecoin vault synthesis
- Authority-model expansion beyond existing classifiers
- Wave 2 schema semantics
- New `Experimental` capability tier keys

## Architecture constraints

| Rule | Enforcement |
|------|-------------|
| No god-object capabilities | Tier namespaces + `CAPABILITY_REGISTRY` ownership |
| No policy in extraction | `extract_semantic_capabilities` is AST/heuristic only |
| Evaluator before enforcer unification | Phase B merged before shared `invariant_engine_core` |
| Traceability | `benchmark/results/capability_traces/` per benchmark case; audit traces on validate |

## PR checklist

- [ ] Semantic suite ≥6/8 Tier B (target 8/8) after evaluator migration
- [ ] Family positive paths unchanged
- [ ] Capability traces emitted for benchmark evaluations
- [ ] Regex fallback usage logged in requirement trace (`path: fallback_regex_alias`)
- [ ] No edits to Wave 2 / LP docs
- [ ] `pytest tests/test_semantic_capabilities.py tests/cashtokens/test_capability_detectors.py tests/test_invariant_engine_core.py` green

## Production API parity (generation)

`/ws/generate` and `GenerationController` default to **benchmark synthesis**:

- `disable_golden=True` (free synthesis)
- `disable_fallbacks=True` (no `fallback_token.cash` substitution)
- 3 generation attempts (same as evaluator)
- Response includes `data.synthesis`: `compile_pass`, `converged`, `fallback_used`, `attempt_number`, `generation_seconds`

Opt out via WebSocket `context`: `benchmark_synthesis: false`, or `allow_fallback: true` / `use_golden: true`.

## Validation commands

```powershell
cd nexops-mcp
python -m pytest tests/test_semantic_capabilities.py tests/cashtokens/test_capability_detectors.py tests/test_invariant_engine_core.py tests/cashtokens/test_evaluator_pools.py -q
python scripts/run_semantic_benchmark.py --all   # requires OPENROUTER_API_KEY
python scripts/run_family_benchmarks.py
```
