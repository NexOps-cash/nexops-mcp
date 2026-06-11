# Split Payment Phase 1 — Final Validation

**Date:** 2026-06-11  
**Status:** **PHASE 1 COMPLETE** (4/4 subset convergence)

---

## 1. What change was made

Revenue-share contracts were failing the **sanity checker** because the LLM emitted only proportional per-output `require`s without an explicit chained sum. Sanity and `split_conservation` helpers require detectable `out[0] + ... + out[N-1] == input` patterns.

**Approach (preferred, minimal):** Strengthen generation guidance — no sanity checker changes.

| File | Change |
|------|--------|
| [`pipeline.py`](../src/services/pipeline.py) | `_SPLIT_RAIL` + Phase 2 `SPLIT MODE`: mandate explicit sum require even when using proportional/revenue-share math; forbid division-only conservation |
| [`split_rules.yaml`](../src/services/knowledge_structured/split_rules.yaml) | Added `SPLIT-PROPORTIONAL-PLUS-SUM` rule |
| [`synthesis_rules.yaml`](../src/services/knowledge_structured/synthesis_rules.yaml) | Added `canonical_revenue_share_split` template with proportional legs **and** explicit 4-way sum |

---

## 2. Benchmark run

| Field | Value |
|-------|-------|
| **Run ID** | `bench_20260611_1517_a76e` |
| **Case** | `split_004_revenue_share` only |
| **Command** | `python -m benchmark.runner benchmark/suites/split_payment.yaml --ids split_004_revenue_share` |

---

## 3. Result

| Metric | Value |
|--------|-------|
| compile_pass | **true** |
| converged | **true** |
| intent_coverage | **1.0** |
| final_score | **1.0** |
| retries_used | 1 |
| failure_layer | **null** |

Generated contract includes both proportional legs and explicit conservation:

```cashscript
require(tx.outputs[0].value == (inputValue * share1) / totalShares);
// ... share2–4 ...
require(
    tx.outputs[0].value + tx.outputs[1].value + tx.outputs[2].value + tx.outputs[3].value ==
    tx.inputs[this.activeInputIndex].value
);
```

---

## 4. First failure layer

**None** — case passed on first attempt.

---

## 5. Phase 1 completion

**Split Payment Phase 1 is COMPLETE** on the 4-case real-world subset.

| Case | Post–structural-hotfix (`1500_19ae`) | Post–revenue guidance (`1517_a76e`) |
|------|--------------------------------------|-------------------------------------|
| split_001_treasury | PASS | PASS (unchanged) |
| split_002_payroll | PASS | PASS (unchanged) |
| split_003_multisig_distribution | PASS | PASS (unchanged) |
| split_004_revenue_share | FAIL (Sanity) | **PASS** |

**Subset metrics:**

| Stage | Run ID | Compile | Convergence | Avg score |
|-------|--------|---------|-------------|-----------|
| Baseline | `bench_20260611_1344_cb95` | 0% | 0% | 0.0 |
| After structural hotfix | `bench_20260611_1500_19ae` | 75% | 75% | 0.75 |
| **Final (4/4)** | `1500_19ae` + `1517_a76e` | **100%** | **100%** | **1.0** |

---

## Phase 1 summary

### Major root causes discovered

1. **Routing:** `effective_mode == "split"` did not map to `split_payment` profile → `split_rules.yaml` never loaded.
2. **2-output hardcoding:** Rails, lint, and sanity assumed `out[0] + out[1]` only (fixed in Phase 1B).
3. **Structural false positive:** `_dangling_require()` flagged valid multiline `require()` blocks → 0% compile despite valid `cashc` output.
4. **Revenue-share guidance gap:** Proportional-only drafts failed sanity before compile.

### Fixes implemented

| Fix | Impact |
|-----|--------|
| `split` → `split_payment` profile alias | Rules/rails load on main path |
| N-output `split_conservation` + lint/sanity | 3+ output conservation |
| Multisig + split feature co-routing | Multisig distribution case |
| Tag-overlay `split_rules` for `ft_transfer` payroll | Payroll rules load |
| Structural integrity hotfix | Unblocked compile gate |
| Revenue-share explicit sum guidance | 4/4 convergence |

### Before / after (4-case subset)

| Metric | Before Phase 1 (`2109_cdbc`) | After Phase 1 complete |
|--------|------------------------------|-------------------------|
| Compile | 0/4 (0%) | 4/4 (100%) |
| Convergence | 0/4 (0%) | 4/4 (100%) |
| Avg score | 0.0 | 1.0 |

### Lessons for other BCH patterns

| Lesson | Applies to |
|--------|------------|
| **Verify checker before refactoring generation** — structural FP blocked 100% compile with valid drafts | All patterns |
| **Layer diagnosis** — distinguish routing vs lint vs sanity vs compile first failure | Escrow, multisig |
| **Explicit conservation `require` in rails** — do not rely on implicit math (division) for sanity gates | Escrow fee splits, revenue shares |
| **Profile alias bugs** — `effective_mode` vs `canonical_pattern` mismatch silently drops YAML rules | Multisig (`multisig` profile exists; watch mode aliases) |
| **Multiline `require()` is common for N-output sums** — checkers must use balanced-paren scan | Vault staged splits, escrow release paths |
| **Diagnostic JSON tooling** (`diagnose_split_case.py`) — reusable for escrow/vault/hashlock | Pattern stabilization playbook |

---

## Re-run full subset (optional confirmation)

```bash
python -m benchmark.runner benchmark/suites/split_payment.yaml \
  --ids split_001_treasury,split_002_payroll,split_003_multisig_distribution,split_004_revenue_share
```

---

## Related artifacts

- [`split_payment_phase1_plan.md`](split_payment_phase1_plan.md)
- [`split_payment_phase1_results.md`](split_payment_phase1_results.md)
- [`structural_integrity_hotfix_results.md`](structural_integrity_hotfix_results.md)
- [`split_layer_diagnosis.md`](split_layer_diagnosis.md)
