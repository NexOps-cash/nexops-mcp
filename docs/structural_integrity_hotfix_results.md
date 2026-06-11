# Structural Integrity Hotfix — Results

**Hotfix:** Balanced-parenthesis `_dangling_require()` in [`structural_integrity.py`](../src/services/structural_integrity.py)  
**Tests:** [`tests/test_structural_integrity_multiline_require.py`](../tests/test_structural_integrity_multiline_require.py)  
**Before run:** `bench_20260611_1344_cb95`  
**After run:** `bench_20260611_1500_19ae`

---

## Summary

| Metric | Before hotfix | After hotfix | Delta |
|--------|---------------|--------------|-------|
| **Compile rate** (4-case subset) | **0%** (0/4) | **75%** (3/4) | +75 pp |
| **Convergence rate** | **0%** (0/4) | **75%** (3/4) | +75 pp |
| **Avg final score** | 0.0 | 0.75 | +0.75 |
| **Avg intent coverage** | 0.0 | 0.75 | +0.75 |
| **Avg latency** | 26.2s | 16.3s | −9.9s |

**Verdict:** Split payment is the **first BCH pattern in this subset** moved from **0% compile to post-hotfix convergence** on real-world N-output cases. Three of four cases converge on **first attempt** with score **1.0**.

---

## Per-case comparison

| Case | Compile before | Conv before | Compile after | Conv after | Score after | First failure after |
|------|----------------|-------------|---------------|------------|-------------|---------------------|
| split_001_treasury | fail | no | **pass** | **yes** | 1.0 | — |
| split_002_payroll | fail | no | **pass** | **yes** | 1.0 | — |
| split_003_multisig_distribution | fail | no | **pass** | **yes** | 1.0 | — |
| split_004_revenue_share | fail | no | fail | no | 0.0 | **Sanity** (then pipeline exhaust) |

---

## What changed

### Code

Replaced line-oriented regex:

```python
re.search(r"require\s*\(\s*[^)]*$", code, re.MULTILINE)
```

With `_closing_paren_index()` — balanced `(` / `)` scan respecting strings and comments — applied to each `\brequire\s*\(` occurrence.

### Validation

- `tests/test_structural_integrity_multiline_require.py` — 4 new cases (all pass)
- `tests/test_structural_integrity.py` — existing corruption fixtures still pass (16 total)
- Saved pre-hotfix drafts in `benchmark/results/structural_failures_split/` — all four now `is_structurally_valid() == True`

---

## Remaining failure: split_004_revenue_share

**Before hotfix:** Structural integrity blocked compile (false `dangling_require` on multiline sums).

**After hotfix:** Pipeline reaches generation but **sanity checker** rejects drafts:

```
Sanity Check failed (STRICT): ['Split payment intent requires sum-preservation check across multiple outputs.']
```

**Root cause:** Revenue-share prompts often produce **per-output proportional `require`s** (e.g. `output[i].value == (input * share_i) / total`) without a single detectable **chained sum == input** line. `has_bch_value_conservation()` does not yet treat proportional legs as provable conservation.

**Benchmark `failure_layer`:** Reported as `Compile` with `tokens_completion: 0` because synthesis exhausted retries after sanity failures (no code returned in JSON).

**Next smallest fix (optional):** Extend sanity / conservation helper to accept proportional share patterns, or require explicit multiline sum in rails for 4-way revenue cases.

---

## Interpretation

| Hypothesis | Outcome |
|------------|---------|
| Structural false positive was blocking all split compiles | **Confirmed** — 3/4 immediate convergence after fix |
| LLM could not generate valid N-output CashScript | **Refuted** for 3/4 cases — compiles on attempt 1 |
| Rails / routing still broken | **Refuted** for treasury, payroll, multisig distribution |
| 100% convergence on subset | **Not yet** — revenue share blocked at sanity layer |

---

## Re-run command

```bash
cd nexops-mcp
python -m pytest tests/test_structural_integrity_multiline_require.py tests/test_structural_integrity.py -q
python -m benchmark.runner benchmark/suites/split_payment.yaml \
  --ids split_001_treasury,split_002_payroll,split_003_multisig_distribution,split_004_revenue_share
```

---

## Related documents

- Root-cause analysis: [`structural_failure_analysis_split.md`](structural_failure_analysis_split.md)
- Layer diagnosis: [`split_layer_diagnosis.md`](split_layer_diagnosis.md)
