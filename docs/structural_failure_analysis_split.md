# Structural Integrity Failure Analysis — Split Payment

**Benchmark run:** `bench_20260611_1344_cb95`  
**Investigation date:** 2026-06-11  
**Tool:** `scripts/investigate_split_structure.py`  
**Artifacts:** `benchmark/results/structural_failures_split/` (gitignored; regenerate with script)

---

## Executive summary

All four split cases failed with `[StructuralIntegrity] Post-lint code invalid — skipping compile, regen`. Investigation shows **100% of rejections are false positives**: the only structural issue flagged is `dangling_require`, triggered by **multiline `require(...)` blocks** that are syntactically complete.

**Every saved final draft compiles successfully with `cashc`.**

| Case | Structural valid | cashc compile | Dominant issue |
|------|------------------|---------------|----------------|
| split_001_treasury | false | **pass** | `dangling_require` (false positive) |
| split_002_payroll | false | **pass** | `dangling_require` (false positive) |
| split_003_multisig_distribution | false | **pass** | `dangling_require` (false positive) |
| split_004_revenue_share | false | **pass** | `dangling_require` (false positive) |

**Dominant failure mode:** `dangling_require` false positive on multiline `require()` (12/12 generation attempts).

**Root cause class:** **D — Structural repair rejecting recoverable drafts** (checker bug, not LLM degeneration).

**Smallest fix for >50% compile:** Patch `_dangling_require()` in [`structural_integrity.py`](../src/services/structural_integrity.py) to parse balanced parentheses across lines instead of flagging `require(` lines that continue on the next line.

---

## Methodology

For each case the investigation script:

1. Ran Phase 1 + 3× Phase 2 (matching benchmark `disable_fallbacks=True`)
2. Saved each draft to `*_attemptN.cash` and `*_final_draft.cash`
3. Ran `diagnose_structure()` and DSL lint (same path as `pipeline_engine.py`)
4. Re-ran `CompilerService.compile()` on final drafts post-hoc

---

## Per-case results

### split_001_treasury

| Attempt | Lines | Structural | Lint | Rejection |
|---------|-------|------------|------|-----------|
| 1 | 23 | `dangling_require` | pass (LNC-021 warn) | structural_integrity_post_lint |
| 2 | 23 | `dangling_require` | pass | structural_integrity_post_lint |
| 3 | 23 | `dangling_require` | pass | structural_integrity_post_lint |

**Final draft:** `benchmark/results/structural_failures_split/split_001_treasury_final_draft.cash`

**Triggering construct** (lines 18–21):

```cashscript
        require(
            tx.outputs[0].value + tx.outputs[1].value + tx.outputs[2].value ==
            tx.inputs[this.activeInputIndex].value
        );
```

**Post-hoc compile:** pass  
**Intent gaps:** Valid 3-output treasury split with owner `checkSig` and BCH conservation.

---

### split_002_payroll

| Attempt | Lines | Structural | Lint | Rejection |
|---------|-------|------------|------|-----------|
| 1 | 38 | `dangling_require` | pass | structural_integrity_post_lint |
| 2 | 38 | `dangling_require` | pass | structural_integrity_post_lint |
| 3 | 39 | `dangling_require` | pass | structural_integrity_post_lint |

**Final draft:** `split_002_payroll_final_draft.cash`

**Triggering constructs:** Multiline `require()` for tokenAmount sum (lines 29–32) and BCH value sum (lines 34–37).

**Post-hoc compile:** pass  
**Intent gaps:** 3-way token split with category preservation; uses param amounts (acceptable).

---

### split_003_multisig_distribution

| Attempt | Lines | Structural | Lint | Rejection |
|---------|-------|------------|------|-----------|
| 1 | 29 | `dangling_require` | pass | structural_integrity_post_lint |
| 2 | 29 | `dangling_require` | pass | structural_integrity_post_lint |
| 3 | 29 | `dangling_require` | pass | structural_integrity_post_lint |

**Final draft:** `split_003_multisig_distribution_final_draft.cash`

**Triggering construct:** Multiline BCH conservation `require()` (lines 24–27). Includes valid `checkMultiSig` 2-of-3.

**Post-hoc compile:** pass

---

### split_004_revenue_share

| Attempt | Lines | Structural | Lint | Rejection |
|---------|-------|------------|------|-----------|
| 1 | 34 | `dangling_require` | pass | structural_integrity_post_lint |
| 2 | 34 | `dangling_require` | pass | structural_integrity_post_lint |
| 3 | 34 | `dangling_require` | pass | structural_integrity_post_lint |

**Final draft:** `split_004_revenue_share_final_draft.cash`

**Triggering construct:** Multiline 4-way value sum `require()` (lines 30–32). Proportional share math via integer division.

**Post-hoc compile:** pass  
**Intent gap:** No `checkSig` in draft (evaluator would still score low on auth).

---

## Classification frequency

Counts across **12 generation attempts** (3 per case × 4 cases):

| Class | Count | % of attempts |
|-------|-------|---------------|
| **dangling_require** | 12 | **100%** |
| bracket_imbalance | 0 | 0% |
| truncated_function | 0 | 0% |
| truncated_contract | 0 | 0% |
| malformed_signature | 0 | 0% |
| invalid_cashscript_syntax | 0 | 0% |
| duplicate_function | 0 | 0% |
| other (empty, etc.) | 0 | 0% |

**Brace/paren balance on all drafts:** `open_braces == close_braces == 2`, `paren_delta == 0`.

---

## Root cause: `_dangling_require` false positive

[`structural_integrity.py`](../src/services/structural_integrity.py) `_dangling_require()` uses:

```python
re.search(r"require\s*\(\s*[^)]*$", code.rstrip(), re.MULTILINE)
```

With `re.MULTILINE`, `$` matches **end of each line**. Any line that opens `require(` without a closing `)` on the **same line** matches — including valid multiline requires:

```cashscript
require(
    expr ==
    input
);
```

The pipeline then hits [`pipeline_engine.py`](../src/services/pipeline_engine.py) ~235:

```python
if not is_structurally_valid(code):
    logger.warning("[StructuralIntegrity] Post-lint code invalid — skipping compile, regen")
    continue
```

**Compile is never attempted** despite lint passing and `cashc` accepting the code.

---

## Hypothesis evaluation

| Hypothesis | Verdict | Evidence |
|------------|---------|----------|
| **A. Prompt size / complexity** | **Unlikely primary** | Drafts are 23–39 lines, 709–1411 chars; complete contracts |
| **B. Rail interactions** | **Not blocking compile** | Rails produce correct N-output shapes; lint passes |
| **C. LLM degeneration (truncation)** | **Not observed** | No brace/paren imbalance, no incomplete functions, no truncation |
| **D. Structural repair rejecting recoverable drafts** | **Confirmed** | All drafts compile; only `dangling_require` FP blocks gate |

---

## Recommended fix (smallest path to >50% compile)

### P0 — Fix multiline `require()` detection (~15 lines)

Replace line-oriented `[^)]*$` check with parenthesis-balanced scanning:

- Track depth from each `require(` until matching `)` (ignore parens inside strings/comments)
- Only flag if EOF reached with depth > 0

**Expected impact:** 4/4 cases should reach compile gate immediately on current drafts (100% compile on this subset vs 0% today).

### P1 — Add regression test

`tests/test_structural_integrity.py`:

- Valid multiline `require()` → `is_structurally_valid() == True`
- Genuinely unclosed `require(` → False

### P2 — Optional follow-ups (not required for 50% compile)

| Item | Why |
|------|-----|
| `split_004` owner signature | Intent/evaluator, not structural |
| LNC-021 warning on BCH splits | Warning only; does not block |
| Enable split fallback in benchmark | Separate policy choice |

---

## Regenerate artifacts

```bash
cd nexops-mcp
python scripts/investigate_split_structure.py
```

Outputs:

- `benchmark/results/structural_failures_split/<case>_final_draft.cash`
- `benchmark/results/structural_failures_split/<case>_analysis.json`
- `benchmark/results/structural_failures_split/summary.json`

---

## Conclusion

`bench_20260611_1344_cb95` did **not** fail because the LLM produced unrecoverable CashScript. It failed because **`_dangling_require` misclassifies standard multiline `require()` blocks** used for N-output conservation sums. Fixing this single checker is the highest-leverage change to move split compile rate above 50% without prompt, rail, or model changes.
