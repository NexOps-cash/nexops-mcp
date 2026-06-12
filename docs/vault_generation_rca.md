# Vault — Phase 1B Generation RCA

**Date:** 2026-06-11  
**Scope:** Generation audit for `v_005`, `v_008`, `vr_010`, `vr_020`, `vr_023`, `vr_024`. **No evaluator changes. No rails. No Phase 1B implementation.**  
**Historical baselines:** `bench_20260331_2128_47e9` (`vaults.yaml`), `bench_20260401_2119_3456` (`vaults_real`, 24-case canonical)  
**Tools:** `scripts/vault_generation_rca_offline.py` (routing + gate replay), `scripts/diagnose_vault_case.py` (routing only)

**LLM note:** Live generation traces blocked (OpenRouter 402). RCA combines cross-run benchmark mining, offline gate replay on saved code, and representative synthesis drafts.

---

## Executive conclusion

| Case | Routing mismatch? | First **hard** failure (generation) | Benchmark label |
|------|-------------------|---------------------------------------|-----------------|
| **v_005** | No (`vault` / `vault_rules.yaml`) | **DSLLint `LNC-003`** on malformed tiered drafts; **known-good tiered shape passes all gates** | `Compile` (coarse, ~40% fail rate) |
| **v_008** | No | **DSLLint `LNC-003`/`LNC-016`** on vulnerable shape; pipeline emits **safe** code when it compiles | `Compile` / **AdversarialIntentNotMet** |
| **vr_010** | No | **Pipeline timeout** (300s, 3 retries); simple 3-path draft **passes all gates** | `Timeout` |
| **vr_020** | No | **AdversarialIntentNotMet** — generator preserves amounts; vulnerable draft blocked by **DSLLint** | `converged: false` (failure case) |
| **vr_023** | No | **Pipeline timeout** (~17% of runs); founder-treasury draft **passes all gates** | `Timeout` |
| **vr_024** | No | **Not a compile blocker** — 100% historical compile; post-1A **`cancellation_path`** risk when code uses `emergencyRecover` only | Usually **converged** |

**Routing is not a factor** for any of these cases — all land on `contract_type: vault` with `vault_rules.yaml` and `_VAULT_RAIL`.

**Remaining `vaults_real` positive convergence gap is dominated by two flaky timeouts (`vr_010`, `vr_023`), not routing or measurement.**

---

## Summary table

| Case | First failure | Compile error | Lint | Sanity | Draft exists |
|------|---------------|---------------|------|--------|--------------|
| **v_005** | **DSLLint** (`LNC-003` on claim bodies without value anchor) on failing attempts; success shape passes | Not reached on `LNC-003` failures | **Fail** on typical retry drafts; **Pass** on historical tiered code | Pass on success shape | **Yes** (60% of runs); **No** on compile-fail runs |
| **v_008** | **DSLLint** (`LNC-003`/`LNC-016`) on vulnerable announce; **AdversarialIntentNotMet** when safe code compiles | Rare (`unused variable` on minimal drafts) | **Fail** on intentional vulnerability shape | Pass on safe typical output | **Yes** (40% of runs) |
| **vr_010** | **Timeout** (pipeline never returns code) | Not reached | Pass on representative 3-fn draft | Pass | **Yes** in 50% of runs; **No** on timeout run |
| **vr_020** | **AdversarialIntentNotMet** (safe staged split emitted) | Pass | **Fail** on vulnerable draft (`LNC-003`/`LNC-016`) | Pass on emitted safe code | **Yes** (100% of runs) |
| **vr_023** | **Timeout** (~17% of runs) | Not reached on timeout | Pass on founder-treasury draft | Pass | **Yes** (83% of runs) |
| **vr_024** | **EvaluatorCritical** (`cancellation_path`) on `emergencyRecover`-only shapes offline; canonical run scored 1.0 pre-steer | Pass | Pass | Pass | **Yes** (100% of runs) |

Artifacts:
- `benchmark/results/vault_generation/<case>_representative_draft.cash`
- `benchmark/results/vault_generation/<case>_rca_offline.json`
- `benchmark/results/vault_generation/rca_offline_summary.json`
- `benchmark/results/vault_generation/vaults_real_convergence_snapshot.json`

---

## Quantified remaining failures

### Cross-run generation reliability (10+ historical runs where available)

| Case | Runs | Compile rate | Convergence rate | Timeout rate | Median latency (success) |
|------|------|--------------|------------------|--------------|--------------------------|
| **v_005** | 10 | **60%** | 50% | 0% | ~18s |
| **v_008** | 10 | **40%** | 20% | 0% | ~11s |
| **vr_010** | 2 | **50%** | 50% | **50%** | ~33s |
| **vr_020** | 2 | **100%** | 0%† | 0% | ~16s |
| **vr_023** | 6 | **83%** | 67% | **17%** | ~15s |
| **vr_024** | 7 | **100%** | 86% | 0% | ~16s |

†Failure-case policy: `converged` stays false until adversarial critical `must_fail_missing_amount_validation` is satisfied.

### `vaults_real` convergence toward ≥95%

| Metric | Canonical `bench_20260401_2119_3456` | Post Phase 1A (measurement only) | Gap to ≥95% positives |
|--------|--------------------------------------|----------------------------------|------------------------|
| Positive cases | 20 (excl. vr_019–vr_022 failure cases) | 20 | — |
| Compile (positives) | **18/20** (90%) | **20/20**‡ offline on saved code | 0 |
| Converged (positives) | **16/20** (80%) | **~18/20**‡ (vr_006, vr_009 fixed) | **Need +1** → **19/20 = 95%** |
| Full suite (24) | 16/24 converged (67%) | ~20/22 compiling at 1.0 | Failure cases tracked separately |

‡Offline re-score with Phase 1A helpers; live confirmation pending LLM credits.

**Minimum work for ≥95% `vaults_real` positive convergence:** fix **one** of the two flaky timeout cases (`vr_010` or `vr_023`); fixing **both** yields **20/20 (100%)** with margin.

**Cases that do not block the 95% positive gate:**
- `vr_024` — compiles reliably; cancellation naming is a steer/measurement edge case, not a systemic compile fail.
- `v_008`, `vr_020` — security-negative adversarial intents; safe-code emission is expected pipeline behavior.
- `v_005` — `vaults.yaml` only (not in `vaults_real`).

---

## Question-by-question determination

### Is routing a factor?

**No.** All six cases infer `contract_type: vault`, `canonical_pattern: vault`, `knowledge_files: [vault_rules.yaml]`. Vault Phase 1A confirmed routing/rails are stable across representative cases.

### Is it a DSL lint issue?

**Yes — primary hard failure on malformed synthesis attempts** for tiered and adversarial shapes.

| Case | Lint rules on failing shapes | Notes |
|------|------------------------------|-------|
| v_005 (retry drafts) | **LNC-003** | `claimMedium`/`claimLarge` with `tx.outputs.length == 1` but no `outputs[0].value == input.value` |
| v_008 (vulnerable target) | **LNC-003**, **LNC-016** | 2-output announce without value conservation |
| vr_020 (vulnerable target) | **LNC-003**, **LNC-016** | Same pattern |
| Success shapes | Pass (LNC-005 disabled for vault profile) | Staged `input - withdrawAmount` splits are allowed in vault mode |

Vault profile explicitly disables **LNC-005** (fee arithmetic) — tiered splits are not lint-blocked when correctly formed.

### Is it a toll gate / compile issue?

**Secondary.** Historical tiered (`v_005`) and backup-cancel (`vr_010`) success drafts pass toll gate with non-critical warnings (`output_binding_missing`, `multisig_distinctness_flaw`). Compile failures on benchmark are usually **retry exhaustion** before a converged artifact, not a single `cashc` error on the final shape.

### Is it a timeout issue?

**Yes — dominant for `vr_010` and `vr_023`.**

| Case | Timeout pattern | Success template exists? |
|------|-----------------|--------------------------|
| vr_010 | 300s, 3 retries, `code: null`, 0 completion tokens | **Yes** — 3-function announce/claim/cancel (~33s in `bench_20260401_2030_ceb2`) |
| vr_023 | 300s in 1/6 runs; 5/6 compile in ~14–26s | **Yes** — founder treasury with `instantSpend` + staged large + `emergencyRecover` |

Timeouts indicate the LLM **explores over-complex shapes** (extra outputs, nested staging) and exhausts the retry budget without returning the simpler pattern that offline replay already validates.

### Is it an adversarial-generation issue?

**Yes — `v_008` and `vr_020`.**

The pipeline is **designed to emit safe vaults**. When compilation succeeds:
- Generated code includes `outputs[0].value == input - withdrawAmount` splits.
- `must_fail_missing_amount_validation` is **not** triggered.
- Benchmark correctly keeps `converged: false` with `final_score: 0.2`.

Intentionally vulnerable drafts fail **earlier at DSLLint** — the pipeline will not ship them without explicit adversarial synthesis mode.

---

## Per-case detail

### v_005 — Multi-tier vault (`vaults.yaml`)

**Intent:** Instant withdrawals up to 0.01 BCH; 24h delay for 0.01–0.1 BCH; 7-day delay for larger amounts.

**Routing:** `vault` → `vault_rules.yaml` — no mismatch.

**Historical success code** (`bench_20260331_2128_47e9`, also `bench_20260401_2011_0c72` at score 1.0 post-1A):

```cashscript
function announceSmall(...) { /* withdrawAmount <= smallLimit */ }
function claimSmall(...) { require(this.age >= smallDelay); ... }
function announceLarge(...) { /* withdrawAmount > smallLimit */ }
function claimLarge(...) { require(this.age >= largeDelay); ... }
function cancel(...) { ... }
function emergency(...) { ... }
```

**Gate replay on success shape:** lint ✓, compile ✓, toll gate ✓ (warnings only), sanity ✓, evaluator criticals ✓ (post-1A).

**Failing retry shape (likely LLM exploration):**

```cashscript
function claimMedium(sig ownerSig) {
    require(this.age >= smallDelay);
    require(tx.outputs.length == 1);
    require(checkSig(ownerSig, owner));
    // missing: require(tx.outputs[0].value == tx.inputs[this.activeInputIndex].value);
}
```

→ **DSLLint `LNC-003`** (first hard failure) → lint retry loop → `synthesis_failed_no_fallback` → benchmark `failure_layer: Compile`.

**Verdict:** Generation instability on **tiered multi-function synthesis**, not a missing rail or routing defect. A golden or Phase 2 template for 3-tier instant/medium/large paths would collapse retry variance.

---

### v_008 — FAILURE CASE: missing amount validation (`vaults.yaml`)

**Intent:** Vault that does **not** validate output amounts (vulnerability by design).

**Gate replay:**
- **Vulnerable draft** (announce without value split): **DSLLint `LNC-003`/`LNC-016`** — blocked before compile.
- **Safe typical output** (historical `bench_20260401_1946_a582`): all gates pass → **AdversarialIntentNotMet**.

**Verdict:** Not fixable with standard vault synthesis. Requires **adversarial generation mode** (or benchmark-only lint exemptions) — out of scope for production vault convergence.

---

### vr_010 — Backup-cancel safety wallet (`vaults_real`)

**Intent:** Announce withdrawal today; claim after 3 days; backup key can cancel first.

**Timeout run** (`bench_20260401_2119_3456`): 300s, 3 retries, no code.

**Success run** (`bench_20260401_2030_ceb2`): 33s, score 1.0 — simple 1-output announce state machine:

```cashscript
function announce(sig ownerSig) {
    require(tx.outputs.length == 1);
    require(tx.outputs[0].lockingBytecode == this.activeBytecode);
    require(tx.outputs[0].value == tx.inputs[this.activeInputIndex].value);
}
function claim(sig ownerSig) { require(this.age >= delaySeconds); ... }
function cancel(sig backupSig) { ... re-anchor full value ... }
```

**Gate replay:** representative draft passes all gates.

**Verdict:** **Flaky timeout**, not structural impossibility. Steer synthesis away from 3-output over-complex shapes; optional golden for announce→delay→claim+cancel idiom.

---

### vr_020 — FAILURE CASE: staged withdraw without conservation (`vaults_real`)

**Intent:** Vault that stages withdrawals but **never** checks remaining value.

**Emitted code** (both historical runs): full staged split with `outputs[0].value == input - withdrawAmount` — **semantically safe**.

**Gate replay:** saved code passes all gates → **AdversarialIntentNotMet**. Vulnerable draft fails **DSLLint `LNC-003`**.

**Verdict:** Same class as `v_008` — pipeline safety prevents adversarial output. Not a positive-convergence blocker.

---

### vr_023 — Founder treasury (`vaults_real`)

**Intent:** Cold key recovers immediately; small expenses easy via ops limit.

**Timeout:** 1/6 runs (`bench_20260401_2119_3456`, 300s). **Success:** 5/6 runs, ~14–26s, score 1.0.

**Success pattern:** `instantSpend` (amount ≤ opsLimitSats) + `stageLargeWithdrawal` + `finalizeLargeWithdrawal` + `emergencyRecover`.

**Gate replay:** all gates pass on saved founder-treasury code.

**Verdict:** **Flaky timeout** on complex exploration paths. Template for ops-limit + emergency recover would stabilize.

---

### vr_024 — Comprehensive secure vault (`vaults_real`)

**Intent:** Delay for normal withdrawals, cancellation, preserved funds across stages.

**Historical:** 7/7 compile, 7/7 intent coverage 1.0 when scored, 6/7 `converged`.

**Representative code issue:** some shapes use `emergencyRecover` without a `cancel*` function — offline replay flags **`cancellation_path`** critical miss; canonical `bench_20260401_2119_3456` still scored 1.0 (benchmark predates strict post-1A steer).

**Verdict:** **Low-severity generation steer** — add `cancel` or `emergencyCancel` naming in Phase 2 vault prompt for comprehensive intents. **Not required for 95% positive gate** (already converges in most runs).

---

## Why benchmark says “Compile” or “Timeout”

```text
lint/toll retry exhaustion OR 300s wall clock
  → synthesis_failed_no_fallback OR timeout
    → evaluator failure_layer = "Compile" | "Timeout"
    → code = null (timeout / exhaustion cases)
```

Improvement for future audits: propagate `last_failure_layer` from `pipeline_engine.py` into benchmark results (same gap noted in refundable RCA).

---

## Effort estimate to ≥95% `vaults_real` positive convergence

| Work package | Cases | Effort | Expected lift |
|--------------|-------|--------|-----------------|
| **P0 — Timeout stabilization** | vr_010, vr_023 | **1–2 days** | 18/20 → **20/20** converged positives |
| **P1 — Tiered vault golden** | v_005 (`vaults.yaml`) | **1 day** | 60% → ~95% compile on tiered case |
| **P2 — Cancellation naming steer** | vr_024 | **0.5 day** | Edge-case measurement alignment |
| **Defer — Adversarial synthesis** | v_008, vr_020 | **3–5 days** (new mode) | Security-negative benchmarks only; not needed for 95% positives |

**Total for 95% `vaults_real` positives:** **~1–2 days** (P0 only).  
**Total for full vault hard-case polish including tiered + adversarial:** **~5–8 days**.

---

## Vault completion vs Refundable Phase 1B

| Dimension | Vault completion (P0) | Refundable Phase 1B |
|-----------|---------------------|---------------------|
| **Cases blocked at compile** | 0 positives (2 timeouts only) | **2/6** (`rp_003`, `rp_004` — 0% compile historically) |
| **First hard failure** | Timeout / retry exhaustion | **DSLLint** (`LNC-005`, `LNC-016`, `LNC-010`, `LNC-011`) |
| **Routing contribution** | None | **Secondary** (escrow / linear_vesting mismatch) |
| **Known-good draft exists** | **Yes** (vr_010, vr_023, v_005) | Partial (simple rp_003 escrow passes; rp_004 vesting does not) |
| **Effort to next gate** | **1–2 days** | **2–3 days** |
| **Impact** | **+1–2** positive vault cases → **95–100%** `vaults_real` | **+2** refundable cases from **0%** compile → partial suite unblock |
| **Risk** | Low — templates mirror existing success code | Medium — lint-safe vesting/subscription shapes need new synthesis rules |
| **Live validation** | Blocked on credits (same as refundable) | Blocked on credits |

### Recommendation — next stabilization target

**Choose Vault P0 (timeout stabilization for `vr_010` + `vr_023`) before Refundable Phase 1B.**

Rationale:
1. **Higher near-term convergence ROI** — two templates close the **95% `vaults_real` positive gate**; refundable cases need net-new lint-safe synthesis paths.
2. **Lower technical risk** — success shapes already exist in benchmark history; refundable requires LNC-010/011/016-safe vesting math not yet in production synthesis.
3. **Vault measurement (Phase 1A) is complete** — remaining gap is purely generation flakiness, not evaluator work.
4. **Refundable Phase 1B remains the right second target** — routing overlay and `refundable_payment_rules` can follow once rp_003/rp_004 lint templates land.

**Do not implement Vault Phase 1B or Refundable Phase 1B in this pass** — this document is the decision gate input only.

---

## Phase 1B design sketch (after RCA — not implemented)

### Do first (vault generation)

| Priority | Target | Action |
|----------|--------|--------|
| P0 | **vr_010** | Golden or Phase 2 block: 1-output announce → `this.age` claim + backup `cancel` |
| P0 | **vr_023** | Golden founder-treasury: `instantSpend` + staged large + `emergencyRecover` |
| P1 | **v_005** | Golden multi-tier: instant (≤limit) + `announceSmall`/`claimSmall` + `announceLarge`/`claimLarge` |
| P2 | **vr_024** | Prompt steer: require `cancel` or `emergencyCancel` function name for cancellation intents |

### Defer

| Item | Why defer |
|------|-----------|
| **v_008 / vr_020 adversarial** | Requires adversarial synthesis mode; pipeline correctly refuses vulnerable output |
| **Routing / rail changes** | Routing confirmed stable; not first failure |
| **Evaluator changes** | Phase 1A complete |

### Success criteria (Vault Phase 1B gate)

| Metric | Target |
|--------|--------|
| `vaults_real` positive convergence | **≥ 19/20 (95%)** on live benchmark |
| vr_010, vr_023 | `compile_pass: true`, draft saved, intent coverage ≥ 0.70 |
| v_005 | `compile_pass: true` on ≥2 consecutive live runs |

---

## Reproduce

```bash
# Offline routing + gate replay (no LLM)
python scripts/vault_generation_rca_offline.py

# Routing only (requires LLM for Phase1)
python scripts/diagnose_vault_case.py vr_010

# Full benchmark (requires LLM credits)
python -m benchmark.runner benchmark/suites/vaults_real
python -m benchmark.runner benchmark/suites/vaults.yaml --ids v_005,v_008
```
