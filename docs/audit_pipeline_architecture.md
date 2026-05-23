# NexOps audit & synthesis pipeline — architecture report

Accuracy target: codebase as of the Wave 1 stabilization work (`GuardedPipelineEngine`, `BenchmarkEvaluator`, `AuditAgent`, `Phase3`, `DSLLinter`, TollGate-related modules). Paths are relative to **`nexops-mcp/`**.

---

## 1. Current pipeline architecture (exact execution flow)

### 1.1 Synthesis pipeline (`GuardedPipelineEngine.generate_guarded`)

Primary orchestrator: **`src/services/pipeline_engine.py`**.

| Order | Stage | Deterministic vs LLM | Input artifact | Gates on compile? |
|-------|--------|---------------------|----------------|-------------------|
| 1 | **Phase 1 — intent** (`Phase1.run`) | **LLM** (JSON → `IntentModel` + `ContractIR`) plus deterministic routing/normalization in `pipeline.py` | Raw user `intent` string | No |
| 2 | **Phase 2 draft** (`Phase2.run`) | **LLM** (CashScript source) | `ContractIR`, optional prior `ViolationDetail[]`, retry count | No |
| 3 | **Language guard** | **Deterministic** (regex forbid-list) | Raw source string | No |
| 4 | **DSL lint** (`DSLLinter.lint`) | **Deterministic** (regex + heuristic function bodies on **source text**) | Raw source string | No |
| 5 | **Compile gate** (`CompilerService.compile` → **`cashc` subprocess**) | **Deterministic** tool; inner **syntax repair** mixes **deterministic micro-fixes** + **LLM** (`_request_syntax_fix`) | Raw source string → compiler stderr/structured error | Lint + language guard must pass to reach compile; Phase 3 waits for **compile success** |
| 6 | **Phase 3 Toll Gate** (`Phase3.validate`) | **Deterministic** (anti-pattern detectors over **`CashScriptAST`**) | Raw source parsed to internal AST abstraction | **Yes — only after compile success** |
| 7 | **Phase 4 Sanity** (`SanityChecker.validate`) | **Deterministic** (regex/feature evidence vs `IntentModel`) | Raw source string | Yes (after Toll Gate) |
| 8 | **Fallback** (if not `disable_fallbacks`) | Canonical `.cash` file read | N/A | Fallback code is validated with Phase 3 |

**Repair / regen:**

- **Lint loop:** deterministic violations → injected into Phase 2 retry; stuck-lint breaker can skip to compile with guardrails; structurally invalid code forces **hard regen** (state cleared).
- **Compile repair:** `_request_syntax_fix`: structural validation + `save_repair_cycle` logs under `benchmark/results/repair_debug/` (gitignored); corrupt LLM output → reject, **abort fix loop**, **full regeneration**.
- **Semantic “repair”** in synthesis = **retry Phase 2 / full gen** with violation feedback — not `RepairAgent` unless user hits `/api/repair`.

There is **no separate “benchmark semantic evaluator”** inside the guarded engine. **`BenchmarkEvaluator`** wraps `generate_guarded` and applies **offline scoring** after success (§4).

### 1.2 Audit pipeline (`AuditAgent`)

Orchestrator: **`src/services/audit_agent.py`** (invoked by API / tooling).

Rough order (**compile failure still runs lint & toll-derived issues**, but skips LLM semantic audit):

1. **`cashc`** — compile → `compile_success`; on failure emits `AuditIssue` (mapped severities/classes).
2. **DSL lint** — same `DSLLinter` as synthesis (generation path historically may pass `effective_mode`; audit uses caller’s mode).
3. **`validate_audit`** — **`src/services/audit_engine/audit_phase.py`**: parse with `CashScriptAST`, **`audit_lint`** + **`AuditEnforcer`** (parallel **audit detector** registry — not identical file-for-file to synthesis `DETECTOR_REGISTRY` but same family).
4. **LLM semantic classification** (`SEMANTIC_SYSTEM_PROMPT`) — **only if `compile_success`**; produces category + confidence, fed into **`calculate_audit_report`**.

Audit does **not** use `Phase3.validate` directly — it uses **`validate_audit`** (audit-specific lint + enforcer assembly).

### 1.3 Benchmark runner

- **`benchmark/runner.py`**: loads YAML cases, holds `BenchmarkRunner.engine` (`get_guarded_pipeline_engine()`), delegates per-case scoring to **`benchmark/evaluator.py`** (`BenchmarkEvaluator.evaluate` → **`generate_guarded`**).
- **`scripts/run_semantic_benchmark.py`**: thin sequential runner over the semantic suite + checkpoint.

### 1.4 API entrypoints

See **`src/server.py`**: generation, **`/api/audit`**, **`/api/repair`**, **`/api/edit`**, etc. Repair path uses **`RepairAgent`** (`src/services/repair_agent.py`) — orthogonal to guarded synthesis compile repair.

---

## 2. TollGate / security engine (synthesis `Phase3`)

Implementation: **`src/services/pipeline.py`** → **`Phase3.validate(code, contract_mode)`**.

### 2.1 How anti-patterns are represented

- **Documentation**: `knowledge/anti_pattern/*.cash` files — human-readable vulnerability notes only.
- **Enforcement**: **`src/services/anti_pattern_detectors.py`** — **`Detector`** classes implementing **`detect(ast: CashScriptAST) -> Violation | None`**.
- Representation is **semantic over AST**: traversals, mode-aware branches (`contract_mode` on AST), supplemental **`InvariantEngine(ast).analyze()`** used in audit enforcer variant (generation enforcer focuses on detectors).

Phase 3 aggregates:

1. **`AntiPatternEnforcer.validate_code`** → list of violations with `rule`, `reason`, `exploit`, `severity`, …
2. **`structural_score`** — coarse ratio `(len(DETECTOR_REGISTRY) − unique_failed_rule_count) / len(DETECTOR_REGISTRY)` in `pipeline.py` (same rule id collapsing multiple detectors).
3. **Gate**: **`passed` iff no violation with `severity == "critical"`** (high/medium/low do **not** block convergence).

### 2.2 Finding types

**Hybrid.** Examples:

| Type | Examples |
|------|----------|
| Syntactic / structural misuse | Hardcoded indices, tautological guards (still expressed via AST) |
| Semantic (UTXO / covenant) | Output binding, covenant continuation, implicit ordering |
| Heuristic | `authorization_model_classifier` (often INFO / non-blocking in audit mapping) |

### 2.3 Severity / confidence

- **Generation TollGate**: violations carry **`severity`** string; **only `critical` blocks**.
- **Audit path**: TollGate violations mapped to **`AuditIssue`** with `_severity_from_string`, **`issue_class`**, **`exploit_severity`**; non-exploitable HIGH may be downgraded; **`authorization_model_classifier` + INFO** → **`NOISE`**.

Confidence for **risk scoring** appears in **`calculate_audit_report`** semantic bucket (**LLM** `confidence`), not inside Phase 3.

### 2.4 False-positive suppression

- **`pattern_profiles`**: **`disable_detectors`**, **`disable_lint_rules`** per `contract_mode`.
- **`audit_agent`**: exploitable heuristic, downgrade rules, `deferred_validation` for parser/missing-artifact modes.
- **`audit_enforcer`**: filters auth classifier to metadata-only in some flows.

### 2.5 CashTokens in TollGate

There is **no separate “CashToken type system” inside Phase 3**. CashToken behavior emerges from:

- **`contract_mode`** (`nft_transfer_immutable`, `ft_transfer`, `hybrid_token`, …) wired from **`IntentModel.contract_type`**,
- Detectors such as **`TokenPairValidationDetector`**, **`MintingAuthorityEscapeDetector`**, **`CovenantContinuationDetector`**, **`OutputBindingDetector`**, **`WeakOutputLimitDetector`**, **`CommitmentLengthSafetyDetector`**,
- Profile-driven disables for fragile modes.

Topics you asked:

| Topic | Mechanism |
|-------|-----------|
| Authority leakage | e.g. **`MintingAuthorityEscapeDetector`** (0x02 without custody), multisig detectors, authorization classifier (soft) |
| Covenant persistence | **`CovenantContinuationDetector`**, DSL **LNC-008**, **LNC-016**, five-point heuristic **LNC-025** (warning) |
| `tokenCategory` continuity | **`TokenPairValidationDetector`**, DSL **LNC-014**, **LNC-018**, **LNC-020** |
| `tokenAmount` conservation | Pair rules with category (**LNC-014**), AST token pair detector, **five-point covenant** heuristic |
| Mutable NFT reanchor | Covenant / hybrid detectors + DSL **LNC-020**, **capability_byte_match LNC-022** (warnings), **lifecycle_lint LNC-026/LNC-027** in DSL |

---

## 3. DSL linter internals

Module: **`src/services/dsl_lint.py`** (`DSLLinter`).

### 3.1 Regex vs AST

**Almost entirely regex + `_function_bodies`** (brace-depth scan of **`function foo(...) {`** blocks — not a full CashScript grammar). **`semantic`** and **`contract_mode`** parameters tune rules.

There is **no separate AST pass** inside `DSLLinter`.

### 3.2 LNC rule representation

- Each rule = Python function **`_check_*`** returning **`list[{"rule_id", "message", "line_hint", "severity?"}]`**.
- **`DSLLinter.RULES`** is the ordered registry.
- **Blocking** vs **warning**: default blocking unless violation dict sets **`"severity": "warning"`**.
- **`get_pattern_profile(contract_mode)["disable_lint_rules"]`** can disable rule **prefixes**.

### 3.3 Control flow / I/O relationships

Limited: **per-function body** substring analysis, optional output-length guards (LNC-001c), coupling heuristics (LNC-004). **No true CFG.**

### 3.4 CashTokens semantics in lint

Partial: rules inspect **`.tokenCategory` / `.tokenAmount` / `.nftCommitment` / `this.activeBytecode`** in text.

**Semantic dict** passes **`ownership_mode`**, **`lifecycle_mode`**, **`supply_mode`**, **`commitment_schema`** into **`_check_value_anchoring`** (termination escape), **`_check_token_pair_completeness`** (LNC‑014 skips burn/redeem with `supply_mode`), **`_check_token_mint_supply_enforcement`** (LNC‑017), **`_check_nft_commitment_preservation`** (LNC‑020), **`_check_semantic_lifecycle_rules`** → **`lifecycle_lint.py`**.

Examples:

```text
LNC-014: If a function mentions .tokenCategory or .tokenAmount, require BOTH in that function (exceptions for burn/redeem / burnable,redeemable supply).
LNC-015: LockingBytecodeP2PKH/P2SH args must be hash160(...), literal bytes20, or param name suffix hash|pkh|lock|bytecode.
Lifecycle: LNC-026 soulbound external transfer forbidden; LNC-027 hybrid + state needs checkSig; terminating payout self-anchor hints (warnings).
```

---

## 4. Semantic evaluator / benchmark engine

Module: **`benchmark/evaluator.py`**, extractor **`benchmark/feature_extractor.py`**, rules **`benchmark/config/feature_rules.yaml`**.

### 4.1 `required_features` / `critical_features`

Both go through **`requirement_satisfied(req)`**:

1. **Capability map** (regex-derived flags + `detected` feature strings from **`FeatureExtractor`**).
2. **Special-case** token validation:** redeemable category-zero burn (**regex on source**).
3. **Pattern aliases:**
   - `semantic_*` → **`_semantic_alias_pool`** (heavy **regex over full `code` string**, plus booleans from capabilities).
   - CashToken patterns → **`_cashtoken_alias_pool`**.

Matching is **not AST** and **not deep auth reasoning** — it is **tag + regex alias** scoring.

### 4.2 Convergence (**Tier B**) scoring

Benchmark **`converged`** (production-oriented) requires (**all must hold**):

- `compile_pass` and **not** `fallback_used`
- `intent_coverage >= 0.70` (fraction of **`required_features` matched`)
- **`critical_features`** list all satisfied via same `requirement_satisfied`
- **`semantic_pass`**: heuristic rules over **`FeatureExtractor`**’s naive function roles (**INTERMEDIATE** must include `this.activeBytecode` anchor; **TERMINAL** must not) — vault-only relaxation flag exists
- Failure/vuln cases with `must_fail_*` criticals handled specially

**`final_score`** mixes compile, lint factor from weights YAML, intent coverage, critical missing penalty — used for ranking, not deployment.

### 4.3 Can the evaluator reason about unauthorized paths?

**Limited.** It can infer:

- **Missing `checkSig` / multisig**: only indirectly via extractor patterns or alias pools (e.g. `valid_signature_check` from capability).
- **Unrestricted migration / state continuity**: aliases like **`migratory_locking_bytecode`**, **`covenant_self_reference`** use **substring / regex**, not exhaustive path enumeration.

Treat benchmark semantics as **regression telemetry**, not a proof of absence of exploits.

---

## 5. CashTokens representation layer

Stored on **`IntentModel`** (`src/models.py`):

- **`contract_type`**, **`features[]`**, **`token_class`** (`ft` | NFT classes | …), **`nft_capability`** (`none` | `mutable` | `minting`), BCMR-ish fields (**`expected_category`**, **`requires_commitment`**, …).
- **`apply_cashtoken_intent_routing()`** / normalization in **`src/services/pipeline.py`** and **`semantic_normalization.py`** steers **`contract_type`** and token class from keywords.

Capability distinction (**+0x01 / +0x02**) is **not modeled as enums** beyond **`nft_capability`** and **lint/rules** referencing **`split(32)`** /**`+ 0x01`** patterns.

There is **`ContractIR`** for generation — **no single normalized “protocol IR”** shared by compiler and evaluator; evaluator sees **final source string**.

---

## 6. Semantic constraint system (Wave 1)

| Concern | Location |
|---------|----------|
| Storage | **`IntentModel`**: **`ownership_mode`**, **`lifecycle_mode`**, **`supply_mode`**, **`commitment_schema`** (validated/coerced enums) |
| Conflict resolution | **`resolve_semantic_constraints()`** in **`semantic_profiles.py`** |
| Rails injection | **`semantic_rail_blocks(intent_model)`** appended via **`build_pattern_rails(..., intent_model=intent_model)`** in **`pipeline.py`** |
| Deterministic normalization | **`apply_semantic_normalization`** after Phase 1 routing in pipeline |
| Phase 2 freedom | Still **large** — rails + DSL rules + anti-pattern context constrain but **do not mechanically synthesize**; LLM emits full `.cash`. |

Rails examples (**`semantic_profiles.py`**): soulbound containment, terminating vs migratory, burnable/redeemable hints, capped mint, marketplace 2‑party bolt-on, expiry/governance snippets.

---

## 7. Compile repair system

**Entry:** **`GuardedPipelineEngine._request_syntax_fix`** (`pipeline_engine.py`).

1. Runs **`apply_deterministic_micro_fixes`** from **`structural_integrity.py`** (unused vars, timelock shape, bytes32 body-only substitution, **`new LockingBytecodeP2PKH`**, safe single `}`, token recognition quirks).
2. If structure still invalid → **save debug JSON**, return **`(pre_code, aborted=True)`** → outer loop **forces regen**.
3. If structure valid → **LLM fix** (`LLMFactory` task **`fix`**), **`_extract_cash_code`**; post-parse structure check; on failure revert and abort.

**Orchestration decisions:**

| Situation | Action |
|-----------|--------|
| Lint blocking + retries exhausted | **Full regeneration** (context cleared when invalid structure) |
| Compile fails after micro-fix attempts | Retry LLM fix while valid structure; else **regen** |
| All gen attempts exhausted | **Fallback template** (**unless `disable_fallbacks`**) |

---

## 8. Report / confidence system

### 8.1 Aggregation

**`calculate_audit_report`** (`src/services/scoring.py`) combines:

- **Deterministic bucket (0–70)**: compile success gates base; deductions via severity × **issue_class** × **exploit_severity** multipliers; `semantic_*` rule ids zeroed from deterministic deductions; **`deferred_validation`** zeros penalty.
- **Semantic bucket (0–30)**: structured category map + **`business_logic_score`** (audit LLM), capped; **`funds_unspendable`** forces semantic 0.

**Deployment gate (**`deployment_allowed`**):

```python
det_score >= 50 and semantic_score > 0 and display_score >= 75
```

(`display_score = max(20, total_score)`).

There is **`semantic_confidence`** in **`AuditMetadata`** — **no first-class separate “compile confidence”** beyond compile success flags / toolchain neutrality.

### 8.2 Compile-failed audits

Emitted as **`AuditIssue`** (`compile_*` rule IDs) **HIGH/CRITICAL** depending on error class; deterministic score collapses (**0**) except toolchain-error neutral score; LLM semantic step **skipped**.

---

## 9. Current biggest weaknesses (engineering view)

1. **Benchmark / evaluator shallowness**: regex-heavy **`_semantic_*`** aliases and **`FeatureExtractor`** function-role regex — easy false pass/fail vs real protocol behavior.
2. **Cross-function / multi-path reasoning**: TollGate detectors improved but **no systematic path-sensitive model** across all spends.
3. **Temporal semantics**: time locks age vs `tx.time` — partial enforcement; LLM hallucination still possible before lint catches it.
4. **Repair / codegen coupling**: synthesis still depends on LLM for most syntax fixes; structural gate reduces corruption but **does not eliminate** bad economics logic.
5. **CashTokens invariant coverage**: split between DSL (token pair, custody) and AST detectors — **gaps remain** for edge multi-output swaps, delegated paths, BCMR/off-chain commitments.
6. **Multi-contract / sidecar blindness**: consciously deferred; prompts even cap semantic confidence when certain identifier patterns appear (**`audit_agent`**).
7. **Duplication drift risk**: **`AntiPatternEnforcer`** vs **`AuditEnforcer`**, **`Phase3`** vs **`validate_audit`** — similar ideas, two code paths.

---

## 10. Codebase map (rough tree)

```
nexops-mcp/
├── benchmark/
│   ├── evaluator.py          # BenchmarkEvaluator, alias pools
│   ├── runner.py             # Loads suites, invokes evaluator
│   ├── schemas.py             # BenchmarkCase fields
│   ├── config/
│   │   ├── feature_rules.yaml # Regex feature detectors
│   │   └── scoring_weights.yaml
│   └── suites/*.yaml          # Case definitions (semantic, family)
├── docs/
│   ├── audit_pipeline_architecture.md  # (this file)
│   ├── cashtokens_semantic_layers.md
│   └── semantic_005_008_investigation.md
├── scripts/
│   ├── run_semantic_benchmark.py
│   └── diagnose_semantic_case.py
├── src/
│   ├── server.py                      # REST / MCP-ish entry
│   ├── models.py                       # IntentModel, ContractIR, AuditReport
│   ├── utils/cashscript_ast.py         # AST wrapper for detectors
│   └── services/
│       ├── pipeline.py                 # Phase1–3, build_pattern_rails, Phase2
│       ├── pipeline_engine.py          # Guarded synthesis orchestration ⭐
│       ├── dsl_lint.py                  # DSLLinter (LNC-*) ⭐
│       ├── lifecycle_lint.py            # LNC-026/027 semantic hooks from DSL
│       ├── semantic_normalization.py    # Keyword → semantic fields
│       ├── semantic_profiles.py         # resolve + rail blocks ⭐
│       ├── structural_integrity.py       # Structural validation / repair telemetry
│       ├── language_guard.py
│       ├── compiler.py                   # cashc subprocess
│       ├── sanity_checker.py             # Phase4 regex heuristic
│       ├── anti_pattern_enforcer.py     # Loads docs + runs detectors ⭐
│       ├── anti_pattern_detectors.py     # Detector registry ⭐
│       ├── audit_agent.py               # Full audit orchestration ⭐
│       ├── audit_engine/
│       │   ├── audit_phase.py          # validate_audit (parse + lint + enforce)
│       │   ├── audit_enforcer.py
│       │   ├── audit_detectors.py
│       │   └── audit_lint.py
│       ├── scoring.py                   # calculate_audit_report ⭐
│       ├── pattern_profiles.py         # Mode → disable detectors/lint
│       ├── repair_agent.py             # User-initiated surgical repair
│       └── llm/factory.py              # Providers by task_type
├── knowledge/anti_pattern/*.cash       # Vulnerability narratives (detector docs only)
├── tests/
│   ├── test_structural_integrity.py
│   ├── test_suite areas (audit_engine/, cashtokens/, ...)
│   └── fixtures/structural_corruption/
└── benchmark/results/                   # Outputs (often gitignored)
```

---

### Quick ASCII flow (synthesis)

```
intent
  → Phase1 (LLM + deterministic routing/normalization → IntentModel)
  → Phase2 (LLM → .cash)
  → LanguageGuard (deterministic regex)
  → DSLLinter (deterministic)
  → cashc compile + structural repair loop (deterministic + LLM)
  → Phase3 TollGate AntiPatternEnforcer(AST) (deterministic)
  → SanityChecker (deterministic regex)
  → success | regen | fallback
```

Quick ASCII flow (**audit**, distinct stack):

```
.cash → cashc → DSLLinter → validate_audit(AST + audit detectors) → [LLM semantic if compiled] → calculate_audit_report
```

---

*If you extend this doc, link new detection rules to both **LNC-ID** (DSL), **rule id strings** (TollGate/audit), and **benchmark feature names** to avoid terminology drift.*
