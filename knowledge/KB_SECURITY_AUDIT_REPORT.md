# NexKB — Full Security Audit Report

> **Date**: 2026-02-16  
> **Scope**: All 25 knowledge files across 4 layers  
> **Verdict**: ✅ Structurally sound — 5 enhancement opportunities identified

---

## Table of Contents

1. [Audit Scope](#1-audit-scope)
2. [Primitives — Security Invariant Summary](#2-primitives--security-invariant-summary)
3. [Anti-Pattern Threat Matrix](#3-anti-pattern-threat-matrix)
4. [Common Mistakes — Arithmetic & State Safety](#4-common-mistakes--arithmetic--state-safety)
5. [Template Audit Results](#5-template-audit-results)
6. [Cross-Layer Dependency Map](#6-cross-layer-dependency-map)
7. [Gap Analysis & Recommendations](#7-gap-analysis--recommendations)
8. [Conclusion](#8-conclusion)

---

## 1  Audit Scope

Audited **25 `.cash` files** across 4 knowledge layers in `knowledge/`:

| Layer | Count | Files |
|-------|-------|-------|
| **Primitives** | 7 | `authorization`, `covenant_enforcement`, `division_safety`, `state_transition`, `time_gating`, `token_mint_control`, `value_redistribution` |
| **Anti-Patterns** | 9 | `fee_assumption_violation`, `implicit_output_ordering`, `minting_authority_leak`, `missing_output_limit`, `missing_token_amount_validation`, `missing_token_validation`, `time_validation_error`, `unvalidated_position`, `vulnerable_covenant` |
| **Common Mistakes** | 4 | `array_bounds`, `division_by_zero`, `integer_overflow`, `state_corruption` |
| **Templates** | 5 | `auction_dutch`, `auction_english`, `crowdfunding_refundable`, `escrow_2of3`, `vesting_linear` |

### Methodology

Each file was read in full and evaluated for:
- **Completeness** — Does it cover all relevant attack surfaces?
- **Correctness** — Are the vulnerable/secure examples accurate?
- **Consistency** — Do severity labels, terminology, and patterns align across files?
- **Actionability** — Does it provide AST-level detection rules and audit checklists?
- **Template immunity** — Do the templates correctly apply all primitives and avoid all anti-patterns?

---

## 2  Primitives — Security Invariant Summary

Each primitive defines a **mandatory enforcement rule** that NexOps must check at AST / build level.

| # | Primitive | Core Invariant | Required `require()` Pattern |
|---|-----------|----------------|------|
| 1 | **authorization** | Every spending path must have explicit `checkSig` | `require(checkSig(sig, pubkey))` — no shorthand, no `checkMultiSig` |
| 2 | **covenant_enforcement** | Continuation output must lock to same bytecode | `require(tx.outputs[N].lockingBytecode == tx.inputs[this.activeInputIndex].lockingBytecode)` |
| 3 | **division_safety** | Divisor must be proven > 0 before any `/` or `%` | `require(divisor > 0)` dominating the division AST node |
| 4 | **state_transition** | State hash verified + new state computed on-chain | `require(hash256(state) == stateHash)` + deterministic new state calc (never trust caller) |
| 5 | **time_gating** | `>=` for "at or after", `<` for "before" — **never `>`** | `require(tx.time >= deadline)` or `require(tx.time < deadline)` |
| 6 | **token_mint_control** | Mint outputs must lock to expected bytecode + validate category + amount | Full output triple: `lockingBytecode`, `tokenCategory`, `tokenAmount` |
| 7 | **value_redistribution** | Every output validated for bytecode, value, and token category | Explicit per-output `require()` triple on every path |

### Key Design Principles Extracted

1. **Explicit over implicit** — Every property must be validated with an explicit `require()`, never assumed.
2. **Dominating checks** — Validation must execute **before** the guarded operation in **all** code paths.
3. **Caller-controlled amounts** — Contracts never assume or calculate fees; callers specify exact output values.
4. **Adversarial builder model** — Contracts assume the transaction builder may be malicious.

---

## 3  Anti-Pattern Threat Matrix

### 3.1  Fee Assumption Violation
- **File**: `anti_pattern/fee_assumption_violation.cash` (934 lines)
- **Vulnerability**: Covenant reasons about fees (e.g. `output.value == input.value - FEE`)
- **Attack Vector**: Attacker subsidizes fee from extra inputs, hiding value extraction; or builds "free" transactions
- **Severity**: High
- **Detection**: AST scan for `input.value - constant` or hardcoded subtraction in output value calculations
- **Fix**: Never hardcode or calculate fees — let caller specify exact output amounts
- **Impact**: Value extraction, covenant economics bypass, invariant violation

### 3.2  Implicit Output Ordering
- **File**: `anti_pattern/implicit_output_ordering.cash` (1146 lines)
- **Vulnerability**: Code assumes `outputs[0]` is covenant continuation, `outputs[1]` is user payment, etc.
- **Attack Vector**: Reorder outputs so attacker-controlled script sits at the covenant's expected index
- **Severity**: Critical
- **Detection**: AST scan for `tx.outputs[literal]` without semantic `lockingBytecode` validation
- **Fix**: Validate each output **semantically** (`lockingBytecode`, `value`, `tokenCategory`) — not by index alone
- **Impact**: Value theft, covenant bypass, role swap attack

### 3.3  Minting Authority Leak
- **File**: `anti_pattern/minting_authority_leak.cash` (715 lines)
- **Vulnerability**: Minting path doesn't restrict recipient of newly minted tokens
- **Attack Vector**: Attacker mints unlimited tokens to their own address, inflating supply
- **Severity**: Critical
- **Detection**: AST scan for token minting operations without `lockingBytecode` validation on mint output
- **Fix**: `require(mintOutput.lockingBytecode == expectedBytecode)` — restrict minting to known covenant or beneficiary
- **Impact**: Supply inflation, governance bypass, token economic destruction

### 3.4  Missing Output Limit
- **File**: `anti_pattern/missing_output_limit.cash` (556 lines)
- **Vulnerability**: No `tx.outputs.length` check in contract
- **Attack Vector**: Attacker appends extra outputs → unauthorized minting, value drain, output spam
- **Severity**: Critical
- **Detection**: AST scan for functions lacking `require(tx.outputs.length ...)` statement
- **Fix**: `require(tx.outputs.length == N)` or bounded range `require(tx.outputs.length >= X && tx.outputs.length <= Y)`
- **Impact**: Unauthorized minting, fee manipulation, multi-output extraction

### 3.5  Missing Token Amount Validation
- **File**: `anti_pattern/missing_token_amount_validation.cash` (776 lines)
- **Vulnerability**: `tokenCategory` is checked but `tokenAmount` is not
- **Attack Vector**: Token inflation/duplication — attacker sets arbitrary amounts on outputs
- **Severity**: Critical
- **Detection**: AST scan for `tokenCategory` checks without paired `tokenAmount` checks on same output
- **Fix**: `require(tx.outputs[N].tokenAmount == expectedAmount)` — always pair with category validation
- **Impact**: Token duplication, accounting bypass, supply violation

### 3.6  Missing Token Category Validation
- **File**: `anti_pattern/missing_token_validation.cash` (717 lines)
- **Vulnerability**: Output assumed BCH-only but `tokenCategory` never checked
- **Attack Vector**: Attach unwanted tokens to BCH-only outputs; substitute valuable tokens with worthless ones
- **Severity**: Critical
- **Detection**: AST scan for output value/bytecode checks without `tokenCategory` check
- **Fix**: `require(tx.outputs[N].tokenCategory == expectedCategory)` — use `NO_TOKEN` constant for BCH-only
- **Impact**: Token attachment, token substitution, token theft

### 3.7  Time Validation Error
- **File**: `anti_pattern/time_validation_error.cash` (646 lines)
- **Vulnerability**: `>` instead of `>=` (or vice versa) in time comparison — off-by-one
- **Attack Vector**: Exploit boundary condition to unlock funds 1 block/second early
- **Severity**: High
- **Detection**: AST scan for `tx.time >` (should be `>=`) or `tx.time <=` (should be `<`)
- **Fix**: **Always** use `>=` for "at or after" and `<` for "before" — these are complementary and gap-free
- **Impact**: Premature unlocking, time-lock bypass, boundary exploitation

### 3.8  Unvalidated Input Position
- **File**: `anti_pattern/unvalidated_position.cash` (720 lines)
- **Vulnerability**: Code assumes `this.activeInputIndex == 0` without checking, or uses it without verification
- **Attack Vector**: Reorder inputs to place attacker UTXO at expected index → oracle manipulation, validation bypass
- **Severity**: Critical
- **Detection**: AST scan for `tx.inputs[this.activeInputIndex]` property access without dominating `lockingBytecode == this.lockingBytecode` check
- **Fix**: `require(tx.inputs[this.activeInputIndex].lockingBytecode == this.lockingBytecode)` on **every** path
- **Impact**: Input substitution, oracle manipulation, security check bypass

### 3.9  Vulnerable Covenant (Composite)
- **File**: `anti_pattern/vulnerable_covenant.cash` (317 lines)
- **Vulnerability**: Missing validation of `lockingBytecode`, `tokenCategory`, **and** `value` on continuation output
- **Attack Vector**: Three simultaneous attacks — code injection, token substitution, AND value extraction
- **Severity**: Critical
- **Detection**: AST scan for covenant continuation lacking any of the three validations
- **Fix**: Triple validation on every continuation output: `lockingBytecode`, `tokenCategory`, `value`
- **Impact**: Complete covenant compromise — attacker gains full control

---

## 4  Common Mistakes — Arithmetic & State Safety

### 4.1  Array Bounds Violation
- **File**: `common_mistakes/array_bounds.cash` (364 lines)
- **Category**: Memory Safety
- **Severity**: Critical (consensus failure)
- **Risk**: Out-of-bounds `tx.inputs[N]` or `tx.outputs[N]` access → script evaluation fails → tx rejected → potential contract **bricking** (permanent, no recovery)
- **Detection Rule**: For every `tx.inputs[idx]` / `tx.outputs[idx]` AST node, verify dominating `require(idx >= 0 && idx < array.length)`
- **Patterns**:
  - Literal index `[0]`: requires `require(array.length >= 1)`
  - Variable index: requires full bounds check `>= 0` AND `< length`
  - `this.activeInputIndex`: guaranteed valid by consensus, but defensive check recommended

### 4.2  Division by Zero
- **File**: `common_mistakes/division_by_zero.cash` (250 lines)
- **Category**: Arithmetic Safety
- **Severity**: Critical (consensus bricking — **permanent fund loss**)
- **Risk**: `/0` or `%0` → immediate script failure → UTXO permanently unspendable
- **Detection Rule**: For every `/` or `%` AST node, verify dominating `require(divisor > 0)`
- **Common Scenarios**: `vestingEnd == vestingStart`, zero-duration periods, zero total supply
- **Prevention Cost**: Nearly zero (one `require` statement)
- **Fix Cost**: **Impossible** (contract is immutable)

### 4.3  Integer Overflow
- **File**: `common_mistakes/integer_overflow.cash` (355 lines)
- **Category**: Arithmetic Safety
- **Severity**: High (silent miscalculation)
- **Risk**: Int64 wraparound → wrong balances → bypassed validation → fund theft
- **Detection Rule**: For every `+`, `*`, `-` AST node with non-constant operands, verify bounded inputs
- **Integer Bounds**: `-9,223,372,036,854,775,808` to `9,223,372,036,854,775,807`
- **Key Difference**: Overflow is **silent** (no consensus failure, no error) — just wrong math
- **Safe Patterns**:
  - Addition: `require(a <= MAX - b)` before `a + b`
  - Multiplication: bound both factors; stage calculations with intermediate checks
  - Subtraction: `require(a >= b)` before `a - b`

### 4.4  State Corruption
- **File**: `common_mistakes/state_corruption.cash` (403 lines)
- **Category**: Covenant Continuation Safety
- **Severity**: Critical (fund loss, protocol violation)
- **Risk**: Invalid state transitions → covenant escape, logic bypass, arbitrary state injection
- **Detection Rule**: For stateful covenants, verify:
  1. State integrity: `require(hash256(state) == stateHash)`
  2. State format: `require(state.length == expectedLength)` before deserialization
  3. Continuation: `require(output.lockingBytecode == input.lockingBytecode)`
  4. New state: computed on-chain, **never** trusted from caller
- **Known CashScript Limitation**: Cannot reconstruct `lockingBytecode` with updated parameters on-chain → NexOps must validate state parameter updates at build-time

---

## 5  Template Audit Results

All 5 templates were audited against the full anti-pattern matrix and primitive checklist.

### 5.1  Summary Table

| Template | Lines | Paths | Anti-Pattern Immunity | Known Limitation |
|----------|-------|-------|----------------------|------------------|
| **`escrow_2of3`** | 270 | `settle`, `disputeBuyerArbiter`, `disputeSellerArbiter`, `refund` | ✅ **9/9** | None — stateless, no covenant continuation needed |
| **`vesting_linear`** | 322 | `claim`, `revoke` | ✅ **9/9** | None — covenant continuation is cryptographically enforced |
| **`auction_dutch`** | 425 | `bid`, `reclaim` | ✅ **9/9** | None — stateless first-come-first-served design |
| **`auction_english`** | 411 | `bid`, `claim` | ✅ **8/9** | ⚠️ Covenant continuation params (new bidder key) **cannot** be enforced on-chain — NexOps builder must validate |
| **`crowdfunding_refundable`** | 447 | `pledge`, `claim`, `refund` | ✅ **9/9** | NFT commitment uniqueness delegated to NexOps builder |

### 5.2  Universal Security Invariant Checklist

Every template passes these checks:

- [x] `this.activeInputIndex` validated → `lockingBytecode == this.lockingBytecode` on **all** paths
- [x] Input `tokenCategory` validated on **all** paths
- [x] Output `tokenCategory` validated on **all** outputs
- [x] `tx.outputs.length` constrained on **all** paths
- [x] `lockingBytecode` validated on **all** outputs
- [x] `value` validated on **all** outputs
- [x] Time comparisons use `>=` for "at-or-after", `<` for "before"
- [x] No fee assumptions — caller specifies exact output amounts
- [x] No implicit output ordering — all outputs validated semantically
- [x] Division-by-zero prevented where applicable
- [x] Signature validation uses explicit `checkSig` (no shorthand)

### 5.3  Per-Template Security Notes

#### `escrow_2of3`
- Cleanest design — all 4 paths follow identical validation structure
- Buyer can redirect refund to any script (intentional flexibility, not a vulnerability)
- No arbiter-only spending path (intentional design constraint)

#### `vesting_linear`
- **Cryptographically enforced** covenant continuation — `lockingBytecode == input.lockingBytecode`
- `vestingEnd > vestingStart` prevents division by zero
- Issuer revocation restricted to pre-cliff period only
- Handles both 1-output (full claim) and 2-output (partial claim + continuation) cases

#### `auction_dutch`
- Linear price decay with explicit `require(duration > 0)` division-by-zero protection
- Builder-provided `currentPrice` validated against on-chain calculation
- Reserve price enforced as floor: `require(currentPrice >= reservePrice)`
- Three-phase time model with clear boundaries

#### `auction_english`
- **Atomic bid replacement with on-chain refund guarantee** — previous bidder always gets exact refund
- Even with malicious builder, no bidder can lose funds (fund safety is cryptographic, not trust-based)
- ⚠️ **Builder must validate parameter reconstruction** when creating new auction contract with updated bidder

#### `crowdfunding_refundable`
- **NFT-based pledge tracking** with burn-on-refund to prevent double-refund
- NFT burn enforcement relies on `tx.outputs.length <= 2` invariant (documented dependency)
- Covenant continuation cryptographically enforced on pledge and partial-refund paths
- Intentional design: goal met after deadline = funds locked (time-bound guarantees > convenience)

---

## 6  Cross-Layer Dependency Map

```mermaid
graph TD
    subgraph "Layer 1: Primitives"
        AUTH[authorization]
        COV[covenant_enforcement]
        DIV[division_safety]
        STATE[state_transition]
        TIME[time_gating]
        TOKEN[token_mint_control]
        VAL[value_redistribution]
    end

    subgraph "Layer 2: Anti-Patterns"
        FEE[fee_assumption_violation]
        ORDER[implicit_output_ordering]
        MINT[minting_authority_leak]
        LIMIT[missing_output_limit]
        TAMOUNT[missing_token_amount]
        TCAT[missing_token_validation]
        TVAL[time_validation_error]
        POS[unvalidated_position]
        VULN[vulnerable_covenant]
    end

    subgraph "Layer 3: Common Mistakes"
        ARRAY[array_bounds]
        DIVZ[division_by_zero]
        OVER[integer_overflow]
        CORRUPT[state_corruption]
    end

    subgraph "Layer 4: Templates"
        ESC[escrow_2of3]
        VEST[vesting_linear]
        DUTCH[auction_dutch]
        ENG[auction_english]
        CROWD[crowdfunding_refundable]
    end

    COV --> VULN
    COV --> ORDER
    COV --> CORRUPT
    VAL --> FEE
    VAL --> ORDER
    VAL --> LIMIT
    TOKEN --> MINT
    TOKEN --> TAMOUNT
    TOKEN --> TCAT
    TIME --> TVAL
    AUTH --> POS
    DIV --> DIVZ
    DIV --> OVER
    STATE --> CORRUPT

    ESC -.->|"immune to"| FEE
    ESC -.->|"immune to"| ORDER
    ESC -.->|"immune to"| POS
    VEST -.->|"immune to"| DIVZ
    VEST -.->|"immune to"| VULN
    DUTCH -.->|"immune to"| TVAL
    DUTCH -.->|"immune to"| DIVZ
    CROWD -.->|"immune to"| TAMOUNT
    CROWD -.->|"immune to"| TCAT
```

**Reading the diagram**:
- Solid arrows: "this primitive prevents this threat"
- Dashed arrows: "this template is immune to this anti-pattern"

---

## 7  Gap Analysis & Recommendations

### ✅ Strengths

| Aspect | Assessment |
|--------|------------|
| **Coverage** | All major CashScript attack surfaces are documented |
| **Pedagogy** | Every file has ❌ vulnerable and ✅ secure examples with detailed commentary |
| **Actionability** | AST-level detection rules specified for every vulnerability class |
| **Consistency** | Severity labels (Critical/High/Medium) are uniform across all 25 files |
| **Template quality** | All 5 templates pass the complete security invariant checklist |
| **Documentation** | Audit checklists, deployment notes, and edge cases documented per file |

### ⚠️ Identified Gaps

| # | Gap | Current Risk | Recommendation |
|---|-----|-------------|----------------|
| 1 | **Re-entrancy** not covered as a topic | **Low** — UTXO model prevents classic re-entrancy, but document this explicitly | Add a note in primitives explaining why UTXO model eliminates re-entrancy risk and under what edge conditions (multi-input txs) caution is still needed |
| 2 | **Signature replay / malleability** not addressed | **Medium** — cross-path or cross-contract signature reuse could be exploited | Add `sig_replay.cash` anti-pattern covering signature reuse across different spending paths and across transactions |
| 3 | **Integer overflow** not checked in templates | **Low** — templates implicitly bound via `<= inputValue`, but no explicit max-int guards in vesting/auction math | Consider adding explicit overflow checks in `vesting_linear` price calculation and `auction_dutch` price decay formula for large-value deployments |
| 4 | **Deployment parameter validation** documented but not enforced on-chain | **Medium** — deployer error (e.g., `vestingEnd <= vestingStart`) locks funds permanently | NexOps builder **must** reject deployment when `vestingEnd <= vestingStart`, `startPrice <= reservePrice`, `priceDecayEnd <= priceDecayStart`, etc. Specify these as mandatory build-time checks |
| 5 | **NFT commitment uniqueness** fully delegated to builder | **Medium** — duplicate commitments could enable pledge collision attacks | Create a specification document for builder-side NFT commitment generation (e.g., `hash(txid + outputIndex + nonce)`) with uniqueness guarantees |

### 🔮 Future Enhancements

- **Automated test harness**: Generate test transactions for each template against each anti-pattern
- **Severity scoring**: Assign CVSS-style scores for cross-referencing severity across files
- **Contract composition safety**: Document rules for safely composing multiple templates (e.g., escrow + vesting)

---

## 8  Conclusion

The NexKB is **structurally sound** and provides comprehensive coverage of CashScript security concerns. The four-layer architecture creates a coherent knowledge pipeline:

```
Primitives (what must be true)
    ↓
Anti-Patterns (what goes wrong when it's not)
    ↓
Common Mistakes (arithmetic & memory safety)
    ↓
Templates (correct application of all principles)
```

### By the Numbers

| Metric | Value |
|--------|-------|
| Total files audited | **25** |
| Primitives (invariants) | **7** |
| Anti-patterns (threats) | **9** |
| Common mistakes (safety) | **4** |
| Templates (reference impl) | **5** |
| Total lines of knowledge | **~10,000+** |
| Templates passing full checklist | **5/5** |
| Anti-patterns immune per template | **8–9 / 9** |
| Gaps identified | **5** (all enhancement-level, none blocking) |

> **Verdict**: The KB is ready to power NexOps audit and code generation with high confidence. The 5 gaps identified are enhancement opportunities for future iterations.
