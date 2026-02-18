# Fixes Applied to Enable Compilable, Valid, Correct CashScript Generation

## Summary
Fixed **5 critical issues** that prevented the pipeline from generating compilable, secure CashScript `.cash` files that match the knowledge base patterns.

---

## ✅ Fix #1: Language Guard - Allow Secure Patterns

**File**: `src/services/language_guard.py`

**Problem**: The guard was blocking **required security patterns** from the KB:
- `tx.outputs[n].lockingBytecode` (required for covenant validation)
- `tx.inputs[this.activeInputIndex].*` (required for position-safe access)
- `tokenCategory` / `tokenAmount` validation (required for token safety)

**Solution**: 
- **Removed** blanket bans on `.lockingBytecode`, `.tokenCategory`, `.tokenAmount`, and `tx.inputs[`
- **Added** targeted blocking of **only unsafe patterns**:
  - Hardcoded literal indices: `tx.inputs[0]`, `tx.inputs[1]`, etc. (blocks unsafe patterns)
  - EVM/Solidity syntax: `msg.sender`, `mapping()`, `emit`, `payable`, etc.
- **Allows** secure patterns: `tx.inputs[this.activeInputIndex].*`, `tx.outputs[n].lockingBytecode`, etc.

**Result**: Generated code can now use the same secure patterns as the KB templates.

---

## ✅ Fix #2: Phase2 Prompt - Require Security Patterns

**File**: `src/services/pipeline.py`

**Problem**: Phase2 prompt explicitly **forbade** the security patterns required by `security_rules.json`:
- "FORBIDDEN: .lockingBytecode, .tokenCategory, .tokenAmount"
- This contradicted SEC-004, SEC-005 which **require** these validations

**Solution**:
- **Changed** "FORBIDDEN" list to only include EVM/Solidity patterns
- **Added** "REQUIRED SECURITY PATTERNS" section explicitly listing:
  - `tx.outputs[n].lockingBytecode` - REQUIRED for covenant continuation
  - `tx.inputs[this.activeInputIndex].lockingBytecode` - REQUIRED for position safety
  - `tx.outputs[n].tokenCategory` / `tokenAmount` - REQUIRED for token safety
- **Updated** structural protocols to mandate these patterns
- **Clarified** that Language Guard allows these secure patterns

**Result**: LLM is now **instructed to use** security patterns instead of avoiding them.

---

## ✅ Fix #3: Wire Violations Back to Phase2 on Retry

**File**: `src/services/pipeline_engine.py`

**Problem**: When Phase 3 (Toll Gate) failed, violations were **not passed** to Phase2.run(), so retries had no feedback about what failed.

**Solution**:
- **Added** `previous_violations` variable to track Phase 3 violations
- **Pass** violations to `Phase2.run(ir, violations=previous_violations, ...)` on retry
- **Clear** violations on language guard failures and syntax errors (need full regeneration)
- **Preserve** violations on Phase 3 failures (targeted fixes possible)

**Result**: Retries now get **targeted feedback** about which anti-patterns failed, enabling convergence to secure code.

---

## ✅ Fix #4: Fix Compiler Bug (Windows PATH)

**File**: `src/services/compiler.py`

**Problem**: Line 36 had `os.pathpathsep` (typo) which would cause `AttributeError` on Windows when checking PATH.

**Solution**:
- **Fixed** typo: `os.pathpathsep` → `os.pathsep`
- `os.pathsep` is the correct Python constant for PATH separator (`;` on Windows, `:` on Unix)

**Result**: Compiler can now correctly resolve `cashc` on Windows systems.

---

## ✅ Fix #5: Align Pragma Version with KB

**File**: `src/services/pipeline.py`

**Problem**: Phase2 prompt said "ALWAYS use `pragma cashscript ^0.10.0`" but all KB files use `^0.13.0`.

**Solution**:
- **Updated** pragma instruction: `^0.10.0` → `^0.13.0`
- **Added** note: "(matches knowledge base)"

**Result**: Generated code uses the same pragma version as KB templates, ensuring compatibility.

---

## Impact Summary

| Aspect | Before | After |
|--------|--------|-------|
| **Covenant-safe code** | ❌ Blocked by Language Guard | ✅ Allowed (secure patterns) |
| **Security patterns** | ❌ Forbidden in prompt | ✅ Required in prompt |
| **Retry feedback** | ❌ No violation context | ✅ Violations passed to Phase2 |
| **Windows compilation** | ❌ Bug (AttributeError) | ✅ Fixed |
| **Pragma alignment** | ❌ Mismatch (0.10 vs 0.13) | ✅ Aligned (0.13) |

---

## Testing Recommendations

1. **Test Language Guard**: Generate code with `tx.outputs[0].lockingBytecode` - should pass
2. **Test Hardcoded Indices**: Generate code with `tx.inputs[0]` - should be rejected
3. **Test Violation Feedback**: Generate code that fails Phase 3, verify retry includes violation context
4. **Test Compilation**: Verify `cashc` resolution works on Windows
5. **Test Pragma**: Verify generated code uses `^0.13.0`

---

## Next Steps

The pipeline should now be able to generate **compilable, valid, correct** CashScript code that:
- ✅ Uses secure patterns from the KB
- ✅ Passes Language Guard (allows secure patterns)
- ✅ Gets targeted feedback on retries
- ✅ Compiles with `cashc`
- ✅ Matches KB pragma version

**Note**: The pipeline still depends on:
- LLM quality (Phase 1, Phase 2)
- `cashc` being installed and in PATH
- Knowledge base quality (already good)

These fixes remove the **structural blockers** that prevented correct code generation.
