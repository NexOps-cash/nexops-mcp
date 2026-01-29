# Anti-Pattern Detection Rules

## Philosophy

Anti-pattern detection must be:
- **Structural** - Based on code structure, not string matching
- **Deterministic** - Same code always produces same result
- **Semantic** - Understands what code means, not just what it says
- **Rule-based** - Explicit logic, not heuristics

---

## Prohibited Detection Methods

❌ **String matching** - `"tx.outputs[0]" in code`  
❌ **Keyword scanning** - Looking for specific variable names  
❌ **Heuristics** - Probabilistic or confidence-based detection  
❌ **LLM interpretation** - Asking AI to judge code safety  

---

## Required Detection Methods

✅ **AST analysis** - Parse code into abstract syntax tree  
✅ **Semantic validation** - Check for missing safety properties  
✅ **Structural patterns** - Detect code structure violations  
✅ **Invariant checking** - Verify required properties exist  

---

## Detection Architecture

### 1. Anti-Pattern Files (.cash)

**Purpose:** Documentation and education

**Contents:**
- Vulnerability explanation
- Attack vector description
- Vulnerable code examples
- Secure code examples

**NOT used for:** Detection logic, pattern matching, enforcement rules

### 2. Detector Classes (Python)

**Purpose:** Enforcement and validation

**Structure:**
```python
class AntiPatternDetector:
    id: str  # e.g., "implicit_output_ordering"
    
    def detect(self, ast: CashScriptAST) -> Optional[Violation]:
        """
        Detect anti-pattern violation using semantic analysis.
        
        Returns:
            Violation if pattern detected, None otherwise
        """
        pass
```

**Requirements:**
- Deterministic (same AST → same result)
- Semantic (understands code meaning)
- Explainable (can describe WHY it's unsafe)

### 3. Violation Output

**Required fields:**
```python
{
    "rule": str,          # Anti-pattern ID
    "reason": str,        # Which invariant violated
    "exploit": str,       # Why this is exploitable
    "location": dict,     # Where in code (line/function)
    "severity": "critical"
}
```

**Explanation must include:**
- What assumption is unsafe
- Which BCH property makes it exploitable
- What attacker can do

---

## Example: Implicit Output Ordering Detection

### ❌ WRONG (String Matching)

```python
def detect(code: str) -> bool:
    return "tx.outputs[0]" in code  # Too broad!
```

**Problem:** Flags secure code that validates lockingBytecode

### ✅ CORRECT (Semantic Analysis)

```python
def detect(ast: CashScriptAST) -> Optional[Violation]:
    for output_ref in ast.find_output_references():
        if output_ref.uses_index_only():
            # Check if lockingBytecode is validated
            if not ast.validates_locking_bytecode_for(output_ref):
                return Violation(
                    rule="implicit_output_ordering",
                    reason="Output semantic role inferred from index without lockingBytecode validation",
                    exploit="Attacker can reorder outputs to redirect value",
                    location=output_ref.location
                )
    return None
```

**Why correct:**
- Checks for missing validation (semantic property)
- Doesn't flag secure code that validates lockingBytecode
- Explains WHY it's unsafe
- Deterministic

---

## Detection Workflow

```
Code Input
    ↓
Parse to AST
    ↓
For each detector:
    ↓
Semantic Analysis
    ↓
Violation? → HALT + Report
    ↓
No violation? → Continue
    ↓
All detectors pass → SAFE
```

---

## Adding New Detectors

### Requirements Checklist

- [ ] Detector class implements `detect(ast) -> Optional[Violation]`
- [ ] Detection is deterministic (no randomness)
- [ ] Detection is semantic (not string matching)
- [ ] Violation includes exploit explanation
- [ ] False positive rate is zero (or near-zero)
- [ ] Corresponding .cash file exists for documentation

### Testing Requirements

- [ ] Detects all vulnerable examples from .cash file
- [ ] Does NOT flag secure examples from .cash file
- [ ] Explains WHY each violation is unsafe
- [ ] Works on real-world contract variations

---

## Separation of Concerns

| Component | Role | Forbidden |
|-----------|------|-----------|
| `.cash` files | Documentation | Detection logic |
| Detector classes | Enforcement | Fixing code |
| Audit mode | Detection | Repair |
| Repair mode | Regeneration | Audit |

---

## Final Rules

1. **No heuristics** - Detection must be binary (yes/no)
2. **No string matching** - Use AST/semantic analysis
3. **No fixes in audit** - Detection and repair are separate
4. **Explainable violations** - Must describe exploit vector
5. **Zero false positives** - Secure code must never be flagged
