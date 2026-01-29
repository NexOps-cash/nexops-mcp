# Anti-Pattern Enforcement System

## Overview

The Anti-Pattern Enforcement System is the **negative type system** of NexOps MCP. It defines what code structures are **absolutely forbidden** due to known security vulnerabilities in Bitcoin Cash covenants.

## Philosophy

> **Anti-patterns are used for detection only, never for correction.**

This system implements a strict separation between:
- **Audit** - Detection and reporting of violations
- **Repair** - Regeneration of safe code (future phase)

## Architecture

### 1. Documentation Layer (`knowledge/anti_pattern/*.cash`)

**Purpose:** Educational and contextual

**Contents:**
- Vulnerability explanations
- Attack vector descriptions
- Vulnerable code examples
- Secure code examples

**NOT used for:** Detection logic, pattern matching, or enforcement

### 2. Detection Layer (`src/services/anti_pattern_detectors.py`)

**Purpose:** Semantic enforcement

**Components:**
- `ImplicitOutputOrderingDetector` - Detects output index assumptions without lockingBytecode validation
- `MissingOutputLimitDetector` - Detects absence of output count validation
- `UnvalidatedPositionDetector` - Detects missing input position validation
- `FeeAssumptionViolationDetector` - Detects fee calculation patterns

**Method:** AST-based semantic analysis, not string matching

### 3. AST Parser (`src/utils/cashscript_ast.py`)

**Purpose:** Code structure analysis

**Capabilities:**
- Parse CashScript into simplified AST
- Identify output references
- Track validation checks
- Semantic property detection

### 4. Orchestrator (`src/services/anti_pattern_enforcer.py`)

**Purpose:** Coordination and context

**Responsibilities:**
- Load documentation files dynamically
- Coordinate detector execution
- Generate LLM context
- Return structured violations

## Detection Workflow

```
CashScript Code
    ↓
Parse to AST (cashscript_ast.py)
    ↓
For each detector in DETECTOR_REGISTRY:
    ↓
Semantic Analysis (detector.detect(ast))
    ↓
Violation found? → Record + Continue
    ↓
All detectors complete
    ↓
Return validation result
```

## Violation Structure

```python
{
    "rule": "implicit_output_ordering.cash",
    "reason": "Output semantic role inferred from index without lockingBytecode validation",
    "exploit": "Attacker can reorder outputs to redirect value...",
    "location": {
        "line": 15,
        "function": "withdraw",
        "output_index": 0
    },
    "severity": "critical"
}
```

## Key Principles

### 1. No Heuristics
Detection is **binary** - code either violates or doesn't. No confidence scores, no probabilistic matching.

### 2. No String Matching
Detection uses **semantic analysis** - understands what code means, not just what it says.

### 3. No Fixes in Audit
Audit mode **only detects** - it never modifies code, suggests fixes, or generates alternatives.

### 4. Explainable Violations
Every violation includes:
- Which invariant is violated
- What assumption is unsafe
- Why BCH makes this exploitable

### 5. Zero False Positives
Secure code must **never** be flagged. Detection logic is conservative and precise.

## Adding New Detectors

### Requirements

1. **Create detector class** in `anti_pattern_detectors.py`:
```python
class NewPatternDetector(AntiPatternDetector):
    id = "new_pattern"
    
    def detect(self, ast: CashScriptAST) -> Optional[Violation]:
        # Semantic detection logic
        pass
```

2. **Add to registry**:
```python
DETECTOR_REGISTRY = [
    # ... existing detectors
    NewPatternDetector(),
]
```

3. **Create documentation** in `knowledge/anti_pattern/new_pattern.cash`

4. **Write tests** in `tests/test_anti_pattern_enforcer.py`

### Testing Checklist

- [ ] Detects all vulnerable examples
- [ ] Does NOT flag secure examples
- [ ] Explains WHY violation is unsafe
- [ ] Works on real-world variations
- [ ] Deterministic (same input → same output)

## Usage

### In Code

```python
from src.services.anti_pattern_enforcer import get_anti_pattern_enforcer

enforcer = get_anti_pattern_enforcer()

# Validate code
result = enforcer.validate_code(cashscript_code, stage="audit")

if not result["valid"]:
    for violation in result["violations"]:
        print(f"VIOLATION: {violation['rule']}")
        print(f"Reason: {violation['reason']}")
        print(f"Exploit: {violation['exploit']}")
```

### In LLM Prompts

```python
# Get anti-pattern context for LLM
context = enforcer.get_anti_pattern_context()

# Include in system prompt
system_prompt = f"""
{context}

Generate CashScript code that avoids all anti-patterns...
"""
```

## Current Detectors

| Detector | Detects | Safe Alternative |
|----------|---------|------------------|
| `ImplicitOutputOrderingDetector` | Output index without lockingBytecode validation | Validate lockingBytecode for each output |
| `MissingOutputLimitDetector` | No `tx.outputs.length` check | `require(tx.outputs.length <= N)` |
| `UnvalidatedPositionDetector` | No `this.activeInputIndex` check | `require(this.activeInputIndex == N)` |
| `FeeAssumptionViolationDetector` | Fee calculation as `input - output` | Don't reason about fees; use bounded value loss |

## Future Enhancements

1. **Full CashScript Parser** - Replace simplified AST with actual compiler AST
2. **More Detectors** - Add remaining anti-patterns (minting authority, time validation, etc.)
3. **Repair Integration** - Connect to Phase 2 logic generator for safe regeneration
4. **Performance Optimization** - Cache AST parsing, parallel detector execution

## References

- [ANTI_PATTERN_PROTOCOL.md](../specs/ANTI_PATTERN_PROTOCOL.md) - Core philosophy
- [ANTI_PATTERN_DETECTION_RULES.md](../specs/ANTI_PATTERN_DETECTION_RULES.md) - Detection methodology
- [BCH Knowledge Base](../knowledge/BCH_Knowledge_Base-main/) - Security patterns
