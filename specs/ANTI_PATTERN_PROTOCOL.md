# NexOps Anti-Pattern Protocol

## Purpose

Anti-patterns define **forbidden code structures** that represent
known exploit classes in Bitcoin Cash covenants.

They are **not suggestions**, **not lint rules**, and **not heuristics**.

An anti-pattern match represents a **provable security failure**.

---

## Core Principle

> Anti-patterns are used for **detection only**, never for correction.

---

## 1. Trigger Conditions

An anti-pattern is triggered when **any** of the following is true:

- A required validation is missing (e.g. no lockingBytecode check)
- A dangerous assumption is made (e.g. fee = input - output)
- Semantic meaning is inferred from index position
- Covenant safety depends on attacker-controlled behavior

Triggering is **binary**:
- Either the violation exists
- Or it does not

There is no confidence score.

---

## 2. Audit Behavior (MANDATORY)

When an anti-pattern is triggered during `action: "audit"`:

### The system MUST:
- Record the anti-pattern ID
- Mark severity as defined in the file
- Reject the contract as unsafe

### The system MUST NOT:
- Modify code
- Suggest fixes
- Generate alternative implementations
- Infer developer intent

Audit output is **descriptive only**.

---

## 3. Forbidden Behavior After Trigger

Once an anti-pattern is detected:

❌ The system must not "patch" the code  
❌ The system must not auto-insert checks  
❌ The system must not rewrite logic  
❌ The system must not continue generation  

**Audit halts immediately.**

---

## 4. Repair Phase Usage (Explicit Action Only)

Anti-patterns may be used during `action: "repair"`:

### In repair mode:
- Anti-patterns act as **hard constraints**
- Generated code must **not reintroduce** the pattern
- The system may choose *any safe architecture* that avoids it

Repair requires:
- Original code
- Audit findings
- Optional user intent

Repair output must:
- List which anti-patterns were resolved
- Declare any design tradeoffs

---

## 5. Generation Phase Usage

During `action: "generate"`:

- Anti-patterns define **forbidden structures**
- Generated code must never match an anti-pattern
- If conflict arises, generation fails explicitly

---

## 6. Adding New Anti-Patterns (Future-Proofing)

New anti-pattern files may be added **without changing system logic**.

Requirements:
- Deterministic trigger conditions
- Explicit exploit explanation
- Clear vulnerable vs secure contrast

No anti-pattern may:
- Be probabilistic
- Rely on LLM interpretation
- Include suggested fixes in audit mode

---

## Final Rule

> Anti-patterns protect the protocol,  
> not the developer's convenience.
