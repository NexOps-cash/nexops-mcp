# NexOps KB Design (Deterministic Context)

## Philosophy
To strictly control the LLM's logic generation, we provide **deterministic** context.
Instead of fuzzy vector search, we use **keyword-based** or **category-based** retrieval for Phase 1.

## Structure (`nexops-mcp/knowledge/`)

### 1. `security_rules.json`
A strictly structured list of security constraints that must be injected into the Prompt.

**Schema:**
```json
[
  {
    "id": "SEC-001",
    "category": "defi",
    "severity": "critical",
    "rule": "Do not use `tx.age` without a sequence check.",
    "description": "Prevents replay attacks or premature spending."
  }
]
```

### 2. `patterns/` Directory
Contains `.cash` or `.md` files with best-practice snippets.

**Example:** `patterns/auth_checks.cash`
```cashscript
// PATTERN: P2PKH Auth
require(checkSig(sig, pubkey));
```

## `KnowledgeRetriever` Interface

```python
class KnowledgeRetriever:
    def get_security_rules(self, categories: List[str]) -> str:
        # Returns formatted constraints for the System Prompt
        pass

    def get_patterns(self, keywords: List[str]) -> str:
        # Returns relevant code snippets
        pass
```
