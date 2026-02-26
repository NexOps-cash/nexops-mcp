# NexOps MCP 🚀

The Intelligence Layer for NexOps. This Model Context Protocol (MCP) server orchestrates high-performance guarded synthesis, security auditing, and automated repair for CashScript ^0.13.0 smart contracts.

---

## 💎 Core Features

### 1. Hybrid Scoring v2 (70/30)
NexOps utilizes a sophisticated hybrid scoring engine to ensure both structural and semantic correctness.
*   **Deterministic Bucket (0–70 pts):** Automated static analysis (Linter + Compiler + Security Invariants).
*   **Semantic Bucket (0–30 pts):** AI-powered assessment of business logic, race conditions, and incentive alignment.
    *   *Structured Category (0–20 pts):* Categorization into Risk Levels.
    *   *Business Logic Score (0–10 pts):* Subjective analysis of fairness and edge cases.
*   **Deployment Gate:** Contracts must achieve `Det Score ≥ 50` AND `Total Score ≥ 75` to be eligible for mainnet deployment.

### 2. Guarded Synthesis Pipeline
A multi-stage generation loop that self-corrects based on compiler errors and linter violations.
*   **Soft Convergence Policy:** Minor structural violations (≤ 4 total, 0-1 critical) allow for "soft pass" convergence, enabling the UI to show the audit/repair loop instead of blocking indefinitely.
*   **Hard Gates:** Safety-critical invariants (Sum preservation, Output limits) trigger immediate regeneration.

### 3. Automated Repair Agent
One-click fix capabilities for all deterministic violations (LNC-001 to LNC-015).

---

## 🛡️ Deterministic Rule Set (LNC)

NexOps enforces 15 security-critical structural rules BEFORE compilation:

| ID | Name | Description | Severity |
|:---|:---|:---|:---|
| **LNC-001** | Index Guard | Prevents hardcoded `tx.inputs[0]` or unvalidated `tx.outputs[N]`. | CRITICAL |
| **LNC-002** | Unused Vars | Heuristic detection of variables declared but never read. | LOW |
| **LNC-003** | Value Anchor | Ensures funds are anchored to inputs (Sum Invariants). | CRITICAL |
| **LNC-004** | Scope Check | Prevents indexing `tx.outputs` outside of function bodies. | HIGH |
| **LNC-005** | Fee Arithmetic | Forbids implicit fee subtraction (e.g., `value - fee`). | HIGH |
| **LNC-006** | Field Update | Replaces deprecated Solidity-isms like `.lockingBytecode`. | INFO |
| **LNC-007** | Version Guard | Catches CashScript 0.12.x patterns incompatible with ^0.13.0. | HIGH |
| **LNC-008** | Self-Anchor | Forces covenants to perpetuate state via `this.activeBytecode`. | CRITICAL |
| **LNC-009** | Syntax Filter | Forbids non-functional constructs (Ternary, Loops, If/Else). | HIGH |
| **LNC-010** | Timelock | Enforces standalone `require(tx.time >= X)` patterns. | HIGH |
| **LNC-011** | Div Guard | Protects against Division by Zero with mandatory `> 0` checks. | CRITICAL |
| **LNC-012** | Frozen State | Warns when a stateful contract lacks mutation logic. | WARNING |
| **LNC-013** | Mint Guard | Enforces Auth pubkey checks for token-minting functions. | HIGH |
| **LNC-014** | Token Pair | Ensures Category and Amount are validated together. | CRITICAL |
| **LNC-015** | Constructor | Validates P2PKH/P2SH constructor argument types. | CRITICAL |

---

## ⚡ API Reference

### 🌐 REST Endpoints

#### `POST /api/audit`
Performs a full security audit and returns a structured Hybrid Score.
*   **Request Body:** `{"code": "string", "intent": "string"}`
*   **Response:** `{"total_score": 85, "deployment_allowed": true, "issues": [...]}`

#### `POST /api/repair`
Generates a targeted fix for a specific linter violation.
*   **Request Body:** `{"code": "string", "issue": AuditIssue}`

#### `POST /api/edit`
LLM-powered arbitrary modification of contract logic while preserving safety invariants.

### 🔌 WebSocket Endpoints

#### `WS /ws/generate`
The high-speed guarded synthesis bridge.
*   **Message Type:** `intent`
*   **Payload:** `{"prompt": "User requirement text"}`
*   **Events:** Emit progress stages (`phase1_parsing` → `phase2_linting` → `phase3_validation`).

---

## � System Flows

### 1. Guarded Generation Flow (`WS /ws/generate`)
The pipeline ensures that the generated code is structurally sound and compiles before reaching the user.
```mermaid
graph TD
    A[User Intent] --> B[Phase 1: Intent Parsing]
    B --> C[Phase 2: Constrained Synthesis]
    C --> D{DSL Lint Gate}
    D -- Hard Fail --> C
    D -- Soft Fail / Pass --> E[Phase 3: Security Invariants]
    E --> F[Phase 4: Sanity Check]
    F -- Success --> G[Final .cash Contract]
    F -- Logic Gap --> C
```

### 2. Audit & Scoring Flow (`POST /api/audit`)
The 70/30 engine evaluates precisely where a contract stands on the security spectrum.
```mermaid
graph LR
    Code --> Det[Deterministic Analyzer]
    Code --> Sem[Semantic AI Auditor]
    Det -- Penalties --> Score[Scoring Engine]
    Sem -- Category + Biz Logic --> Score
    Score --> Final[Total Score + Deployment Gate]
```

### 3. Automated Repair Flow (`POST /api/repair`)
Targeted remediation for specific linter violations.
```mermaid
graph TD
    Issue[Linter Violation] --> Router[Repair Router]
    Router -- Deterministic Rule --> Fixed[Static Code Substitution]
    Router -- Structural Rule --> LLM[LLM-Powered Targeted Patch]
    Fixed --> Verify[Compilation Verification]
    LLM --> Verify
    Verify --> Done[Secured Patch]
```

### 4. Semantic Edit Flow (`POST /api/edit`)
Updating logic while maintaining security invariants.
```mermaid
graph LR
    Old[Existing Code] --> Intent[New User Instruction]
    Intent --> Enforcer[Anti-Pattern Enforcer]
    Enforcer --> Synth[Synthesis Gate]
    Synth --> New[Updated Secured Contract]
```

---

## 📝 Scenarios & Examples

### Scenario A: Clean Escrow (The Ideal Path)
*   **Prompt**: "Create a 2-of-3 escrow with an arbitrator, preventing fund lock."
*   **Generate**: Synthesis converges on attempt 1 with 100% DSL compliance.
*   **Audit Result**:
    *   `deterministic_score`: 70/70
    *   `semantic_score`: 28/30 (`category: "none"`, `biz_logic: 8/10`)
    *   `total_score`: 98
    *   `deployment_allowed`: **TRUE** ✅

### Scenario B: Token Inflation (Safety Gate)
*   **Prompt**: "A token contract that allows the owner to mint whenever they want."
*   **Generate**: Pipeline detects `LNC-013` (Mint Authority Guard) failure. Retries and adds a signature check.
*   **Audit Result**:
    *   `issues`: `[{"rule_id": "LNC-014", "severity": "CRITICAL"}]` (Missing Category check)
    *   `deterministic_score`: 50/70
    *   `total_score`: 68
    *   `deployment_allowed`: **FALSE** ❌ (Score < 75)

### Scenario C: Soft-Convergence (The "Good Enough" Draft)
*   **Prompt**: "Simple vesting contract with a 1-year cliff."
*   **Generate**: Returns code with 2 minor `LNC-002` (Unused Var) violations.
*   **Metadata**: `{"lint_soft_fail": true, "soft_fail_count": 2}`
*   **Action**: UI displays warnings; User triggers **Repair** to clean up the code.

### Scenario D: Fatal Deadlock (Security Hammer)
*   **Prompt**: "Complex logic where funds only unlock if 5 different variables match exactly."
*   **Audit**: AI detects that variables cannot realistically match → `funds_unspendable`.
*   **Result**: 
    *   `semantic_score`: 0 (Unconditional override)
    *   `risk_level`: **CRITICAL**
    *   `deployment_allowed`: **FALSE** ❌

---

## �🛠️ Getting Started

### Prerequisites
- Python 3.11+
- CashScript Compiler (`cashc`)

### Installation
```powershell
# Create & Activate Virtual Environment
python -m venv venv
.\venv\Scripts\Activate

# Install NexOps Core
pip install -e .
```

### Running the Engine
```powershell
$env:PORT=3005; python -m src.server
```

---

## 🧪 Verification
Execute the hybrid scoring regression suite:
```powershell
python -m pytest test_audit_repair.py -v
```

© 2026 NexOps Team. Built for the Bitcoin Cash DeFi Ecosystem.
