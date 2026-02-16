# NexOps MCP: The Intelligence Layer for Secure BCH Covenants

NexOps MCP (Model Context Protocol) is the authoritative intelligence core of the NexOps ecosystem. It transitions AI reasoning out of the peripheral IDE and into a centralized, specialized, and safety-hardened server dedicated to the generation of secure Bitcoin Cash (BCH) smart contracts.

## 🎯 Mission

To provide a deterministic, safety-first code generation pipeline that eliminates common vulnerabilities in Cashtokens and BCH covenants by enforcing a "Negative Type System" through semantic anti-pattern detection.

## 🏗️ Core Architecture

NexOps MCP is built on a tiered architecture that separates structural intent from logic implementation, wrapped in a strict security baseline.

### 1. The Architect (Phase 1)
Responsible for structural skeleton generation. It defines the "shape" of a contract (parameters, functions, storage) without implementing logic, ensuring the high-level design is sound before a single line of script is written.

### 2. The Engineer (Phase 2)
The logic implementation core. It transforms skeletons into fully functional CashScript code by drawing from an authoritative **Knowledge Base** of production-tested patterns and security rules.

### 3. The Safety Layer (Anti-Pattern Enforcer)
A rigorous "Negative Type System" that semantically analyzes generated code for known exploitable patterns.
- **Authoritative**: If a violation is detected, the code is REJECTED.
- **Semantic**: Uses AST analysis (not string matching) to understand logic flow.
- **Explainable**: Provides detailed reports on why code is unsafe and which BCH invariants were violated.

### 4. The Knowledge Layer
A curated library of Bitcoin Cash domain expertise:
- **Security Rules**: 18+ critical rules for covenant safety.
- **Secure Patterns**: Production-ready snippets for validation, auth, and state management.
- **Templates**: Reference implementations for standard contract types (Escrows, Vaults, DAOs).

## 🛠️ Technology Stack

- **Core**: Python 3.11+
- **API Framework**: FastAPI
- **Real-time Communication**: WebSockets (JSON-RPC style)
- **Validation**: Pydantic v2
- **Testing**: Pytest (Unit & Integration)
- **Security Logic**: Custom CashScript AST Parser & Semantic Evaluator

## 🤝 NexOps Integration

NexOps MCP is designed to be the "brain" behind the NexOps IDE. While the IDE handles UI/UX and user interaction, the MCP server handles:
1.  **Context-Aware Reasoning**: Injecting BCH-specific constraints into LLM prompts.
2.  **Security Audits**: Real-time checking of user-written or AI-generated code.
3.  **Knowledge Retrieval**: Providing the IDE with authoritative patterns on-demand.

---

*Part of the NexOps ecosystem - building the future of secure decentralized finance on Bitcoin Cash.*
