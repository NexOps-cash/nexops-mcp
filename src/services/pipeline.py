"""
3-Phase Generation Pipeline

Phase1 — Skeleton generation (LLM → ContractIR)
Phase2 — Logic fill (ContractIR + KB → .cash code)
Phase3 — Toll gate (deterministic validation → TollGateResult)
"""

import json
import logging
from typing import List, Optional

from src.models import (
    ContractIR,
    TollGateResult,
    ViolationDetail,
)
from src.services.llm.factory import LLMFactory
from src.services.knowledge import get_knowledge_retriever
from src.services.anti_pattern_enforcer import get_anti_pattern_enforcer
from src.services.rule_engine import get_rule_engine

logger = logging.getLogger("nexops.pipeline")

MAX_RETRIES = 3


# ─── Phase 1: Skeleton Generator ─────────────────────────────────────

class Phase1:
    """Generate structural skeleton from user intent. Returns ContractIR."""

    @staticmethod
    async def run(intent: str, security_level: str = "high") -> ContractIR:
        """Call LLM to produce a contract skeleton as ContractIR."""

        kb = get_knowledge_retriever()
        # Inject only template skeletons (structural, no logic)
        template_context = kb.get_category_content("templates")
        # Keep it lean — strip to first 80 lines per template
        skeleton_hints = _truncate_kb_context(template_context, max_lines=80)

        prompt = _build_phase1_prompt(intent, security_level, skeleton_hints)

        llm = LLMFactory.get_provider("phase1")
        raw_response = await llm.complete(prompt)

        # Parse LLM JSON response into ContractIR
        ir = _parse_phase1_response(raw_response, intent, security_level)
        ir.metadata.generation_phase = 1
        logger.info(f"Phase 1 complete: contract={ir.contract_name}, functions={len(ir.functions)}")
        return ir


# ─── Phase 2: Logic Fill ─────────────────────────────────────────────

class Phase2:
    """Fill business logic into skeleton. Returns compilable .cash code."""

    @staticmethod
    async def run(
        ir: ContractIR,
        violations: Optional[List[ViolationDetail]] = None,
        retry_count: int = 0,
        temperature: float = 0.7,
    ) -> str:
        """Take ContractIR (and optional prior violations) and produce .cash code."""

        kb = get_knowledge_retriever()
        enforcer = get_anti_pattern_enforcer()

        # Build KB context: primitives + compressed anti-pattern constraints
        primitives_context = kb.get_category_content("primitives")
        constraint_summary = enforcer.get_anti_pattern_context()

        # On retry, inject full anti-pattern docs for each violated rule
        violation_context = ""
        if violations and retry_count > 0:
            violation_context = _build_violation_context(violations, retry_count, kb)

        skeleton_code = _ir_to_skeleton_code(ir)
        
        # Activate Rules based on intent tags
        rule_engine = get_rule_engine()
        active_rules = rule_engine.get_rules_for_tags(ir.metadata.intent_tags)
        rule_context = rule_engine.format_rules_for_prompt(active_rules)

        prompt = _build_phase2_prompt(
            skeleton_code=skeleton_code,
            intent=ir.metadata.intent,
            primitives_context=_truncate_kb_context(primitives_context, max_lines=200),
            constraint_summary=constraint_summary,
            violation_context=violation_context,
            rule_context=rule_context,
        )

        llm = LLMFactory.get_provider("phase2")
        raw_response = await llm.complete(prompt, temperature=temperature)

        # Extract .cash code from response
        code = _extract_cash_code(raw_response)
        ir.metadata.generation_phase = 2
        ir.metadata.retry_count = retry_count
        logger.info(f"Phase 2 complete: {len(code)} chars, retry={retry_count}, temp={temperature}")
        return code


# ─── Phase 3: Structural Toll Gate ───────────────────────────────────

class Phase3:
    """Deterministic validation. No LLM calls. Returns TollGateResult."""

    @staticmethod
    def validate(code: str) -> TollGateResult:
        """Run all detectors on code. Returns pass/fail with violation details."""

        violations: List[ViolationDetail] = []
        hallucination_flags: List[str] = []

        # 1. Run AntiPatternEnforcer (uses CashScriptAST + all 11 detectors)
        enforcer = get_anti_pattern_enforcer()
        result = enforcer.validate_code(code, stage="generation")

        if not result["valid"]:
            for v in result.get("violations", []):
                rule = v.get("rule", "unknown")
                violations.append(ViolationDetail(
                    rule=rule,
                    reason=v.get("reason", ""),
                    exploit=v.get("exploit", ""),
                    location=v.get("location", {}),
                    severity=v.get("severity", "critical"),
                    fix_hint=_derive_fix_hint(rule),
                ))
                
                if rule == "evm_hallucination":
                    hallucination_flags.append(v.get("reason", "Solidity syntax"))

        # Score is based on number of passing detectors in registry
        from src.services.anti_pattern_detectors import DETECTOR_REGISTRY
        total_detectors = len(DETECTOR_REGISTRY)
        failed_count = len(set(v.rule for v in violations))
        score = (total_detectors - failed_count) / total_detectors if total_detectors > 0 else 0.0

        passed = len(violations) == 0
        gate_result = TollGateResult(
            passed=passed,
            violations=violations,
            hallucination_flags=hallucination_flags,
            structural_score=score,
        )

        logger.info(f"Phase 3 complete: passed={passed}, violations={len(violations)}, score={score:.2f}")
        return gate_result


# ═══════════════════════════════════════════════════════════════════════
# PRIVATE HELPERS
# ═══════════════════════════════════════════════════════════════════════


def _build_phase1_prompt(intent: str, security_level: str, skeleton_hints: str) -> str:
    """Build the Phase 1 LLM prompt."""
    return f"""You are "The Architect", a specialized CashScript contract skeleton generator.

Your ONLY goal is to generate the STRUCTURAL SKELETON of a CashScript contract.

Rules:
1. Define the `contract` block with correct constructor parameters.
2. Define all necessary public `function` signatures with correct parameters (including `sig s` and `pubkey pk` where needed).
3. Inside every function body, place exactly ONE comment: `// TODO: Implement logic`
4. DO NOT write any `require(...)` statements.
5. DO NOT write business logic, arithmetic, or covenant continuation.
6. DO NOT use Solidity syntax (no msg.sender, no mapping, no emit, no modifier).
7. Use CashScript ^0.10.0 syntax only.
8. Include `pragma cashscript ^0.10.0;` at the top.

Security Level: {security_level}

Identify relevant Intent Tags from this set: [multisig, escrow, timelock, stateful, spending, tokens].

Reference Templates (for structural patterns only):
{skeleton_hints}

User Request: {intent}

Output ONLY valid JSON:
{{
  "contract_name": "...",
  "pragma": "cashscript ^0.10.0",
  "constructor_params": [
    {{"name": "...", "type": "...", "purpose": "..."}}
  ],
  "functions": [
    {{
      "name": "...",
      "params": [{{"name": "...", "type": "..."}}],
      "visibility": "public",
      "structural_guards": [],
      "business_logic": [],
      "primitives_used": []
    }}
  ],
  "state": {{
    "is_stateful": false,
    "state_fields": [],
    "continuation_required": false
  }},
  "metadata": {{
    "intent_tags": ["multisig", "..."]
  }}
}}

Return ONLY the JSON object. No markdown fences. No explanation."""


def _build_phase2_prompt(
    skeleton_code: str,
    intent: str,
    primitives_context: str,
    constraint_summary: str,
    violation_context: str,
    rule_context: str = "",
) -> str:
    """Build the Phase 2 LLM prompt with strict structural security enforcement."""
    
    violation_section = ""
    if violation_context:
        violation_section = f"""
### !!! CRITICAL: FIX PREVIOUS VIOLATIONS !!!
Your previous attempt failed validation. You MUST implement these exact structural fixes:
{violation_context}
"""

    return f"""You are a "Secure CashScript Implementation Engine". 
Your goal is to fill the provided skeleton with logic that passes a rigorous structural safety gate (Phase 3).

{violation_section}

{rule_context}

### EXPLICIT STRUCTURAL PROTOCOLS

#### 1. MULTISIG SAFETY (Threshold = N-of-M)
- **Distinct Pubkeys**: Use `require(pk1 != pk2);` for every pair of pubkeys in the constructor or setup.
- **Unique Signatures**: Every public key MUST have its own unique signature variable (e.g., `aliceSig`, `bobSig`).
- **NO REUSE**: A single signature variable CANNOT be used for multiple checkSig calls.
  *BAD*: `checkSig(s1, p1) && checkSig(s1, p2)` 
  *GOOD*: `checkSig(aliceSig, alice) && checkSig(bobSig, bob)`

#### 2. COVENANT PROPERTY ACCESS ORDERING
- **Validation-First**: Before accessing `tx.outputs[N].value`, `tokenCategory`, or `tokenAmount`, you MUST validate the `lockingBytecode` for that index.
  *MANDATORY PATTERN*: 
  ```cashscript
  require(tx.outputs[0].lockingBytecode == expected_script); // 1. Validate destination
  require(tx.outputs[0].value == 1000);                      // 2. Safe to access value
  ```

#### 3. OUTPUT ANCHORING
- **Strict Limits**: Every spending function MUST have `require(tx.outputs.length == 1);` OR validate the value of every output produced.
- **Clean Outputs**: For change or payout outputs, explicitly validate:
  `require(tx.outputs[N].tokenCategory == NO_TOKEN);`
  `require(tx.outputs[N].tokenAmount == 0);`

#### 4. TEMPORAL ACCURACY
- **Secure Operators**: ALWAYS use `tx.time >= deadline` for "at or after" checks.
- **Forbidden**: Never use `>` or `block.timestamp`.

#### 5. GENERAL SAFETY
- **Input Anchoring**: Always include `require(this.activeInputIndex == 0);` (or correct index).
- **No Fee Logic**: Never calculate fees. Use hardcoded or formula-based output values.
- **Type Safety**: Do not compare `lockingBytecode` (bytes) to `bytes32` constants (e.g. NO_TOKEN).

### CONTEXT
- **Intent**: {intent}
- **Constraints**: {constraint_summary}
- **Primitives**: {primitives_context}

### SKELETON (DO NOT EDIT NAMES/PARAMS)
```cashscript
{skeleton_code}
```

Implement the function bodies now. Return ONLY the complete, compilable `.cash` code. No explanation. No markdown fences."""


def _parse_phase1_response(raw: str, intent: str, security_level: str) -> ContractIR:
    """Parse Phase 1 JSON into ContractIR."""
    try:
        # Clean potential markdown from JSON
        json_str = raw.strip()
        if json_str.startswith('```json'):
            json_str = json_str[7:].strip()
        if json_str.endswith('```'):
            json_str = json_str[:-3].strip()
            
        data = json.loads(json_str)
        # Ensure metadata is populated
        metadata = data.get("metadata", {})
        data["metadata"] = {
            "intent": intent, 
            "intent_tags": metadata.get("intent_tags", []),
            "security_level": security_level,
            "generation_phase": 1
        }
        return ContractIR(**data)
    except Exception as e:
        logger.error(f"Failed to parse Phase 1 response: {e}\nRaw: {raw}")
        # Return a minimal IR as fallback
        return ContractIR(
            contract_name="ErrorFallback",
            constructor_params=[],
            functions=[],
            metadata={"intent": intent, "security_level": security_level, "generation_phase": 1}
        )


def _ir_to_skeleton_code(ir: ContractIR) -> str:
    """Reconstruct a skeletal .cash file from IR."""
    lines = [f"pragma {ir.pragma};", ""]
    
    params = ", ".join([f"{p.type} {p.name}" for p in ir.constructor_params])
    lines.append(f"contract {ir.contract_name}({params}) {{")
    
    for fn in ir.functions:
        params = ", ".join([f"{p.type} {p.name}" for p in fn.params])
        lines.append(f"    function {fn.name}({params}) {{")
        lines.append("        // TODO: Implement logic")
        lines.append("    }")
    
    lines.append("}")
    return "\n".join(lines)


def _extract_cash_code(raw: str) -> str:
    """Extract code from potential markdown fences."""
    if '```' in raw:
        # Search for cashscript or plain fences
        match = re.search(r'```(?:cashscript)?\s*(.*?)\s*```', raw, re.DOTALL)
        if match:
            return match.group(1).strip()
    return raw.strip()


def _truncate_kb_context(context: str, max_lines: int) -> str:
    """Truncate KB context to fit within prompt limits."""
    lines = context.split('\n')
    if len(lines) <= max_lines:
        return context
    return '\n'.join(lines[:max_lines]) + "\n... (context truncated)"


def _build_violation_context(
    violations: List[ViolationDetail],
    retry_count: int,
    kb: object,
) -> str:
    """Build violation context with mandatory structural patterns and targeted KB retrieval."""
    parts = ["### THE FOLLOWING VIOLATIONS WERE DETECTED (MUST BE FIXED):\n"]

    # 1. Provide concrete mandatory structural patterns
    parts.append("#### MANDATORY STRUCTURAL CONSTRAINTS")
    parts.append("You MUST incorporate these exact patterns into your code to pass validation:")
    
    unique_rules = {v.rule.replace(".cash", "") for v in violations}
    for rule in unique_rules:
        pattern = _derive_mandatory_pattern(rule)
        parts.append(f"- [{rule.upper()}]: `{pattern}`")
    parts.append("")

    # 2. Detailed violation list
    parts.append("#### VIOLATION DETAILS")
    for i, v in enumerate(violations, 1):
        parts.append(f"{i}. [{v.severity.upper()}] {v.rule}: {v.reason}")
        parts.append(f"   REASON: {v.exploit}")
        parts.append("")

    # 3. Targeted Anti-Pattern Retrieval (Retry >= 1 ensures better focus)
    if retry_count >= 1 and hasattr(kb, 'get_category_content'):
        parts.append("#### TARGETED ANTI-PATTERN DOCUMENTATION")
        for rule in unique_rules:
            # Query KB for specific anti-pattern documentation
            doc = kb.get_category_content("anti_pattern", keywords=[rule])
            if doc:
                # Limit to 50 lines per doc to keep context tight
                doc_lines = doc.split("\n")[:50]
                parts.append("\n".join(doc_lines))
                parts.append("---")
    
    return "\n".join(parts)


def _derive_mandatory_pattern(rule: str) -> str:
    """Return a deterministic structural code pattern for a given violation."""
    patterns = {
        "implicit_output_ordering": "require(tx.outputs[0].lockingBytecode == expectedScript); // AND ONLY THEN reference value/tokens",
        "missing_output_limit": "require(tx.outputs.length == 1); // Or exact expected count",
        "unvalidated_position": "require(this.activeInputIndex == 0);",
        "fee_assumption_violation": "// REMOVE all (inputValue - outputValue) patterns",
        "evm_hallucination": "// REMOVE msg.sender, mapping, emit, etc.",
        "empty_function_body": "require(checkSig(sig, pk));",
        "semantic_type_mismatch": "require(tx.outputs[N].lockingBytecode == bytes(target)); // Cast to bytes if needed",
        "multisig_distinctness_flaw": "require(pk1 != pk2); require(pk1 != pk3); // For ALL pairs",
        "missing_value_enforcement": "require(tx.outputs[0].value == amount);",
        "weak_output_count_limit": "require(tx.outputs.length == 1);",
        "missing_output_anchor": "require(tx.outputs[0].lockingBytecode == target_script);",
        "time_validation_error": "require(tx.time >= timeout);",
        "division_by_zero": "require(divisor > 0);",
        "tautological_guard": "// DELETE meaningless checks like require(x == x)",
        "locking_bytecode_self_comparison": "require(tx.outputs[0].lockingBytecode == this.lockingBytecode);",
        "multisig_signature_reuse": "require(checkSig(sigAlice, alice) && checkSig(sigBob, bob)); // UNIQUE VARS",
    }
    return patterns.get(rule, "// Review docs for structural requirements.")


def _derive_fix_hint(rule: str) -> str:
    """Map anti-pattern rule ID to a concrete fix hint."""
    hints = {
        "implicit_output_ordering": "Validate lockingBytecode on every tx.outputs[N] before accessing other properties.",
        "missing_output_limit": "Add require(tx.outputs.length == N) in every function.",
        "unvalidated_position": "Add require(this.activeInputIndex == 0) or validate via lockingBytecode.",
        "fee_assumption_violation": "Remove fee calculations. Use exact output amounts.",
        "evm_hallucination": "Remove all Solidity/EVM syntax.",
        "empty_function_body": "Add require() statements enforcing transaction constraints.",
        "semantic_type_mismatch": "Do not compare bytes (lockingBytecode) to bytes32 (tokenCategory/NO_TOKEN).",
        "multisig_distinctness_flaw": "Multisig pubkeys must be distinct. Add require(pk1 != pk2).",
        "missing_value_enforcement": "Spending functions must validate output values or use a strict single-output anchor.",
        "weak_output_count_limit": "Replace >= with an exact match (==) or add an upper bound for tx.outputs.length.",
        "missing_output_anchor": "Escrow functions must have a hard output anchor.",
        "tautological_guard": "Remove tautological comparisons (e.g., x == x).",
        "locking_bytecode_self_comparison": "Do not compare lockingBytecode to itself. Compare it to an anchor.",
        "multisig_signature_reuse": "Use distinct signature variables (s1, s2, ...) for each public key in a multisig check.",
    }
    # Strip .cash suffix for lookup
    clean_rule = rule.replace(".cash", "")
    return hints.get(clean_rule, "Review the anti-pattern documentation for this rule.")


import re

# EVM/Solidity terms that must never appear in CashScript
_EVM_PATTERNS = [
    r'\bmsg\.sender\b',
    r'\bmsg\.value\b',
    r'\bmapping\s*\(',
    r'\bemit\s+\w+',
    r'\bmodifier\s+\w+',
    r'\bpayable\b',
    r'\bview\b',
    r'\bpure\b',
    r'\bconstructor\s*\(',
    r'\bevent\s+\w+',
    r'\baddress\s+payable\b',
    r'\bsolidity\b',
    r'\buint256\b',
    r'\bint256\b',
    r'\bstruct\s+\w+',
    r'\binterface\s+\w+',
    r'\babstract\b',
    r'\bvirtual\b',
    r'\boverride\b',
    r'\brevert\b',
    r'\bassembly\s*\{',
]


def _detect_evm_hallucinations(code: str) -> List[str]:
    """Detect EVM/Solidity terms in CashScript code."""
    flags = []
    for pattern in _EVM_PATTERNS:
        matches = re.findall(pattern, code, re.IGNORECASE)
        if matches:
            flags.append(matches[0])
    return flags


def _detect_empty_functions(code: str) -> List[str]:
    """Detect functions with no require() statements."""
    empty_fns = []
    # Match function blocks: function name(...) { ... }
    fn_pattern = re.compile(
        r'function\s+(\w+)\s*\([^)]*\)\s*\{([^}]*)\}',
        re.DOTALL
    )
    for match in fn_pattern.finditer(code):
        fn_name = match.group(1)
        fn_body = match.group(2)
        if 'require(' not in fn_body:
            empty_fns.append(fn_name)
    return empty_fns
