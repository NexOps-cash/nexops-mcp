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
        prompt = _build_phase2_prompt(
            skeleton_code=skeleton_code,
            intent=ir.metadata.intent,
            primitives_context=_truncate_kb_context(primitives_context, max_lines=200),
            constraint_summary=constraint_summary,
            violation_context=violation_context,
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
  }}
}}

Return ONLY the JSON object. No markdown fences. No explanation."""


def _build_phase2_prompt(
    skeleton_code: str,
    intent: str,
    primitives_context: str,
    constraint_summary: str,
    violation_context: str,
) -> str:
    """Build the Phase 2 LLM prompt with a focus on structural fixes and distinctness."""
    
    # Check for multisig context to inject explicit distinctness rule
    is_multisig = "pubkey" in skeleton_code and skeleton_code.count("pubkey") >= 2
    distinctness_rule = ""
    if is_multisig:
        distinctness_rule = "\n16. MULTISIG SAFETY: Signatures MUST originate from distinct public keys. Enforce `require(pk1 != pk2);` for all pubkey pairs."

    violation_section = ""
    if violation_context:
        violation_section = f"""
!!! MANDATORY FIXES FOR PREVIOUS VIOLATIONS !!!
You previously failed security validation. You MUST implement the structural patterns provided below.
Failure to use these EXACT patterns will result in immediate rejection.

{violation_context}
"""

    return f"""You are a CashScript implementation engine operating under strict security protocols.

Your objective: Implement the logic for the provided CashScript skeleton while satisfying all security invariants.

{violation_section}

### HARD RULES (NON-NEGOTIABLE):
1. Do NOT change the contract name, function names, or parameters.
2. Every public function MUST contain at least one require(...) enforcing a transaction constraint.
3. ALWAYS validate `this.activeInputIndex` in every function.
4. ALWAYS validate `tx.outputs.length` in every function.
5. ALWAYS validate `tx.outputs[N].lockingBytecode` BEFORE using other properties of that output.
6. NEVER assume output ordering — validate semantically via lockingBytecode.
7. NEVER calculate fees (no inputValue - outputValue patterns).
8. Use `>=` for "at or after" time checks, `<` for "before" — NEVER use `>`.
9. If dividing, ALWAYS `require(divisor > 0)` before the division.
10. Use `pragma cashscript ^0.10.0;` at the top.
11. REMOVE all Solidity/EVM syntax (msg.sender, mapping, etc.).
12. Ensure all `require()` comparisons use compatible types (no bytes vs bytes32/NO_TOKEN).
13. Spending functions MUST validate output values or use a strict `tx.outputs.length == 1` anchor.
14. Escrow/Multisig functions MUST bind outputs to a specific `lockingBytecode`.
15. NO PLACEHOLDER COMMENTS. Functional code only.{distinctness_rule}

### SECURITY PRIMITIVES (MANDATORY PATTERNS):
{primitives_context}

### ANTI-PATTERN SUMMARY:
{constraint_summary}

### SKELETON TO IMPLEMENT:
```cashscript
{skeleton_code}
```

Intent: "{intent}"

Output ONLY the complete .cash code. No explanation. No markdown fences."""


def _parse_phase1_response(raw: str, intent: str, security_level: str) -> ContractIR:
    """Parse LLM JSON output into ContractIR."""
    # Strip markdown fences if present
    clean = raw.strip()
    if clean.startswith("```"):
        lines = clean.split("\n")
        lines = [l for l in lines if not l.strip().startswith("```")]
        clean = "\n".join(lines)

    try:
        data = json.loads(clean)
    except json.JSONDecodeError as e:
        logger.error(f"Phase 1 JSON parse failed: {e}. Raw: {raw[:200]}")
        raise ValueError(f"Phase 1 returned invalid JSON: {e}")

    ir = ContractIR(**data)
    ir.metadata.intent = intent
    ir.metadata.security_level = security_level
    return ir


def _ir_to_skeleton_code(ir: ContractIR) -> str:
    """Convert ContractIR to a .cash skeleton string for Phase 2 input."""
    lines = [f"pragma {ir.pragma};", ""]

    # Contract declaration
    params_str = ", ".join(
        f"{p.type} {p.name}" for p in ir.constructor_params
    )
    lines.append(f"contract {ir.contract_name}({params_str}) {{")

    for fn in ir.functions:
        fn_params_str = ", ".join(f"{p.type} {p.name}" for p in fn.params)
        lines.append(f"    function {fn.name}({fn_params_str}) {{")
        lines.append("        // TODO: Implement logic")
        lines.append("    }")
        lines.append("")

    lines.append("}")
    return "\n".join(lines)


def _extract_cash_code(raw: str) -> str:
    """Extract CashScript code from LLM response, stripping markdown fences."""
    clean = raw.strip()

    # Remove ```cashscript ... ``` or ``` ... ``` wrappers
    if clean.startswith("```"):
        lines = clean.split("\n")
        # Drop first line (```cashscript or ```)
        lines = lines[1:]
        # Drop last ``` if present
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        clean = "\n".join(lines).strip()

    if not clean:
        raise ValueError("Phase 2 returned empty code")

    return clean


def _truncate_kb_context(context: str, max_lines: int) -> str:
    """Truncate KB context to fit within token budget."""
    if not context:
        return ""
    lines = context.split("\n")
    if len(lines) <= max_lines:
        return context
    return "\n".join(lines[:max_lines]) + "\n// ... (truncated for context window)"


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
        "implicit_output_ordering": "require(tx.outputs[N].lockingBytecode == target); // FIRST check for index N",
        "missing_output_limit": "require(tx.outputs.length == FIXED_COUNT);",
        "unvalidated_position": "require(this.activeInputIndex == 0);",
        "fee_assumption_violation": "// REMOVE all inputValue - outputValue patterns",
        "evm_hallucination": "// REMOVE all msg.sender, mapping, emit, and payable terms",
        "empty_function_body": "require(checkSig(sig, pk)); // Add at least one constraint",
        "semantic_type_mismatch": "require(tx.outputs[N].lockingBytecode == bytes(target)); // No bytes32/NO_TOKEN",
        "multisig_distinctness_flaw": "require(pk1 != pk2); // Enforce distinctness for all pubkey pairs",
        "missing_value_enforcement": "require(tx.outputs[N].value == amount); OR require(tx.outputs.length == 1);",
        "weak_output_count_limit": "require(tx.outputs.length == 1); // Use exact match instead of >=",
        "missing_output_anchor": "require(tx.outputs[0].lockingBytecode == target_script);",
        "time_validation_error": "require(tx.time >= deadline); // NEVER use >",
        "division_by_zero": "require(divisor > 0); a / divisor;",
    }
    return patterns.get(rule, "// Review anti-pattern docs for structural requirements.")


def _derive_fix_hint(rule: str) -> str:
    """Map anti-pattern rule ID to a concrete fix hint."""
    hints = {
        "implicit_output_ordering": "Validate lockingBytecode on every tx.outputs[N] before accessing other properties.",
        "missing_output_limit": "Add require(tx.outputs.length == N) in every function.",
        "unvalidated_position": "Add require(this.activeInputIndex == 0) or validate via lockingBytecode.",
        "fee_assumption_violation": "Remove fee calculations. Let the caller specify exact output amounts.",
        "evm_hallucination": "Remove all Solidity/EVM syntax. Use CashScript constructs only.",
        "empty_function_body": "Add require() statements enforcing transaction constraints.",
        "semantic_type_mismatch": "Type mismatch in comparison. Do not compare bytes (lockingBytecode) to bytes32 (tokenCategory/NO_TOKEN).",
        "multisig_distinctness_flaw": "Multisig pubkeys must be distinct. Add require(pk1 != pk2).",
        "missing_value_enforcement": "Spending functions must validate output values or use a strict single-output anchor (== 1).",
        "weak_output_count_limit": "Replace >= with an exact match (==) or add an upper bound for tx.outputs.length.",
        "missing_output_anchor": "Escrow functions must have a hard output anchor (lockingBytecode or value validation).",
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
