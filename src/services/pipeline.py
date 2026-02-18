"""
3-Phase Generation Pipeline

Phase1 — Skeleton generation (LLM → ContractIR)
Phase2 — Logic fill (ContractIR + Structured KB → .cash code)
Phase3 — Toll gate (deterministic validation → TollGateResult)
"""

import json
import yaml
import logging
import re
from pathlib import Path
from typing import List, Optional

from src.models import (
    ContractIR,
    TollGateResult,
    ViolationDetail,
    IntentModel,
)
from src.services.llm.factory import LLMFactory
from src.services.anti_pattern_enforcer import get_anti_pattern_enforcer
from src.services.rule_engine import get_rule_engine

logger = logging.getLogger("nexops.pipeline")

MAX_RETRIES = 3

# ─── Structured Knowledge Loader ─────────────────────────────────────

_structured_knowledge_cache: Optional[str] = None

def load_structured_knowledge() -> str:
    """Load and cache the 3 YAML knowledge packs as a compact JSON string."""
    global _structured_knowledge_cache
    if _structured_knowledge_cache is not None:
        return _structured_knowledge_cache

    base = Path("src/knowledge/structured")
    try:
        with open(base / "cashscript_capabilities.yaml", encoding="utf-8") as f:
            caps = yaml.safe_load(f)
        with open(base / "covenant_security_rules.yaml", encoding="utf-8") as f:
            sec = yaml.safe_load(f)
        with open(base / "anti_solidity_guard.yaml", encoding="utf-8") as f:
            guard = yaml.safe_load(f)

        _structured_knowledge_cache = json.dumps(
            {"capabilities": caps, "security": sec, "guard": guard},
            separators=(",", ":")
        )
        logger.info(f"[KB] Structured knowledge loaded: {len(_structured_knowledge_cache)} chars")
    except Exception as e:
        logger.error(f"[KB] Failed to load structured knowledge: {e}")
        _structured_knowledge_cache = "{}"

    return _structured_knowledge_cache


# ─── Phase 1: Skeleton Generator ─────────────────────────────────────

class Phase1:
    """Analyze user intent into a structured IntentModel. Returns ContractIR."""

    @staticmethod
    async def run(intent: str, security_level: str = "high") -> ContractIR:
        """Call LLM to parse raw text into an IntentModel."""

        prompt = _build_phase1_prompt(intent, security_level)

        llm = LLMFactory.get_provider("phase1")
        raw_response = await llm.complete(prompt)

        # Parse LLM JSON response into IntentModel and wrap in ContractIR
        ir = _parse_phase1_response(raw_response, intent, security_level)
        ir.metadata.generation_phase = 1
        
        tags = ir.metadata.intent_model.features if ir.metadata.intent_model else []
        logger.info(f"Phase 1 complete: type={ir.metadata.intent_model.contract_type if ir.metadata.intent_model else 'unknown'}, tags={tags}")
        return ir


# ─── Phase 2: Logic Fill ─────────────────────────────────────────────

class Phase2:
    """Fill business logic into skeleton. Returns compilable .cash code."""

    @staticmethod
    async def run(
        ir: ContractIR,
        violations: Optional[List[ViolationDetail]] = None,
        retry_count: int = 0,
        temperature: float = 0.3,
    ) -> str:
        """Stage 2A: Generate .cash code from structured IntentModel."""

        # Load structured knowledge (cached after first call)
        structured_knowledge = load_structured_knowledge()

        # Build violation context only on retry
        violation_context = ""
        if violations and retry_count > 0:
            violation_context = _build_violation_context(violations, retry_count, None)

        # Activate Rules based on intent model features
        rule_engine = get_rule_engine()
        intent_model = ir.metadata.intent_model
        tags = intent_model.features if intent_model else []
        active_rules = rule_engine.get_rules_for_tags(tags)
        rule_context = rule_engine.format_rules_for_prompt(active_rules)

        prompt = _build_phase2_prompt(
            intent_model=intent_model,
            structured_knowledge=structured_knowledge,
            violation_context=violation_context,
            rule_context=rule_context,
        )

        logger.info(f"[Phase2] Prompt length: {len(prompt)} chars, retry={retry_count}")

        llm = LLMFactory.get_provider("phase2")
        raw_response = await llm.complete(prompt, temperature=temperature)

        # Extract .cash code from response
        code = _extract_cash_code(raw_response)
        ir.metadata.generation_phase = 2
        ir.metadata.retry_count = retry_count
        logger.info(f"Phase 2A complete: {len(code)} chars, retry={retry_count}, temp={temperature}")
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


def _build_phase1_prompt(intent: str, security_level: str) -> str:
    """Build the Phase 1 Intent Parsing prompt."""
    return f"""You are the "NexOps Intent Parser". Your goal is to convert raw user requests into a structured machine-readable model.

Rules:
1. Identify the high-level `contract_type` (e.g., escrow, multisig, vesting, swap).
2. Extract specific `features` from this set: [multisig, timelock, stateful, spending, tokens, minting, burn].
3. Identify `signers` (names or roles mentioned).
4. Extract `threshold` if multisig is implied.
5. Extract `timeout_days` if a temporal constraint is mentioned.
6. Summarize the technical `purpose` in one sentence.

User Request: "{intent}"

Output ONLY valid JSON:
{{
  "contract_type": "...",
  "features": ["...", "..."],
  "signers": ["...", "..."],
  "threshold": N,
  "timeout_days": N,
  "purpose": "..."
}}

Return ONLY the JSON object. No markdown fences. No explanation."""


def _build_phase2_prompt(
    intent_model: Optional[IntentModel],
    structured_knowledge: str,
    violation_context: str,
    rule_context: str = "",
) -> str:
    """Stage 2A: Build Implementation Prompt from IntentModel using structured knowledge."""
    
    intent_json = intent_model.model_dump_json(indent=2) if intent_model else "{}"
    
    violation_section = ""
    if violation_context:
        violation_section = f"""
### !!! CRITICAL: FIX PREVIOUS VIOLATIONS !!!
{violation_context}
"""

    rule_section = f"\n{rule_context}\n" if rule_context else ""

    return f"""You are a "Secure CashScript Implementation Engine".
Generate complete, compilable CashScript code from the provided Intent Model.

{violation_section}
{rule_section}
### SYSTEM KNOWLEDGE (STRICT RULES):
{structured_knowledge}

### INTENT MODEL (SOLE SOURCE OF TRUTH):
{intent_json}

### FINAL OUTPUT INSTRUCTIONS (STRICT)
- Return ONLY the complete, compilable `.cash` code.
- DO NOT explain the code.
- DO NOT include markdown fences (```).
- DO NOT include reasoning traces or thought chains.
- DO NOT include any text before or after the code.
- FAILURE TO COMPLY WILL CAUSE SYSTEM REJECTION.

Begin code:"""


def _parse_phase1_response(raw: str, intent: str, security_level: str) -> ContractIR:
    """Parse Phase 1 JSON into ContractIR containing an IntentModel."""
    try:
        from src.models import IntentModel, ContractMetadata
        
        # Clean potential markdown from JSON
        json_str = raw.strip()
        if json_str.startswith('```json'):
            json_str = json_str[7:].strip()
        if json_str.endswith('```'):
            json_str = json_str[:-3].strip()
            
        data = json.loads(json_str)
        model = IntentModel(**data)
        
        ir = ContractIR(
            contract_name="GeneratedContract", # Placeholder, Phase 2 might refine
            constructor_params=[], # Will be generated in Phase 2
            functions=[],          # Will be generated in Phase 2
            metadata=ContractMetadata(
                intent=intent,
                intent_model=model,
                security_level=security_level,
                generation_phase=1
            )
        )
        return ir
    except Exception as e:
        logger.error(f"Failed to parse Phase 1 response: {e}\nRaw: {raw}")
        return ContractIR(
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

    # 3. Targeted Anti-Pattern Retrieval (REMOVED CODE INJECTION)
    # We no longer provide raw .cash code to avoid prompt contamination.
    # Instead, we rely on the derived mandatory patterns and violation reasons.
    
    return "\n".join(parts)


def _derive_mandatory_pattern(rule: str) -> str:
    """Return a deterministic structural description for a given violation (avoiding forbidden syntax)."""
    patterns = {
        "implicit_output_ordering": "Validate destination values ONLY AFTER establishing output count and index consistency.",
        "missing_output_limit": "require(tx.outputs.length == 1); // Or exact expected count",
        "unvalidated_position": "require(this.activeInputIndex == 0);",
        "fee_assumption_violation": "REMOVE all (inputValue - outputValue) patterns. Use fixed output values.",
        "evm_hallucination": "REMOVE msg.sender, mapping, emit, modifier, payable, etc.",
        "empty_function_body": "Implement function logic using require() checks.",
        "semantic_type_mismatch": "Ensure type consistency in comparisons.",
        "multisig_distinctness_flaw": "require(pk1 != pk2); require(pk1 != pk3); // Distinctness check for ALL signer pairs",
        "missing_value_enforcement": "require(tx.outputs[0].value == amount);",
        "weak_output_count_limit": "require(tx.outputs.length == 1);",
        "missing_output_anchor": "Ensure the spending function has a deterministic output target.",
        "time_validation_error": "require(tx.time >= timeout);",
        "division_by_zero": "require(divisor > 0);",
        "tautological_guard": "REMOVE meaningless checks like require(x == x)",
        "locking_bytecode_self_comparison": "Avoid self-comparison of transaction properties.",
        "multisig_signature_reuse": "Use distinct signature variables (sig1, sig2, etc.) for each signer in a multisig check.",
    }
    return patterns.get(rule, "Implement security logic following the Intent Model.")


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
    r'\.lockingBytecode\b',
    r'\.tokenCategory\b',
    r'\.tokenAmount\b',
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
