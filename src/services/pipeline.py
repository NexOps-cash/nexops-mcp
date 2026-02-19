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


# ─── Unified DSL Rules (Steps 2 + 3) ─────────────────────────────────────────
# Single source of truth injected into BOTH synthesis AND fix loop prompts.
# Edit here; nowhere else.

def build_unified_dsl_rules() -> str:
    """
    Canonical, version-pinned DSL rule block for CashScript ^0.13.0.

    Injected verbatim into:
      - Phase 2 synthesis system prompt
      - Syntax-fix loop system prompt

    NEVER duplicate or diverge these rules elsewhere.
    """
    return """=== CashScript ^0.13.0 DSL RULES (non-negotiable) ===

VERSION: Target ONLY CashScript ^0.13.0. Do NOT use deprecated 0.12.x patterns.

FILE STRUCTURE:
- First line MUST be: pragma cashscript ^0.13.0;
- Only contract { ... } at file scope. No bare statements.

SELF-REFERENCE:
- this.activeBytecode     ← CORRECT (^0.13.0)
- this.lockingBytecode    ← DOES NOT EXIST — FORBIDDEN

INPUT ACCESS:
- tx.inputs[this.activeInputIndex].value  ← ALWAYS use activeInputIndex
- tx.inputs[0]                            ← FORBIDDEN — hardcoded index
- tx.inputs[i].time                       ← DOES NOT EXIST — use tx.time

OUTPUT RULES:
- require(tx.outputs.length == N) BEFORE accessing any tx.outputs[i]
- require(tx.outputs[0].value == tx.inputs[this.activeInputIndex].value)  ← MANDATORY value anchor
- NEVER subtract fees: e.g. .value - fee  ← FORBIDDEN
- Use a named constructor param (int fee) if fee is needed

VALIDATION:
- Use require() for ALL validation — no return values, no if/else branching
- this.activeInputIndex == 0 in a require() ← FORBIDDEN — not a security guard

MULTISIG:
- Accumulate: int valid = 0; valid += checkSig(s1, pk1) ? 1 : 0; require(valid >= N);
- NEVER nest &&/|| for threshold logic
- require(pk1 != pk2) for ALL key pairs (distinctness)

TIMELOCK:
- tx.time >= N is CLTV (block height or timestamp)
- tx.age  >= N is CSV  (relative timelock)

TYPES (^0.13.0):
- LockingBytecodeP2PKH(bytes20 hash)  ← valid constructor
- LockingBytecodeP2SH20(bytes20 hash) ← valid constructor
- bytes32 vs bytes20: these are DISTINCT — never assign without cast

FORBIDDEN KEYWORDS (Solidity / EVM — causes rejection):
msg.sender, mapping, emit, modifier, payable, view, pure,
constructor(), uint256, address, event, indexed"""

# ─── Structured Knowledge Loader ─────────────────────────────────────

# Tags that require covenant/output/token validation rules
_COVENANT_TAGS = {"covenant", "stateful", "tokens", "minting", "burn", "escrow", "spending"}

# YAML file cache: filename -> parsed dict
_yaml_cache: dict = {}

def _load_yaml(filename: str) -> dict:
    """Load and cache a YAML file from src/services/knowledge_structured/."""
    if filename in _yaml_cache:
        return _yaml_cache[filename]
    base = Path("src/services/knowledge_structured")
    try:
        with open(base / filename, encoding="utf-8") as f:
            data = yaml.safe_load(f)
        _yaml_cache[filename] = data
        return data
    except Exception as e:
        logger.error(f"[KB] Failed to load {filename}: {e}")
        return {}


def build_structured_knowledge(ir: ContractIR) -> str:
    """Build a compact YAML knowledge string, conditionally injecting covenant rules."""
    intent_model = ir.metadata.intent_model if ir.metadata else None
    tags = set(intent_model.features if intent_model else [])

    knowledge = {
        "core": _load_yaml("core_language.yaml"),
        "synthesis": _load_yaml("synthesis_rules.yaml"),
    }

    # Inject covenant/token rules only when the contract requires them
    needs_covenant = bool(tags & _COVENANT_TAGS)
    if needs_covenant:
        knowledge["security"] = _load_yaml("covenant_security.yaml")

    injected_layers = list(knowledge.keys())
    logger.info(f"[Phase2] Injected knowledge layers: {injected_layers} (tags={sorted(tags)})")

    # Emit as YAML string — preserves hierarchy better than JSON for LLM comprehension
    return yaml.dump(knowledge, sort_keys=False, allow_unicode=True, default_flow_style=False)


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

        # ─── Feature Enrichment Layer (Deterministic) ───────────────────
        # LLM classifies. Engine enforces structure.
        # Do NOT rely purely on LLM for escrow tagging.
        tags = list(ir.metadata.intent_model.features) if ir.metadata.intent_model else []

        # Structural inference: timelock + multisig = escrow pattern
        if "timelock" in tags and "multisig" in tags:
            tags.append("escrow")

        # Keyword heuristic: reclaim/refund/timeout intent implies escrow
        _ESCROW_KEYWORDS = {"refund", "reclaim", "timeout", "after", "expire", "expiry", "deadline"}
        if any(word in intent.lower() for word in _ESCROW_KEYWORDS):
            if "multisig" in tags:
                tags.append("escrow")

        # Deduplicate while preserving order
        seen = set()
        tags = [t for t in tags if not (t in seen or seen.add(t))]

        # Write enriched tags back to the model
        if ir.metadata.intent_model:
            ir.metadata.intent_model.features = tags

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

        # Build feature-gated structured knowledge (covenant rules injected conditionally)
        structured_knowledge = build_structured_knowledge(ir)

        # Build compact violation context only on retry
        violation_context = ""
        if violations and retry_count > 0:
            violation_context = _build_violation_context(violations)

        # Activate Rules based on intent model features
        rule_engine = get_rule_engine()
        intent_model = ir.metadata.intent_model
        tags = intent_model.features if intent_model else []
        active_rules = rule_engine.get_rules_for_tags(tags)
        rule_context = rule_engine.format_rules_for_prompt(active_rules)

        # Determine if covenant rules were injected (for conditional prompt instruction)
        needs_covenant = bool(set(tags) & _COVENANT_TAGS)

        # Build layered system + user prompt
        system_prompt, user_prompt = _build_phase2_prompt(
            intent_model=intent_model,
            structured_knowledge=structured_knowledge,
            violation_context=violation_context,
            rule_context=rule_context,
            needs_covenant=needs_covenant,
        )

        total_chars = len(system_prompt) + len(user_prompt)
        logger.info(f"[Phase2] Prompt length: {total_chars} chars (sys={len(system_prompt)}, user={len(user_prompt)}), retry={retry_count}")

        llm = LLMFactory.get_provider("phase2")
        raw_response = await llm.complete(user_prompt, system=system_prompt, temperature=temperature)

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
    needs_covenant: bool = False,
) -> tuple:
    """Build layered Phase 2 prompt. Returns (system_prompt, user_prompt) tuple.
    
    system_prompt: static role + DSL rules (~800-1200 chars, cacheable)
    user_prompt: compact intent JSON + KB + optional violations (dynamic)
    """
    # ── SYSTEM PROMPT (static, cacheable) ──────────────────────────────
    if needs_covenant:
        covenant_rule = (
            "COVENANT MODE: require(tx.outputs.length==1); "
            "require(tx.outputs[0].lockingBytecode==this.activeBytecode); "
            "require(tx.outputs[0].value==tx.inputs[this.activeInputIndex].value); "
            "Also validate tokenCategory/tokenAmount if tokens involved."
        )
    else:
        covenant_rule = (
            "SIGNATURE-ONLY MODE: Use ONLY checkSig()/checkMultiSig() and require(). "
            "If contract performs a split, enforce exact tx.outputs.length == N and "
            "sum-preservation value invariant. "
            "If single-output spend, enforce strict single-output value anchor. "
            "DO NOT add lockingBytecode continuity checks."
        )

    unified_rules = build_unified_dsl_rules()

    system_prompt = f"""You are a Secure CashScript Code Generator. Output ONLY compilable CashScript ^0.13.0 code.

{unified_rules}

CONTRACT MODE: {covenant_rule}

OUTPUT: Return ONLY the .cash source. No markdown fences. No comments explaining rules. No reasoning traces."""

    # ── USER PROMPT (dynamic) ───────────────────────────────────────────
    # Compact intent JSON — no indentation
    intent_json = intent_model.model_dump_json() if intent_model else "{}"

    parts = []

    if violation_context:
        parts.append(f"VIOLATIONS TO FIX:\n{violation_context}")

    if rule_context:
        parts.append(rule_context)

    parts.append(f"KNOWLEDGE:\n{structured_knowledge}")
    parts.append(f"INTENT:{intent_json}")
    parts.append("Generate the complete CashScript contract now:")

    user_prompt = "\n\n".join(parts)

    return system_prompt, user_prompt


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
    """Extract .cash code from LLM response, stripping chatter and markdown fences."""
    raw = raw.strip()

    # Strip any LLM chatter before the pragma (e.g. "Here's the fixed code:\n")
    raw = re.sub(r"^.*?(?=pragma cashscript)", "", raw, flags=re.DOTALL | re.IGNORECASE)

    # Handle markdown fences if pragma stripping didn't find a clean start
    if '```' in raw:
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


def _build_violation_context(violations: List[ViolationDetail]) -> str:
    """Build compact one-liner violation context. No essays, no markdown headers."""
    lines = []
    for v in violations:
        rule = v.rule.replace(".cash", "")
        hint = _derive_mandatory_pattern(rule)
        lines.append(f"- {rule} → {hint}")
    return "\n".join(lines)


def _derive_mandatory_pattern(rule: str) -> str:
    """Return a deterministic structural description for a given violation (avoiding forbidden syntax)."""
    patterns = {
        "implicit_output_ordering": "Validate destination values ONLY AFTER establishing output count and index consistency.",
        "missing_output_limit": "require(tx.outputs.length == 1); // Or exact expected count",
        "unvalidated_position": "Validate output index via explicit tx.outputs.length guard before accessing tx.outputs[N].",
        "fee_assumption_violation": "REMOVE all (inputValue - outputValue) patterns. Use fixed output values.",
        "evm_hallucination": "REMOVE msg.sender, mapping, emit, modifier, payable, etc.",
        "empty_function_body": "Implement function logic using require() checks.",
        "semantic_type_mismatch": "Ensure type consistency in comparisons.",
        "multisig_distinctness_flaw": "require(pk1 != pk2); require(pk1 != pk3); // Distinctness check for ALL signer pairs",
        "missing_value_enforcement": "Enforce exact value preservation using either direct anchor (out[N] == input value) OR sum-preservation (out[0] + out[1] == input value).",
        "weak_output_count_limit": "require(tx.outputs.length == 1);",
        "missing_output_anchor": "Only required for escrow/stateful contracts. Skip for signature-only contracts. For covenant contracts: require(tx.outputs[0].lockingBytecode == this.activeBytecode);",
        "time_validation_error": "require(tx.time >= timeout);  // tx.time is block time. NEVER use tx.inputs[i].time — it does not exist.",
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
        "unvalidated_position": "Add explicit require(tx.outputs.length == N) and validate output index before accessing tx.outputs[N].",
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

# EVM/Solidity terms that must NEVER appear in CashScript.
# NOTE: .lockingBytecode, .tokenCategory, .tokenAmount are VALID CashScript fields.
# They belong in covenant_security.yaml validation, NOT here.
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
    # Invalid CashScript timelock fields — correct fields are tx.time and tx.age
    r'tx\.inputs\[.*?\]\.time\b',
    r'tx\.inputs\[.*?\]\.age\b',
    # Invalid self-reference — correct field is this.activeBytecode
    r'this\.lockingBytecode\b',
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
