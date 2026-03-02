"""
golden_prompt.py — Structured Prompt Builder for Golden Adaptation

Responsibility:
  - Load the Golden Template
  - Extract the MUTABLE_CONSTRUCTOR_START/END zone
  - Build a strict constrained prompt for LLM
  - LLM receives ONLY the mutation zones, not the full contract
  - Demand strict JSON schema response (constructor_block + business_logic_block)
  - No freeform output allowed
"""

import re


# ─── Zone Extraction ──────────────────────────────────────────────────────────

def extract_constructor_zone(template: str) -> str:
    """Extract the mutable constructor parameter block."""
    start = "=== MUTABLE_CONSTRUCTOR_START ==="
    end   = "=== MUTABLE_CONSTRUCTOR_END ==="
    si = template.find(start)
    ei = template.find(end)
    if si == -1 or ei == -1:
        raise ValueError("MUTABLE_CONSTRUCTOR markers not found in template")
    return template[si + len(start):ei].strip()


def extract_business_logic_zone(template: str) -> str:
    """Extract the business logic placeholder zone."""
    marker = "=== BUSINESS_LOGIC_ZONE ==="
    si = template.find(marker)
    if si == -1:
        raise ValueError("BUSINESS_LOGIC_ZONE marker not found in template")
    # Everything after the marker until next === marker or end of block
    rest = template[si + len(marker):]
    # Stop at the next zone marker if present
    next_marker = rest.find("=== ")
    if next_marker != -1:
        rest = rest[:next_marker]
    return rest.strip()


# ─── Prompt Builder ──────────────────────────────────────────────────────────

def build_golden_llm_prompt(
    pattern_id: str,
    intent_json: str,
    constructor_zone: str,
    required_parameters: list,
) -> tuple:
    """
    Build a constrained LLM prompt for Golden Adaptation.

    LLM receives:
      - Pattern ID and invariant context
      - Current constructor zone (to understand existing params)
      - User intent JSON
      - Required parameters list

    LLM must return ONLY:
      {
        "constructor_block": "pubkey buyer,\\npubkey seller,...",
        "business_logic_block": "// your injected logic here"
      }

    LLM must NOT rewrite invariant logic.
    LLM must NOT generate the full contract.
    """
    params_str = ", ".join(required_parameters)

    system = f"""You are the NexOps Golden Template Adapter for pattern: {pattern_id.upper()}.

Your ONLY job is to adapt TWO zones of a pre-audited contract template:
1. constructor_block — adapt the constructor parameters to the user's requirements
2. business_logic_block — add optional business logic to the designated zone

MANDATORY CONSTRAINTS:
- You MUST preserve all required parameters: [{params_str}]
- You MUST NOT modify invariant logic (the security core is locked)
- You MUST NOT generate a full contract
- You MUST NOT add require() statements that override invariant anchors
- The business logic zone is for OPTIONAL additions only (fee splits, metadata, extra checks)

OUTPUT FORMAT — Return ONLY this JSON (no markdown, no explanation):
{{
  "constructor_block": "<adapted constructor parameters as CashScript param declarations>",
  "business_logic_block": "<optional CashScript statements for the business logic zone>"
}}"""

    user = f"""PATTERN: {pattern_id}

CURRENT CONSTRUCTOR ZONE:
{constructor_zone}

USER INTENT:
{intent_json}

Adapt the constructor_block to match the user's requirements.
Add any safe, optional logic in business_logic_block.
Return ONLY the JSON object."""

    return system, user


# ─── Response Parser ─────────────────────────────────────────────────────────

def parse_golden_llm_response(raw: str, required_parameters: list) -> dict:
    """
    Parse and validate the LLM's JSON response.

    Validates:
    - Response is valid JSON
    - Contains constructor_block and business_logic_block keys
    - constructor_block contains all required parameters

    Returns dict with {constructor_block, business_logic_block}.
    Raises ValueError on any violation.
    """
    import json

    # Strip markdown fences if present
    raw = raw.strip()
    if raw.startswith("```"):
        raw = re.sub(r"^```[a-z]*\n?", "", raw)
        raw = re.sub(r"\n?```$", "", raw)

    try:
        data = json.loads(raw)
    except json.JSONDecodeError as e:
        raise ValueError(f"LLM returned invalid JSON: {e}\nRaw: {raw[:200]}")

    if "constructor_block" not in data:
        raise ValueError("LLM response missing 'constructor_block'")
    if "business_logic_block" not in data:
        raise ValueError("LLM response missing 'business_logic_block'")

    constructor_block = data["constructor_block"]

    # Validate all required parameters are preserved
    for param in required_parameters:
        if param not in constructor_block:
            raise ValueError(
                f"LLM dropped required parameter '{param}' from constructor_block"
            )

    # Validate no invariant markers leaked into LLM output
    forbidden_tokens = [
        "INVARIANT_ANCHOR_START",
        "INVARIANT_ANCHOR_END",
        "VALUE_ANCHOR",
    ]
    for token in forbidden_tokens:
        if token in constructor_block or token in data["business_logic_block"]:
            raise ValueError(
                f"LLM attempted to write invariant marker '{token}' — rejected"
            )

    return {
        "constructor_block": constructor_block,
        "business_logic_block": data["business_logic_block"],
    }


# ─── Template Recomposer ─────────────────────────────────────────────────────

def recompose_template(template: str, constructor_block: str, business_logic_block: str) -> str:
    """
    Replace mutation zones in template with LLM-generated content.
    Invariant anchors are NOT touched.
    """
    # Replace constructor zone
    cs = "=== MUTABLE_CONSTRUCTOR_START ==="
    ce = "=== MUTABLE_CONSTRUCTOR_END ==="
    si = template.find(cs)
    ei = template.find(ce)
    if si == -1 or ei == -1:
        raise ValueError("Constructor markers missing from template during recomposition")
    template = template[:si + len(cs)] + "\n    " + constructor_block + "\n    " + template[ei:]

    # Replace business logic placeholder
    bl = "=== BUSINESS_LOGIC_ZONE ==="
    bi = template.find(bl)
    if bi == -1:
        raise ValueError("BUSINESS_LOGIC_ZONE marker missing during recomposition")
    # Find the next marker after business logic to know where to stop replacing
    rest_start = bi + len(bl)
    next_marker = template.find("=== ", rest_start)
    if next_marker != -1:
        template = template[:rest_start] + "\n        " + business_logic_block + "\n\n        " + template[next_marker:]
    else:
        template = template[:rest_start] + "\n        " + business_logic_block + "\n"

    return template
