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


def build_golden_retry_prompt(
    original_system: str,
    original_user: str,
    previous_response: str,
    error_message: str,
) -> tuple:
    """
    Build a corrective retry prompt.

    Appends a strict correction instruction to the original user prompt.
    The system prompt (invariant constraints) is never altered.
    Tells the LLM exactly what failed and what it must fix.
    """
    correction = f"""---
YOUR PREVIOUS OUTPUT WAS REJECTED.

Reason for rejection:
{error_message}

Previous invalid response:
{previous_response}

You MUST correct ONLY the specific issue(s) described above.

CORRECTION RULES (non-negotiable):
- Do NOT modify invariant anchor logic
- Do NOT include: require(  checkSig(  checkMultiSig(  in business_logic_block
- Preserve ALL required constructor parameters — no deletions allowed
- Output STRICT JSON with EXACTLY these two keys and NO others:
  {{
    "constructor_block": "...",
    "business_logic_block": "..."
  }}

Return corrected JSON only. No explanation. No markdown."""

    return original_system, original_user + "\n\n" + correction


# ─── Response Parser ─────────────────────────────────────────────────────────

def parse_golden_llm_response(raw: str, required_parameters: list, template_param_count: int) -> dict:
    """
    Parse and validate the LLM's JSON response for Golden adaptation.

    Guards (in order):
      1. Strict JSON schema — exactly 2 keys, no extras, no missing
      2. Length sanity — no empty or absurdly long output
      3. Forbidden token scan — invariant + security primitive tokens blocked in business logic
      4. Parameter count preservation — LLM cannot remove constructor params

    Raises ValueError on any violation. No auto-correction.
    """
    import json

    # ──────────────────────────────────────────────────────────────────
    # GUARD 0: Strip markdown fences (only structural cleanup, not correction)
    # ──────────────────────────────────────────────────────────────────
    raw = raw.strip()
    if raw.startswith("```"):
        raw = re.sub(r"^```[a-z]*\n?", "", raw)
        raw = re.sub(r"\n?```$", "", raw)
    raw = raw.strip()

    # ──────────────────────────────────────────────────────────────────
    # GUARD 1: Strict JSON schema — valid JSON, exactly 2 required keys
    # ──────────────────────────────────────────────────────────────────
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as e:
        raise ValueError(f"[Guard 1] LLM returned invalid JSON: {e}\nRaw: {raw[:300]}")

    REQUIRED_KEYS = {"constructor_block", "business_logic_block"}
    actual_keys = set(data.keys())

    missing_keys = REQUIRED_KEYS - actual_keys
    if missing_keys:
        raise ValueError(f"[Guard 1] LLM response missing required keys: {missing_keys}")

    extra_keys = actual_keys - REQUIRED_KEYS
    if extra_keys:
        raise ValueError(f"[Guard 1] LLM response contains unexpected keys: {extra_keys} — zero tolerance")

    constructor_block    = data["constructor_block"]
    business_logic_block = data["business_logic_block"]

    # ──────────────────────────────────────────────────────────────────
    # GUARD 2: Length sanity check
    # ──────────────────────────────────────────────────────────────────
    MAX_BUSINESS_LOGIC_CHARS = 2000

    if not constructor_block or not constructor_block.strip():
        raise ValueError("[Guard 2] constructor_block is empty — rejected")

    if len(business_logic_block) > MAX_BUSINESS_LOGIC_CHARS:
        raise ValueError(
            f"[Guard 2] business_logic_block too long: {len(business_logic_block)} chars "
            f"(max {MAX_BUSINESS_LOGIC_CHARS}) — possible prompt injection"
        )

    # ──────────────────────────────────────────────────────────────────
    # GUARD 3: Forbidden token scan in business_logic_block
    # Any attempt to rewrite invariants or re-define security primitives is rejected.
    # ──────────────────────────────────────────────────────────────────
    FORBIDDEN_IN_BUSINESS_LOGIC = [
        # Invariant zone markers
        "INVARIANT_ANCHOR_START",
        "INVARIANT_ANCHOR_END",
        "VALUE_ANCHOR",
        # Security primitives — must not be redefined in business logic zone
        "require(",
        "checkSig(",
        "checkMultiSig(",
    ]

    for token in FORBIDDEN_IN_BUSINESS_LOGIC:
        if token in business_logic_block:
            raise ValueError(
                f"[Guard 3] Forbidden token '{token}' found in business_logic_block — "
                "LLM attempted to rewrite security logic"
            )

    # Also scan constructor_block for invariant marker leakage
    for token in ["INVARIANT_ANCHOR_START", "INVARIANT_ANCHOR_END", "VALUE_ANCHOR"]:
        if token in constructor_block:
            raise ValueError(
                f"[Guard 3] Invariant marker '{token}' leaked into constructor_block — rejected"
            )

    # ──────────────────────────────────────────────────────────────────
    # GUARD 4: Parameter count preservation
    # LLM cannot reduce number of constructor parameters
    # ──────────────────────────────────────────────────────────────────
    # Count comma-separated declarations (crude but reliable for CashScript params)
    returned_param_count = len([p for p in constructor_block.split(",") if p.strip()])

    if returned_param_count < template_param_count:
        raise ValueError(
            f"[Guard 4] Constructor parameter count decreased: "
            f"template had {template_param_count}, LLM returned {returned_param_count} — "
            "no deletions allowed"
        )

    # Guard 4b: All named required parameters must be present
    for param in required_parameters:
        if param not in constructor_block:
            raise ValueError(
                f"[Guard 4] Required parameter '{param}' missing from constructor_block"
            )

    return {
        "constructor_block":    constructor_block,
        "business_logic_block": business_logic_block,
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
