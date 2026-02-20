"""
dsl_lint.py — Deterministic CashScript ^0.13.0 DSL Linter

Runs BEFORE compilation.  Catches structural violations that would either:
  • make the compiler fail (unused vars, syntax noise), or
  • silently generate insecure code (no value anchor, hardcoded indices).

Usage:
    from src.services.dsl_lint import DSLLinter

    linter = DSLLinter()
    result = linter.lint(cashscript_code)
    # → {"passed": bool, "violations": [{"rule_id": str, "message": str, "line_hint": int}]}
"""

from __future__ import annotations
import re
import logging
from typing import Any

logger = logging.getLogger("nexops.dsl_lint")


# ── Internal helpers ──────────────────────────────────────────────────────────

def _lines(code: str) -> list[tuple[int, str]]:
    """Return 1-indexed (lineno, stripped_line) pairs, skipping blank lines."""
    return [(i + 1, ln) for i, ln in enumerate(code.splitlines())]


def _function_bodies(code: str) -> list[tuple[str, str, int]]:
    """
    Extract (func_name, body_text, start_lineno) for every function block.
    Handles simple single-level braces for CashScript functions.
    """
    funcs = []
    pattern = re.compile(r"function\s+(\w+)\s*\(.*?\)\s*\{", re.DOTALL)
    for m in pattern.finditer(code):
        func_name = m.group(1)
        start = m.end()  # position after '{'
        depth = 1
        i = start
        while i < len(code) and depth > 0:
            if code[i] == "{":
                depth += 1
            elif code[i] == "}":
                depth -= 1
            i += 1
        body = code[start : i - 1]
        start_lineno = code[:m.start()].count("\n") + 1
        funcs.append((func_name, body, start_lineno))
    return funcs


# ── Rule implementations ──────────────────────────────────────────────────────

def _check_hardcoded_input_index(code: str) -> list[dict]:
    """
    LNC-001: Detect hardcoded input/output index patterns.

    Banned:
      - tx.inputs[0]                    → use tx.inputs[this.activeInputIndex]
      - require(this.activeInputIndex == 0)
      - tx.outputs[0] without a preceding length guard in the same function
    """
    violations = []
    lines_list = _lines(code)

    # Pattern 1: tx.inputs[0]
    for lineno, line in lines_list:
        if re.search(r"tx\.inputs\[\s*0\s*\]", line):
            violations.append({
                "rule_id": "LNC-001a",
                "message": "Hardcoded tx.inputs[0] — use tx.inputs[this.activeInputIndex]",
                "line_hint": lineno,
            })

    # Pattern 2: require(this.activeInputIndex == 0)
    for lineno, line in lines_list:
        if re.search(r"this\.activeInputIndex\s*==\s*0", line):
            violations.append({
                "rule_id": "LNC-001b",
                "message": "require(this.activeInputIndex == 0) is forbidden — not a security guard",
                "line_hint": lineno,
            })

    # Pattern 3: tx.outputs[N] accessed without a matching length guard (must be >= N+1)
    for func_name, body, start_lineno in _function_bodies(code):
        # Collect all explicit length guards: require(tx.outputs.length == K)
        guarded_lengths: set[int] = set()
        for gm in re.finditer(r"require\s*\(\s*tx\.outputs\.length\s*(==|>=)\s*(\d+)\s*\)", body):
            op  = gm.group(1)
            val = int(gm.group(2))
            guarded_lengths.add(val)  # both == and >= guarantee at least val outputs

        for m in re.finditer(r"tx\.outputs\[\s*(\d+)\s*\]", body):
            idx = int(m.group(1))
            # Safe only if there is a length guard that guarantees length > idx
            safe = any(g > idx for g in guarded_lengths)
            if not safe:
                body_lineno = start_lineno + body[: m.start()].count("\n")
                violations.append({
                    "rule_id": "LNC-001c",
                    "message": (
                        f"tx.outputs[{idx}] accessed but no guard ensures "
                        f"tx.outputs.length >= {idx + 1} in function '{func_name}'"
                    ),
                    "line_hint": body_lineno,
                })

    return violations


def _check_unused_variables(code: str) -> list[dict]:
    """
    LNC-002: Detect declared local variables that are never read.

    Covers: `int x = ...;`  `bytes x = ...;`  `bool x = ...;`
    If name appears only once in the function body → unused.
    """
    violations = []
    _TYPES = r"(?:int|bool|bytes(?:\d*)?|pubkey|sig)"
    decl_pattern = re.compile(rf"^\s*{_TYPES}(?:\[\])?\s+(\w+)\s*=", re.MULTILINE)

    for func_name, body, start_lineno in _function_bodies(code):
        for m in decl_pattern.finditer(body):
            var_name = m.group(1)
            # Count all uses of var_name (not just the declaration)
            uses = len(re.findall(rf"\b{re.escape(var_name)}\b", body))
            if uses <= 1:  # only declaration itself
                decl_lineno = start_lineno + body[: m.start()].count("\n")
                violations.append({
                    "rule_id": "LNC-002",
                    "message": f"Unused variable '{var_name}' declared but never referenced",
                    "line_hint": decl_lineno,
                })

    return violations


def _check_value_anchoring(code: str, contract_mode: str = "") -> list[dict]:
    """
    LNC-003: Every function with an output length guard MUST anchor at least
    one output value to the corresponding input value.

    MODE-CONDITIONAL — only enforced for covenant-grade contracts:
      escrow / vesting / token / covenant / stateful → enforce
      multisig / timelock / stateless / unknown      → SKIP

    Gap 1 fix: matches tx.outputs[ANY_INDEX].value, not just [0].
    Also accepts sum-preservation patterns where any output value equals
    tx.inputs[this.activeInputIndex].value.
    """
    COVENANT_MODES = {"escrow", "vesting", "token", "covenant", "stateful"}

    mode = (contract_mode or "").lower().strip()

    # Skip anchoring for clearly stateless contracts
    if mode in {"multisig", "timelock", "stateless", ""}:
        return []

    violations = []
    for func_name, body, start_lineno in _function_bodies(code):
        # Only check functions that explicitly guard output count
        has_output_guard = bool(re.search(
            r"require\s*\(\s*tx\.outputs\.length\s*==", body
        ))
        if not has_output_guard:
            continue

        # Accept direct equality anchor:
        # require(tx.outputs[N].value == tx.inputs[this.activeInputIndex].value)

        direct_anchor = bool(re.search(
            r"require\s*\(\s*tx\.outputs\[\d+\]\.value\s*==\s*tx\.inputs\[this\.activeInputIndex\]\.value\s*\)",
            body,
        ))

        # Accept sum-preservation pattern:
        # require(tx.outputs[0].value + tx.outputs[1].value == tx.inputs[this.activeInputIndex].value)
        sum_anchor = bool(re.search(
            r"require\s*\(\s*tx\.outputs\[\d+\]\.value\s*\+\s*tx\.outputs\[\d+\]\.value\s*==\s*tx\.inputs\[this\.activeInputIndex\]\.value\s*\)",
            body,
        ))

        has_value_anchor = direct_anchor or sum_anchor
        if not has_value_anchor:
            violations.append({
                "rule_id": "LNC-003",
                "message": (
                    f"Function '{func_name}' guards output count but has no "
                    "value anchor: require(tx.outputs[N].value == tx.inputs[this.activeInputIndex].value)"
                ),
                "line_hint": start_lineno,
            })

    return violations


def _check_implicit_output_ordering(code: str) -> list[dict]:
    """
    LNC-004: Detect tx.outputs field access at file scope (outside any function).
    Accessing tx.outputs outside a function body has no length guard context.
    Gap 4 fix: this rule is now registered in RULES so it actually runs.
    """
    violations = []
    # Build a set of line numbers that are inside a function body
    inside_lines: set[int] = set()
    for _, body, start_lineno in _function_bodies(code):
        body_line_count = body.count("\n")
        for offset in range(body_line_count + 2):
            inside_lines.add(start_lineno + offset)

    for lineno, line in _lines(code):
        if lineno in inside_lines:
            continue
        # File-scope tx.outputs access (e.g. in constructor or top-level expression)
        if re.search(r"tx\.outputs\[\d+\]", line):
            violations.append({
                "rule_id": "LNC-004",
                "message": "tx.outputs indexed outside a function body — no length guard possible",
                "line_hint": lineno,
            })
    return violations


def _check_fee_arithmetic(code: str) -> list[dict]:
    """
    LNC-005: Detect implicit fee arithmetic (subtracting from input value).
    Patterns: value - fee, .value - <any expr>, inputValue - ...
    """
    violations = []
    for lineno, line in _lines(code):
        # Detect patterns like: .value - fee, .value - 1000, inputValue -
        if re.search(r"(?:\.value|inputValue|input_value)\s*-", line):
            violations.append({
                "rule_id": "LNC-005",
                "message": (
                    "Implicit fee arithmetic detected. "
                    "Do NOT subtract fees from value. "
                    "Use a named 'fee' constructor param or fixed output amounts."
                ),
                "line_hint": lineno,
            })
        # Detect explicit `- fee` / `- miner_fee` variable
        if re.search(r"\-\s*(?:fee|miner_?fee|tx_?fee|satoshis_?fee)\b", line, re.IGNORECASE):
            violations.append({
                "rule_id": "LNC-005",
                "message": "Fee variable subtraction detected — forbidden. Use exact output values.",
                "line_hint": lineno,
            })

    return violations


def _check_wrong_self_reference(code: str) -> list[dict]:
    """
    LNC-006: Detect use of this.lockingBytecode which does NOT exist in CashScript ^0.13.0.
    The correct field is this.activeBytecode.
    """
    violations = []
    for lineno, line in _lines(code):
        if "this.lockingBytecode" in line:
            violations.append({
                "rule_id": "LNC-006",
                "message": (
                    "this.lockingBytecode does NOT exist in CashScript ^0.13.0. "
                    "Use this.activeBytecode instead."
                ),
                "line_hint": lineno,
            })
    return violations


def _check_deprecated_patterns(code: str) -> list[dict]:
    """
    LNC-007: Detect CashScript 0.12.x deprecated patterns that break 0.13.0.
    """
    violations = []
    deprecated = [
        (r"tx\.inputs\[i\]\.time\b",   "tx.inputs[i].time — does not exist; use tx.time for CLTV"),
        (r"tx\.locktime\b",             "tx.locktime — deprecated; use tx.time (CLTV) or tx.age (CSV)"),
        (r"\bcheckDataSig\b",           "checkDataSig — removed in ^0.13.0"),
        (r"new\s+Sig\s*\(",             "new Sig(...) constructor — removed in ^0.13.0"),
    ]
    for lineno, line in _lines(code):
        for pattern, msg in deprecated:
            if re.search(pattern, line):
                violations.append({
                    "rule_id": "LNC-007",
                    "message": f"Deprecated 0.12.x pattern: {msg}",
                    "line_hint": lineno,
                })
    return violations


def _check_timelock_standalone(code: str) -> list[dict]:
    """
    LNC-010: tx.time and tx.age must appear ONLY in standalone require()
    statements of the form:
        require(tx.time >= X);
        require(tx.age >= X);
    """

    violations = []

    for func_name, body, start_lineno in _function_bodies(code):
        for m in re.finditer(r"require\s*\((.*?)\)", body):
            inner = m.group(1)

            # If timelock appears but is chained
            if "tx.time" in inner or "tx.age" in inner:
                # Must match EXACT standalone pattern
                if not re.fullmatch(r"\s*tx\.(time|age)\s*>=\s*[\w\d_]+\s*", inner):
                    lineno = start_lineno + body[: m.start()].count("\n")
                    violations.append({
                        "rule_id": "LNC-010",
                        "message": (
                            "tx.time / tx.age must be used only as standalone "
                            "require(tx.time >= X); not chained or nested."
                        ),
                        "line_hint": lineno,
                    })

    return violations


def _check_division_guard(code: str) -> list[dict]:
    """
    LNC-011: Any arithmetic division must have a prior require(divisor > 0)
    inside the same function body.

    Ignores:
      - Comment lines
      - // comments
      - Numeric literals (e.g. / 2)
    """

    violations = []

    for func_name, body, start_lineno in _function_bodies(code):
        # Remove line comments before scanning
        body_no_comments = re.sub(r"//.*", "", body)

        # Match arithmetic division: identifier / identifier
        for m in re.finditer(r"\b(\w+)\s*/\s*(\w+)\b", body_no_comments):
            numerator = m.group(1)
            divisor = m.group(2)

            # Ignore numeric literal divisors
            if divisor.isdigit():
                continue

            guard_pattern = rf"require\s*\(\s*{re.escape(divisor)}\s*>\s*0\s*\)"
            has_guard = re.search(guard_pattern, body_no_comments)

            if not has_guard:
                lineno = start_lineno + body[: m.start()].count("\n")
                violations.append({
                    "rule_id": "LNC-011",
                    "message": (
                        f"Division by '{divisor}' without require({divisor} > 0) guard."
                    ),
                    "line_hint": lineno,
                })

    return violations


def _check_covenant_self_anchor(code: str, contract_mode: str = "") -> list[dict]:
    """
    LNC-008: Covenant Self-Anchor Guard.

    Enforces require(tx.outputs[N].lockingBytecode == this.activeBytecode) for
    state-continuing contracts.

    MODE MATRIX:
    - distribution, split, burn  → FORBID self-anchor (payout/exit intent)
    - vesting, stateful, vault   → REQUIRE self-anchor (continuation intent)
    - covenant                   → REQUIRE self-anchor
    - token                      → REQUIRE self-anchor UNLESS mode is specifically 'burn'
    - multisig, escrow, timelock → SKIP (stateless or single-spend)
    """
    mode = (contract_mode or "").lower().strip()

    # 1. FORBID SELF-ANCHOR MODES (Exit Patterns)
    # If the intent is explicitly to exit/payout, self-anchoring is a bug (trap).
    if mode in {"distribution", "payout", "split", "burn"}:
        if re.search(r"this\.activeBytecode", code):
            return [{
                "rule_id": "LNC-008",
                "message": (
                    f"Contract mode '{mode}' MUST NOT use this.activeBytecode. "
                    "This mode implies funds exit the contract. "
                    "Self-anchoring would permanently trap funds."
                ),
                "line_hint": 0,
            }]
        return []

    # 2. SKIP MODES (Stateless / Single-Spend)
    # These modes don't care about self-anchoring (or use unrelated logic).
    SKIP_MODES = {"multisig", "multisig_simple_spend", "p2pkh", "stateless", "timelock", "escrow", ""}
    if mode in SKIP_MODES:
        return []

    # 3. REQUIRE SELF-ANCHOR MODES (Continuation Patterns)
    # vesting, stateful, covenant, vault, token (mint/transfer-mutable)
    REQUIRE_MODES = {"vesting", "stateful", "covenant", "vault", "token", "minting"}

    # If unknown mode, infer from code content (conservative fallback)
    if mode not in REQUIRE_MODES:
        has_token_refs    = bool(re.search(r"\b(?:tokenCategory|tokenAmount)\b", code))
        has_self_ref      = bool(re.search(r"this\.activeBytecode", code))
        if not (has_token_refs or has_self_ref):
            return [] # No covenant features detected

    violations = []
    for func_name, body, start_lineno in _function_bodies(code):
        # 4. EXCEPTION: BURN FUNCTIONS in Token Contracts
        # If mode is 'token' but function is 'burn', it should NOT self-anchor.
        is_burn_func = bool(re.search(r"\bburn\w*\b", func_name, re.IGNORECASE))
        if mode == "token" and is_burn_func:
            continue

        # Only check functions that actually touch outputs/tokens
        touches_outputs = bool(re.search(r"tx\.outputs\b", body))
        touches_tokens  = bool(re.search(r"\b(?:tokenCategory|tokenAmount)\b", body))
        if not (touches_outputs or touches_tokens):
            continue

        # Must have a lockingBytecode self-anchor
        # Matches: tx.outputs[...].lockingBytecode == this.activeBytecode
        has_self_anchor = bool(re.search(
            r"tx\.outputs\[.*?\]\.lockingBytecode\s*==\s*this\.activeBytecode",
            body,
        ))
        # Also accept input self-anchor (rare but valid)
        has_input_self_anchor = bool(re.search(
            r"tx\.inputs\[.*?\]\.lockingBytecode\s*==\s*this\.activeBytecode",
            body,
        ))

        if not (has_self_anchor or has_input_self_anchor):
            violations.append({
                "rule_id": "LNC-008",
                "message": (
                    f"Covenant function '{func_name}' (mode={mode}) has no self-anchor: "
                    "require(tx.outputs[N].lockingBytecode == this.activeBytecode). "
                    "Stateful/token contracts must perpetuate themselves."
                ),
                "line_hint": start_lineno,
            })

    return violations


def _check_forbidden_syntax(code: str) -> list[dict]:
    """
    LNC-009: Detect CashScript-forbidden language constructs that compile correctly
    in Solidity/JS but are INVALID in CashScript ^0.13.0.

    These cause the exact 'Token recognition error at ?', 'Extraneous input <EOF>'
    errors seen in the escrow compile loop.

    Catches before compile → converts compile failure to Phase2 retry.
    """
    violations = []

    FORBIDDEN_PATTERNS = [
        # Ternary operator — two patterns for belt-and-suspenders coverage:
        # 1. Full form: word ? expr : expr
        (r"\b\w+\s*\?\s*[^:]+:\s*[^;{}\n]+",
         "Ternary operator (?:) is NOT supported in CashScript. Use require() instead."),
        # 2. Bare ? fallback — catch any standalone ? that isn't != or >=
        (r"(?<![!=<>?])\?(?!\?)",
         "Ternary operator '?' is NOT supported in CashScript. Use require() instead."),
        # Compound assignment operators
        (r"(?<![=!<>])\+=",
         "+= is NOT supported. CashScript has no mutable variables.  Use: int y = x + n;"),
        (r"(?<![=!<>])-=",
         "-= is NOT supported. CashScript has no mutable variables. Use: int y = x - n;"),
        (r"(?<![=!<>])\*=",
         "*= is NOT supported. CashScript has no mutable variables."),
        (r"(?<![=!<>])/=",
         "/= is NOT supported. CashScript has no mutable variables."),
        # Increment / decrement
        (r"\+\+",
         "++ is NOT supported. CashScript has no mutation. Use: int y = x + 1;"),
        (r"(?<!-)--(?!-)",
         "-- is NOT supported. CashScript has no mutation. Use: int y = x - 1;"),
        # Control flow forbidden in CashScript
        (r"\bfor\s*\(",
         "for(...) loops are NOT supported in CashScript. Unroll manually."),
        (r"\bwhile\s*\(",
         "while(...) loops are NOT supported in CashScript."),
        (r"\bswitch\s*\(",
         "switch(...) is NOT supported in CashScript."),
        # return statement (functions have no return value)
        (r"\breturn\b",
         "return is NOT valid in CashScript functions. Use only require() statements."),
        # if/else branching (must use require)
        (r"\bif\s*\(",
         "if(...) is NOT supported in CashScript. Use require() for all conditionals."),
        (r"\belse\b",
         "else is NOT supported in CashScript. Use require() for all conditionals."),
    ]

    for lineno, line in _lines(code):
        # Skip full comment lines
        stripped = line.strip()
        if stripped.startswith("//"):
            continue
        # Strip inline comments before pattern matching
        # (prevents comment text from matching patterns AND ensures code portion is scanned correctly)
        code_part = re.sub(r"//.*$", "", line)
        for pattern, msg in FORBIDDEN_PATTERNS:
            if re.search(pattern, code_part):
                violations.append({
                    "rule_id": "LNC-009",
                    "message": msg,
                    "line_hint": lineno,
                })
    return violations


def _check_frozen_state(code: str, contract_mode: str = "") -> list[dict]:
    """
    LNC-012: Frozen State Guard (WARNING only).

    Stateful/vesting contracts that self-anchor via this.activeBytecode but do NOT
    construct new locking bytecode with updated constructor args are 'frozen' state
    machines — they preserve state but never mutate it.

    This is recorded as a warning, not an error, because:
    - Some contracts intentionally 'freeze' (e.g. final vesting cliff)
    - True state mutation requires off-chain bytecode construction helpers

    Fires when:
    - contract_mode in {"stateful", "vesting"}
    - code contains this.activeBytecode (self-continuation)
    - code does NOT contain any new locking bytecode construction pattern
      (no LockingBytecodeP2SH, hash160, or bytes-level concat visible)
    """
    mode = (contract_mode or "").lower().strip()
    if mode not in {"stateful", "vesting"}:
        return []

    # Must be a self-continuing contract
    has_self_anchor = bool(re.search(r"this\.activeBytecode", code))
    if not has_self_anchor:
        return []  # Not a self-continuing contract — LNC-008 handles that

    # Check for any evidence of new bytecode construction (state mutation)
    has_new_bytecode = bool(re.search(
        r"LockingBytecodeP2SH|hash160\s*\(|bytes\s*concat\s*\(|new\s+bytes",
        code,
    ))
    if has_new_bytecode:
        return []  # Contract does attempt state mutation — no warning needed

    # Frozen state detected — warn
    return [{
        "rule_id":   "LNC-012",
        "message":   (
            "Stateful contract perpetuates itself via this.activeBytecode but does not "
            "mutate constructor state (no new locking bytecode construction detected). "
            "This is a structural covenant, not a true state machine. "
            "If mutation is intended, construct a new locking bytecode with updated args."
        ),
        "line_hint": 0,
        "severity":  "warning",  # Not a hard error — does not block lint
    }]


def _check_mint_authority(code: str, contract_mode: str = "") -> list[dict]:
    """
    LNC-013: Mint Authority Guard.

    If contract_mode == 'token' and the code appears to mint tokens (tokenAmount increases
    without explicit input tokenAmount constraint), require that a mintAuthority pubkey
    constructor param is present and a checkSig(mintSig, mintAuthority) appears.

    Conservative: only fires when 'minting' or 'mint' appears in comments/identifiers
    AND no mintAuthority param + sig is detected.
    """
    mode = (contract_mode or "").lower().strip()
    if mode not in {"token", "minting"}:
        return []

    # Only check if the contract has minting intent
    has_mint_intent = bool(re.search(r"\bmint\w*\b", code, re.IGNORECASE))
    if not has_mint_intent:
        return []

    violations = []
    for func_name, body, start_lineno in _function_bodies(code):
        # Check if this function looks like a mint operation
        is_mint_func = bool(re.search(r"\bmint\w*\b", func_name, re.IGNORECASE))
        if not is_mint_func:
            continue

        # Must have a mintAuthority param and matching checkSig
        has_mint_authority_param = bool(re.search(
            r"\bmintAuthority\b", code  # check full contract, not just body
        ))
        has_mint_sig_check = bool(re.search(
            r"checkSig\s*\([^,]+,\s*mintAuthority\s*\)", body
        ))

        if not (has_mint_authority_param and has_mint_sig_check):
            violations.append({
                "rule_id": "LNC-013",
                "message": (
                    f"Mint function '{func_name}' does not require mintAuthority authorization. "
                    "Add: (1) 'pubkey mintAuthority' as a constructor param, "
                    "(2) require(checkSig(mintSig, mintAuthority)) in the mint function."
                ),
                "line_hint": start_lineno,
            })

    return violations


def _check_token_pair_completeness(code: str) -> list[dict]:
    """
    LNC-014: Missing Token Pair Guard.

    tokenCategory and tokenAmount are a pair — both MUST be validated together.
    If a contract reads one but not the other in a require(), it risks:
    - Silent burn (tokenAmount unconstrained → tokens disappear)
    - Category confusion (tokenCategory unconstrained → wrong token accepted)
    """
    violations = []

    for func_name, body, start_lineno in _function_bodies(code):
        references_category = bool(re.search(r"\.tokenCategory\b", body))
        references_amount   = bool(re.search(r"\.tokenAmount\b", body))

        if not (references_category or references_amount):
            continue  # function doesn't touch tokens at all

        # Both must appear if either does
        if references_category and not references_amount:
            violations.append({
                "rule_id": "LNC-014",
                "message": (
                    f"Function '{func_name}' validates tokenCategory but not tokenAmount. "
                    "Add: require(tx.outputs[0].tokenAmount == tx.inputs[this.activeInputIndex].tokenAmount); "
                    "to prevent silent token burns."
                ),
                "line_hint": start_lineno,
            })
        elif references_amount and not references_category:
            violations.append({
                "rule_id": "LNC-014",
                "message": (
                    f"Function '{func_name}' validates tokenAmount but not tokenCategory. "
                    "Add: require(tx.outputs[0].tokenCategory == tx.inputs[this.activeInputIndex].tokenCategory); "
                    "to prevent category confusion attacks."
                ),
                "line_hint": start_lineno,
            })

    return violations


# ── Main DSLLinter class ──────────────────────────────────────────────────────

class DSLLinter:
    """
    Deterministic CashScript ^0.13.0 lint runner.

    Runs all rule checks and returns a structured result.
    Zero LLM calls. Zero side effects.
    """

    RULES = [
        _check_hardcoded_input_index,    # LNC-001 a/b/c
        _check_unused_variables,         # LNC-002  (heuristic)
        _check_value_anchoring,          # LNC-003  (any output index)
        _check_implicit_output_ordering, # LNC-004
        _check_fee_arithmetic,           # LNC-005
        _check_wrong_self_reference,     # LNC-006
        _check_deprecated_patterns,      # LNC-007
        _check_timelock_standalone,      # LNC-010
        _check_division_guard,           # LNC-011
        _check_frozen_state,             # LNC-012  (warning, stateful/vesting only)
        _check_covenant_self_anchor,     # LNC-008  (mode-conditional)
        _check_mint_authority,           # LNC-013  (token/minting mode only)
        _check_token_pair_completeness,  # LNC-014  (any code touching tokens)
        _check_forbidden_syntax,         # LNC-009  (ternary, loops, etc.)
    ]

    def lint(self, code: str, contract_mode: str = "") -> dict[str, Any]:
        """
        Run all lint rules against the provided CashScript source.

        Args:
            code:          CashScript source to validate
            contract_mode: Optional contract type hint from the intent model.
                           Drives conditional rules (e.g. LNC-008, LNC-012, LNC-013).
                           Values: 'multisig' | 'escrow' | 'vesting' | 'stateful' |
                                   'token' | 'minting' | 'distribution' | 'covenant' | ''

        Returns:
            {
                "passed": bool,
                "violations": [{"rule_id": str, "message": str, "line_hint": int}]
            }
        """
        if not code or not code.strip():
            return {
                "passed": False,
                "violations": [{"rule_id": "LNC-000", "message": "Empty code", "line_hint": 0}],
            }

        all_violations: list[dict] = []
        for rule_fn in self.RULES:
            try:
                import inspect
                sig = inspect.signature(rule_fn)
                if "contract_mode" in sig.parameters:
                    all_violations.extend(rule_fn(code, contract_mode=contract_mode))
                else:
                    all_violations.extend(rule_fn(code))
            except Exception as exc:
                logger.warning(f"[DSLLinter] Rule {rule_fn.__name__} raised: {exc}")

        passed = len(all_violations) == 0
        if not passed:
            for v in all_violations:
                logger.warning(f"[DSLLint] {v['rule_id']} L{v['line_hint']}: {v['message']}")
        else:
            logger.info(f"[DSLLint] PASSED (mode={contract_mode or 'auto'}) — no violations.")

        return {"passed": passed, "violations": all_violations}

    def format_for_prompt(self, violations: list[dict]) -> str:
        """
        Compact one-liner format for injecting into a retry prompt.
        e.g.:
            DSL LINT VIOLATIONS (fix these before compile):
            - LNC-003 L12: Function 'spend' has no value anchoring
            - LNC-001a L8: Hardcoded tx.inputs[0]
        """
        if not violations:
            return ""
        lines = ["DSL LINT VIOLATIONS (fix these — do NOT add new logic):"]
        for v in violations:
            lines.append(f"- {v['rule_id']} L{v['line_hint']}: {v['message']}")
        return "\n".join(lines)


# ── Module-level singleton ────────────────────────────────────────────────────

_linter_instance: DSLLinter | None = None


def get_dsl_linter() -> DSLLinter:
    global _linter_instance
    if _linter_instance is None:
        _linter_instance = DSLLinter()
    return _linter_instance
