"""CashScript structural validation and safe deterministic syntax micro-fixes."""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("nexops.structural_integrity")

REPAIR_DEBUG_DIR = Path("benchmark/results/repair_debug")


@dataclass
class StructuralDiagnostics:
    valid: bool
    issues: List[str] = field(default_factory=list)
    open_braces: int = 0
    close_braces: int = 0
    paren_delta: int = 0
    dangling_require: bool = False
    incomplete_functions: List[str] = field(default_factory=list)
    truncated_constructor: bool = False
    duplicate_functions: List[str] = field(default_factory=list)
    missing_new_p2pkh: int = 0
    unterminated_string: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "valid": self.valid,
            "issues": self.issues,
            "open_braces": self.open_braces,
            "close_braces": self.close_braces,
            "paren_delta": self.paren_delta,
            "dangling_require": self.dangling_require,
            "incomplete_functions": self.incomplete_functions,
            "truncated_constructor": self.truncated_constructor,
            "duplicate_functions": self.duplicate_functions,
            "missing_new_p2pkh": self.missing_new_p2pkh,
            "unterminated_string": self.unterminated_string,
        }


def _strip_comments_and_strings(code: str) -> str:
    """Rough strip for balance checks (not a full lexer)."""
    out = []
    i = 0
    n = len(code)
    in_line_comment = False
    in_block = False
    in_str = False
    quote = ""
    while i < n:
        ch = code[i]
        nxt = code[i + 1] if i + 1 < n else ""
        if in_line_comment:
            if ch == "\n":
                in_line_comment = False
                out.append("\n")
            i += 1
            continue
        if in_block:
            if ch == "*" and nxt == "/":
                in_block = False
                i += 2
            else:
                i += 1
            continue
        if in_str:
            if ch == quote and code[i - 1] != "\\":
                in_str = False
            i += 1
            continue
        if ch == "/" and nxt == "/":
            in_line_comment = True
            i += 2
            continue
        if ch == "/" and nxt == "*":
            in_block = True
            i += 2
            continue
        if ch in ('"', "'"):
            in_str = True
            quote = ch
            i += 1
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def _paren_delta(code: str) -> int:
    stripped = _strip_comments_and_strings(code)
    return stripped.count("(") - stripped.count(")")


def _closing_paren_index(code: str, open_paren_idx: int) -> Optional[int]:
    """Index after matching ')' for '(' at open_paren_idx, or None if unclosed."""
    if open_paren_idx < 0 or open_paren_idx >= len(code) or code[open_paren_idx] != "(":
        return None

    depth = 0
    i = open_paren_idx
    in_line_comment = False
    in_block = False
    in_str = False
    quote = ""
    n = len(code)
    while i < n:
        ch = code[i]
        nxt = code[i + 1] if i + 1 < n else ""
        if in_line_comment:
            if ch == "\n":
                in_line_comment = False
            i += 1
            continue
        if in_block:
            if ch == "*" and nxt == "/":
                in_block = False
                i += 2
            else:
                i += 1
            continue
        if in_str:
            if ch == quote and code[i - 1] != "\\":
                in_str = False
            i += 1
            continue
        if ch == "/" and nxt == "/":
            in_line_comment = True
            i += 2
            continue
        if ch == "/" and nxt == "*":
            in_block = True
            i += 2
            continue
        if ch in ('"', "'"):
            in_str = True
            quote = ch
            i += 1
            continue
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    return None


def _dangling_require(code: str) -> bool:
    """True when any require( has no balanced closing ')' (supports multiline blocks)."""
    for m in re.finditer(r"\brequire\s*\(", code):
        open_paren = m.end() - 1
        if _closing_paren_index(code, open_paren) is None:
            return True
    return False


def _incomplete_functions(code: str) -> List[str]:
    names: List[str] = []
    for m in re.finditer(r"function\s+(\w+)\s*\([^)]*\)\s*\{", code):
        name = m.group(1)
        start = m.end()
        depth = 1
        i = start
        while i < len(code) and depth > 0:
            if code[i] == "{":
                depth += 1
            elif code[i] == "}":
                depth -= 1
            i += 1
        if depth != 0:
            names.append(name)
    return names


def _truncated_constructor(code: str) -> bool:
    m = re.search(r"contract\s+\w+\s*\(", code)
    if not m:
        return False
    depth = 0
    started = False
    for ch in code[m.start() :]:
        if ch == "(":
            depth += 1
            started = True
        elif ch == ")":
            depth -= 1
            if started and depth == 0:
                return False
        elif ch == "{" and started and depth > 0:
            return True
    return started and depth > 0


def _duplicate_function_names(code: str) -> List[str]:
    names = re.findall(r"function\s+(\w+)\s*\(", code)
    seen: set[str] = set()
    dups: List[str] = []
    for n in names:
        if n in seen and n not in dups:
            dups.append(n)
        seen.add(n)
    return dups


def _unterminated_string(code: str) -> bool:
    in_str = False
    quote = ""
    i = 0
    while i < len(code):
        ch = code[i]
        if in_str:
            if ch == quote and (i == 0 or code[i - 1] != "\\"):
                in_str = False
            i += 1
            continue
        if ch in ('"', "'"):
            in_str = True
            quote = ch
        i += 1
    return in_str


def diagnose_structure(code: str) -> StructuralDiagnostics:
    if not code or not code.strip():
        return StructuralDiagnostics(valid=False, issues=["empty_code"])

    issues: List[str] = []
    ob = code.count("{")
    cb = code.count("}")
    pd = _paren_delta(code)
    dangling = _dangling_require(code)
    incomplete = _incomplete_functions(code)
    trunc_ctor = _truncated_constructor(code)
    dups = _duplicate_function_names(code)
    missing_new = len(
        re.findall(r"(?<!new\s)(?<!\w)LockingBytecodeP2PKH\s*\(", code)
    )
    unterm = _unterminated_string(code)

    if ob != cb:
        issues.append(f"brace_imbalance:{ob}:{cb}")
    if pd != 0:
        issues.append(f"paren_imbalance:{pd}")
    if dangling:
        issues.append("dangling_require")
    if incomplete:
        issues.append(f"incomplete_functions:{','.join(incomplete)}")
    if trunc_ctor:
        issues.append("truncated_constructor")
    if dups:
        issues.append(f"duplicate_functions:{','.join(dups)}")
    if missing_new:
        issues.append(f"missing_new_p2pkh:{missing_new}")
    if unterm:
        issues.append("unterminated_string")
    if cb > ob:
        issues.append("extra_closing_braces")

    valid = len(issues) == 0
    return StructuralDiagnostics(
        valid=valid,
        issues=issues,
        open_braces=ob,
        close_braces=cb,
        paren_delta=pd,
        dangling_require=dangling,
        incomplete_functions=incomplete,
        truncated_constructor=trunc_ctor,
        duplicate_functions=dups,
        missing_new_p2pkh=missing_new,
        unterminated_string=unterm,
    )


def is_structurally_valid(code: str) -> bool:
    return diagnose_structure(code).valid


def prepend_new_locking_bytecode(code: str) -> Tuple[str, bool]:
    fixed = re.sub(
        r"(?<!new\s)(?<!\w)(LockingBytecodeP2PKH\s*\()",
        r"new \1",
        code,
    )
    return fixed, fixed != code


def _contract_signature_span(code: str) -> Tuple[int, int]:
    m = re.search(r"contract\s+\w+\s*\(", code)
    if not m:
        return -1, -1
    depth = 0
    for i in range(m.start(), len(code)):
        if code[i] == "(":
            depth += 1
        elif code[i] == ")":
            depth -= 1
            if depth == 0:
                return m.start(), i + 1
    return m.start(), len(code)


def apply_deterministic_micro_fixes(
    code: str,
    error_obj: Optional[Dict[str, Any]] = None,
) -> Tuple[str, List[str]]:
    """
    Safe syntax micro-fixes only. Returns (code, repairs_applied).
    Does not append closing braces when structure is severely corrupted.
    """
    repairs: List[str] = []
    error_type = (error_obj or {}).get("type", "")
    error_token = (error_obj or {}).get("token", "")
    error_raw = (error_obj or {}).get("raw", "")

    code, changed = prepend_new_locking_bytecode(code)
    if changed:
        repairs.append("prepend_new_locking_bytecode_p2pkh")

    if error_type == "UnusedVariableError" and error_token:
        var_name = error_token
        fixed = re.sub(
            rf"^\s*\w[\w\[\]]*\s+{re.escape(var_name)}\s*=.*?;\s*$",
            "",
            code,
            flags=re.MULTILINE,
        )
        if fixed != code:
            repairs.append(f"strip_unused_var:{var_name}")
            code = fixed.strip()

    if error_type == "ExtraneousInputError" and error_token in ("tx.time", "tx.age"):
        fixed = re.sub(
            r"require\s*\(\s*(.*?)tx\.(time|age)\s*>=\s*(.*?)&&.*?\);",
            r"require(tx.\2 >= \3);",
            code,
        )
        if fixed != code:
            repairs.append("normalize_timelock_require")
            code = fixed.strip()

    if error_type == "ParseError" and error_token == "?":
        fixed = code.replace("?", "")
        repairs.append("strip_ternary")
        code = fixed.strip()

    if "Token recognition error" in error_raw and ".a" in error_raw:
        fixed = re.sub(
            r"(\btx\.(?:outputs|inputs)\[[^\]]*\])\s*\.\s*activeBytecode",
            r"\1.lockingBytecode",
            code,
        )
        if "age" in fixed:
            fixed = re.sub(r"\btx\s*\.\s*age\b", "this.age", fixed)
        if fixed != code:
            repairs.append("fix_activeBytecode_tx_age")
            code = fixed.strip()

    # bytes→bytes32 ONLY outside contract constructor signature
    if error_type == "TypeMismatchError" and "bytes32" in error_raw:
        sig_start, sig_end = _contract_signature_span(code)
        if sig_start >= 0 and sig_end > sig_start:
            head, sig, tail = code[:sig_start], code[sig_start:sig_end], code[sig_end:]
            body_fixed = re.sub(r"\bbytes\s+(\w+)", r"bytes32 \1", tail)
            fixed = head + sig + body_fixed
        else:
            fixed = re.sub(r"\bbytes\s+(\w+)", r"bytes32 \1", code)
        if fixed != code:
            repairs.append("bytes_to_bytes32_body_only")
            code = fixed.strip()

    # EOF brace: only when exactly one missing closing brace at end, no severe corruption
    if error_type == "ExtraneousInputError" and error_token == "<EOF>":
        diag = diagnose_structure(code)
        if (
            diag.open_braces == diag.close_braces + 1
            and not diag.dangling_require
            and not diag.incomplete_functions
            and not diag.truncated_constructor
        ):
            repairs.append("append_single_closing_brace")
            code = (code + "\n}").strip()

    return code, repairs


def save_repair_cycle(
    *,
    case_label: str,
    gen_attempt: int,
    fix_attempt: int,
    pre_code: str,
    post_code: str,
    diagnostics_pre: StructuralDiagnostics,
    diagnostics_post: StructuralDiagnostics,
    repairs: List[str],
    error_obj: Optional[Dict[str, Any]] = None,
    aborted_llm: bool = False,
) -> Path:
    """Persist one compile-repair cycle for debugging."""
    REPAIR_DEBUG_DIR.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
    path = REPAIR_DEBUG_DIR / f"{case_label}_g{gen_attempt}_f{fix_attempt}_{ts}.json"
    payload = {
        "timestamp": ts,
        "gen_attempt": gen_attempt,
        "fix_attempt": fix_attempt,
        "repairs": repairs,
        "aborted_llm": aborted_llm,
        "error_obj": error_obj,
        "diagnostics_pre": diagnostics_pre.to_dict(),
        "diagnostics_post": diagnostics_post.to_dict(),
        "pre_code": pre_code,
        "post_code": post_code,
    }
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    logger.info("[StructuralIntegrity] repair debug saved: %s", path)
    return path
