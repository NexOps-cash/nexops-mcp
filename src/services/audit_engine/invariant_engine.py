"""
Invariant Reasoning Engine — audit-only transaction-level facts derived from AST.

Used to gate noisy detectors/lint rules without modifying shared core or generator code.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Set

from src.utils.cashscript_ast import CashScriptAST


def _function_bodies_from_code(code: str) -> List[tuple[str, str]]:
    """(func_name, body) for every function — same brace logic as audit_lint."""
    funcs: List[tuple[str, str]] = []
    pattern = re.compile(r"function\s+(\w+)\s*\(.*?\)\s*\{", re.DOTALL)
    for m in pattern.finditer(code):
        func_name = m.group(1)
        start = m.end()
        depth = 1
        i = start
        while i < len(code) and depth > 0:
            if code[i] == "{":
                depth += 1
            elif code[i] == "}":
                depth -= 1
            i += 1
        body = code[start : i - 1]
        funcs.append((func_name, body))
    return funcs


def _parse_output_length_guards(body: str) -> List[Dict[str, Any]]:
    """
    Parsed require() bounds on tx.outputs.length. Each entry: {op, value} where:
      - op '=='  — exactly value outputs  → max index is value-1
      - op '>=' — at least value outputs  → in the worst case max index is value-1
      - op '>'  — length > value          → at least value+1 outputs → max index is value
    """
    out: List[Dict[str, Any]] = []
    for gm in re.finditer(
        r"require\s*\(\s*tx\.outputs\.length\s*(==|>=|>)\s*(\d+)\s*\)", body
    ):
        out.append({"op": gm.group(1), "value": int(gm.group(2))})
    return out


def _max_index_guaranteed_by_length_guard(op: str, value: int) -> int:
    """Largest index that the guard always allows (0-based), worst-case / tight."""
    if op == "==":
        return value - 1
    if op == ">=":
        return value - 1
    if op == ">":
        return value
    return -1


def fixed_indices_covered_by_guards(
    required_max: int, guards: List[Dict[str, Any]]
) -> bool:
    """
    True if some require(tx.outputs.length ...) guarantees access to all indices 0..required_max.
    For each guard, the guarantee is max index >= F(op,value) in the minimum-length reading above.
    """
    if required_max < 0:
        return True
    for g in guards:
        op, v = g.get("op", ""), int(g.get("value", 0))
        m = _max_index_guaranteed_by_length_guard(op, v)
        if m >= required_max:
            return True
    return False


class InvariantEngine:
    """Derive lightweight invariants for gating audit detectors and lint."""

    def __init__(self, ast: CashScriptAST):
        self.ast = ast
        self.code = ast.code or ""
        self._bodies = ast._get_function_bodies()

    def analyze(self) -> Dict[str, Any]:
        return {
            "output_constraints": self._analyze_outputs(),
            "input_constraints": self._analyze_inputs(),
            "coupling": self._analyze_coupling(),
            "value_flow": self._analyze_value_flow(),
        }

    def _analyze_outputs(self) -> Dict[str, Any]:
        fixed_indices: Set[int] = set()
        all_parsed: List[Dict[str, Any]] = []

        for _fn_name, body in self._bodies.items():
            for m in re.finditer(r"tx\.outputs\[(.*?)\]", body):
                inner = m.group(1).strip()
                if inner.isdigit():
                    fixed_indices.add(int(inner))
            all_parsed.extend(_parse_output_length_guards(body))

        required_max = max(fixed_indices) if fixed_indices else 0
        min_required_outputs = required_max + 1 if fixed_indices else 1

        return {
            "fixed_indices": fixed_indices,
            "length_guards": all_parsed,
            "guards": sorted(
                g["value"] for g in all_parsed
            ),  # legacy flat values (lossy; prefer length_guards)
            "required_max_index": required_max,
            "min_required_outputs": min_required_outputs,
            "per_function": self._per_function_output_facts(),
        }

    def _per_function_output_facts(self) -> Dict[str, Dict[str, Any]]:
        """Per function: fixed output indices, parsed length requires, dynamic active-index accesses."""
        out: Dict[str, Dict[str, Any]] = {}
        for fn_name, body in self._bodies.items():
            fixed: Set[int] = set()
            for m in re.finditer(r"tx\.outputs\[\s*(\d+)\s*\]", body):
                fixed.add(int(m.group(1)))
            parsed = _parse_output_length_guards(body)
            dynamic: List[Dict[str, Any]] = []
            for m in re.finditer(
                r"tx\.(inputs|outputs)\[this\.activeInputIndex\s*\+\s*(\d+)\]",
                body,
            ):
                dynamic.append(
                    {
                        "collection": m.group(1),
                        "offset": int(m.group(2)),
                    }
                )
            req_max = max(fixed) if fixed else 0
            out[fn_name] = {
                "fixed_indices": fixed,
                "length_guards": parsed,
                "guards": sorted(p["value"] for p in parsed),
                "dynamic_index_accesses": dynamic,
                "required_max_index": req_max,
                "min_required_outputs": (req_max + 1) if fixed else 1,
            }
        return out

    def _analyze_inputs(self) -> Dict[str, Any]:
        requires_index_zero = False
        min_index = 0

        for _fn, body in self._bodies.items():
            if re.search(r"this\.activeInputIndex\s*==\s*0\b", body):
                requires_index_zero = True
            for m in re.finditer(
                r"tx\.inputs\[this\.activeInputIndex\s*-\s*(\d+)\]", body
            ):
                min_index = max(min_index, int(m.group(1)))

        return {
            "requires_index_zero": requires_index_zero,
            "min_index": min_index,
        }

    def _per_index_output_coupling(self) -> Dict[int, Dict[str, bool]]:
        """
        For each numeric output index, track which properties appear in equality checks
        on tx.outputs[i] (not global string search — avoids false 'full coupling'
        when locking is on [0] and category on [1]).

        Matches both `tx.outputs[N].prop == ...` and `... == tx.outputs[N].prop` (common
        after a line break before the output side).
        """
        body = self.code
        out: Dict[int, Dict[str, bool]] = {}
        prop = r"(lockingBytecode|tokenCategory|nftCommitment)"
        idx_prop = rf"tx\.outputs\[\s*(\d+)\s*\]\.{prop}"
        patterns = (
            rf"{idx_prop}\s*==",  # output on the left of ==
            rf"==\s*{idx_prop}\b",  # output on the right of ==
        )
        for pat in patterns:
            for m in re.finditer(pat, body, re.DOTALL):
                idx = int(m.group(1))
                p = m.group(2)
                slot = out.setdefault(
                    idx,
                    {"lockingBytecode": False, "tokenCategory": False, "nftCommitment": False},
                )
                slot[p] = True
        return out

    def _analyze_coupling(self) -> Dict[str, Any]:
        body = self.code
        positional_count = len(re.findall(r"tx\.outputs\[\d+\]", body))
        per_index = self._per_index_output_coupling()
        has_same_index_locking_and_token = any(
            v.get("lockingBytecode") and v.get("tokenCategory") for v in per_index.values()
        )
        return {
            "lockingBytecode": bool(re.search(r"\.lockingBytecode\s*==", body)),
            "tokenCategory": bool(re.search(r"\.tokenCategory\s*==", body)),
            "nftCommitment": bool(re.search(r"\.nftCommitment\s*==", body)),
            "positional_validation": positional_count >= 3,
            "per_index": {str(k): v for k, v in per_index.items()},
            "has_same_index_locking_and_token": has_same_index_locking_and_token,
        }

    def _analyze_value_flow(self) -> Dict[str, Any]:
        c = self.code
        has_nft_pres = bool(
            re.search(
                r"require\s*\(.*?tx\.outputs\[.*?\]\.nftCommitment\s*==",
                c,
                re.DOTALL,
            )
        )
        return {
            "has_token_checks": "tokenCategory" in c,
            "has_destination_binding": bool(re.search(r"\.lockingBytecode\s*==", c)),
            "has_nft_commitment_preservation": has_nft_pres,
        }


def should_skip_input_output_coupling(invariants: Dict[str, Any]) -> bool:
    """
    True when the contract uses several fixed output positions *and* at least one
    output index has both lockingBytecode and tokenCategory equality (not split
    across different indices).
    """
    c = invariants.get("coupling") or {}
    return bool(
        c.get("positional_validation")
        and c.get("has_same_index_locking_and_token")
    )


def should_skip_commitment_rule_for_body(body: str) -> bool:
    """
    Skip when bytes are hash-pinned, or when split is paired with a require() that
    enforces a *length* on the buffer or split-tuple (src.length, a.length, b.length).
    A bare require(a == x) is not a commitment-length guard.
    """
    if "hash256(" in body:
        return True
    for m in re.finditer(
        r"bytes\s+(\w+)\s*,\s*bytes\s+(\w+)\s*=\s*(\w+)\.split\(",
        body,
    ):
        left_n, right_n, src = m.group(1), m.group(2), m.group(3)
        for name in (src, left_n, right_n):
            if re.search(
                rf"require\s*\([^{{}};]*?{re.escape(name)}\.length",
                body,
                re.DOTALL,
            ):
                return True
    return False


def fixed_output_index_unsafe(fn_name: str, invariants: Dict[str, Any]) -> bool:
    """
    True if fixed tx.outputs[M] (M>0) in this function is not covered by any
    parsed require(tx.outputs.length op K) (==, >=, >) under worst-case reading.
    """
    per = (invariants.get("output_constraints") or {}).get("per_function") or {}
    info = per.get(fn_name) or {}
    fixed: Set[int] = set(info.get("fixed_indices") or [])
    length_guards: List[Dict[str, Any]] = list(info.get("length_guards") or [])
    if not fixed:
        return False
    required_max = max(fixed)
    if required_max == 0:
        return False
    return not fixed_indices_covered_by_guards(required_max, length_guards)


def report_fixed_output_brief(fn_name: str, invariants: Optional[Dict[str, Any]] = None) -> str:
    """Human-readable one-liner for audit output (fixed indices only)."""
    if not invariants:
        return ""
    per = (invariants.get("output_constraints") or {}).get("per_function") or {}
    info = per.get(fn_name) or {}
    rmi = int(info.get("required_max_index", -1) or -1)
    mro = int(info.get("min_required_outputs", 0) or 0)
    if rmi < 0 or mro < 1:
        return ""
    if rmi == 0:
        return f" (fixed access only to output 0; at least 1 output always required)"
    return (
        f" Invariant note: this function uses fixed output indices up to {rmi}; "
        f"in the static case, that implies tx.outputs.length ≥ {mro} (indices 0..{rmi})."
    )
