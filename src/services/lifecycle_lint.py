"""Lifecycle and ownership semantic lint (LNC-026, LNC-027)."""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from src.services.dsl_lint import _function_bodies


def _semantic_ctx(
    contract_mode: str = "",
    semantic: Optional[Dict[str, str]] = None,
) -> Dict[str, str]:
    ctx = dict(semantic or {})
    if not ctx.get("ownership_mode"):
        ctx["ownership_mode"] = "transferable"
    if not ctx.get("lifecycle_mode"):
        ctx["lifecycle_mode"] = "persistent"
    if not ctx.get("supply_mode"):
        ctx["supply_mode"] = "fixed"
    if not ctx.get("commitment_schema"):
        ctx["commitment_schema"] = "opaque"
    ctx["_contract_mode"] = contract_mode
    return ctx


def check_soulbound_transfer(
    code: str,
    contract_mode: str = "",
    semantic: Optional[Dict[str, str]] = None,
) -> List[dict]:
    """LNC-026: Soulbound — no external transfer of NFT-bearing output."""
    ctx = _semantic_ctx(contract_mode, semantic)
    if ctx.get("ownership_mode") != "soulbound":
        return []

    violations = []
    for func_name, body, start_lineno in _function_bodies(code):
        has_external = bool(
            re.search(
                r"lockingBytecode\s*==\s*(?!this\.activeBytecode)(\w+)",
                body,
            )
        )
        lacks_self = "this.activeBytecode" not in body
        if has_external and lacks_self:
            violations.append({
                "rule_id": "LNC-026",
                "message": (
                    f"Soulbound function '{func_name}' must not transfer NFT to external "
                    "lockingBytecode; use this.activeBytecode on continuation output only."
                ),
                "line_hint": start_lineno,
            })
    return violations


def check_hybrid_state_auth(
    code: str,
    contract_mode: str = "",
    semantic: Optional[Dict[str, str]] = None,
) -> List[dict]:
    """LNC-027: Hybrid + state_transition requires checkSig."""
    ctx = _semantic_ctx(contract_mode, semantic)
    mode = (contract_mode or "").lower()
    if mode != "hybrid_token" and ctx.get("lifecycle_mode") != "state_transition":
        return []
    if mode != "hybrid_token":
        return []

    if ctx.get("lifecycle_mode") not in ("state_transition", "persistent"):
        return []

    if re.search(r"checkSig\s*\(", code):
        return []

    return [{
        "rule_id": "LNC-027",
        "message": (
            "Hybrid token with state_transition/persistent lifecycle requires "
            "require(checkSig(ownerSig, vaultOwner)) on spending functions."
        ),
        "line_hint": 0,
    }]


def check_lifecycle_anchor_rules(
    code: str,
    contract_mode: str = "",
    semantic: Optional[Dict[str, str]] = None,
) -> List[dict]:
    """Lifecycle-aware self-anchor hints (warnings)."""
    ctx = _semantic_ctx(contract_mode, semantic)
    lm = ctx.get("lifecycle_mode", "")
    violations: List[dict] = []

    if lm == "terminating":
        for func_name, body, start_lineno in _function_bodies(code):
            if "claim" in func_name.lower() or "release" in func_name.lower() or "redeem" in func_name.lower():
                if re.search(r"lockingBytecode\s*==\s*this\.activeBytecode", body):
                    violations.append({
                        "rule_id": "LNC-008",
                        "message": (
                            f"Terminating function '{func_name}' must not self-anchor payout output."
                        ),
                        "line_hint": start_lineno,
                        "severity": "warning",
                    })

    if lm in ("persistent", "state_transition"):
        if not re.search(r"this\.activeBytecode", code):
            violations.append({
                "rule_id": "LNC-008",
                "message": (
                    f"Lifecycle mode '{lm}' expects this.activeBytecode on continuation outputs."
                ),
                "line_hint": 0,
                "severity": "warning",
            })

    return violations


def run_semantic_lint(
    code: str,
    contract_mode: str = "",
    semantic: Optional[Dict[str, str]] = None,
) -> List[dict]:
    out: List[dict] = []
    out.extend(check_soulbound_transfer(code, contract_mode, semantic))
    out.extend(check_hybrid_state_auth(code, contract_mode, semantic))
    out.extend(check_lifecycle_anchor_rules(code, contract_mode, semantic))
    return out
