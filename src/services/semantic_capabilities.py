"""
Tiered semantic capabilities for CashTokens verification.

Design rules (Wave 1.5):
- Capabilities are grouped by tier namespace; no policy logic in extraction.
- Derivation records evidence snippets for traceability.
- Experimental tier is blocked in this phase.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

from src.services.structural_integrity import diagnose_structure
from src.utils.cashscript_ast import CashScriptAST

logger = logging.getLogger("nexops.semantic_capabilities")

CAPABILITY_TRACE_DIR = Path("benchmark/results/capability_traces")

# Registry: capability key -> (tier, owner module)
CAPABILITY_REGISTRY: Dict[str, tuple[str, str]] = {
    # Structural
    "structurally_valid": ("Structural", "structural_integrity"),
    # Authorization
    "has_signature_auth": ("Authorization", "cashscript_ast"),
    "has_multisig_auth": ("Authorization", "cashscript_ast"),
    "requires_signature": ("Authorization", "cashscript_ast"),
    "requires_multisig": ("Authorization", "cashscript_ast"),
    "unrestricted_external_transfer": ("Authorization", "semantic_capabilities"),
    "unrestricted_state_update": ("Authorization", "semantic_capabilities"),
    # TokenFlow
    "preserves_token_category": ("TokenFlow", "cashscript_ast"),
    "preserves_token_amount": ("TokenFlow", "cashscript_ast"),
    "burns_output_tokens": ("TokenFlow", "semantic_capabilities"),
    "token_category_constrained": ("TokenFlow", "semantic_capabilities"),
    "enforces_supply_cap": ("TokenFlow", "semantic_capabilities"),
    # Lifecycle
    "reanchors_covenant": ("Lifecycle", "cashscript_ast"),
    "migratory_output": ("Lifecycle", "semantic_capabilities"),
    "terminating_output": ("Lifecycle", "semantic_capabilities"),
    "capability_retained": ("Lifecycle", "semantic_capabilities"),
    "capability_escaped": ("Lifecycle", "semantic_capabilities"),
}


class CapabilityTier(str, Enum):
    STRUCTURAL = "Structural"
    AUTHORIZATION = "Authorization"
    TOKEN_FLOW = "TokenFlow"
    LIFECYCLE = "Lifecycle"
    EXPERIMENTAL = "Experimental"


@dataclass
class CapabilityEvidence:
    key: str
    value: bool
    tier: str
    source: str  # ast | structural | heuristic
    anchors: List[str] = field(default_factory=list)


@dataclass
class SemanticCapabilities:
    """Tiered capability snapshot — data only, no policy."""

    structural: Dict[str, bool] = field(default_factory=dict)
    authorization: Dict[str, bool] = field(default_factory=dict)
    token_flow: Dict[str, bool] = field(default_factory=dict)
    lifecycle: Dict[str, bool] = field(default_factory=dict)
    evidence: List[CapabilityEvidence] = field(default_factory=list)
    parse_error: Optional[str] = None

    def all_capabilities(self) -> Dict[str, bool]:
        out: Dict[str, bool] = {}
        for tier_map in (self.structural, self.authorization, self.token_flow, self.lifecycle):
            out.update(tier_map)
        return out

    def get(self, key: str) -> Optional[bool]:
        return self.all_capabilities().get(key)

    def to_trace_dict(self) -> Dict[str, Any]:
        return {
            "capabilities": self.all_capabilities(),
            "by_tier": {
                "Structural": self.structural,
                "Authorization": self.authorization,
                "TokenFlow": self.token_flow,
                "Lifecycle": self.lifecycle,
            },
            "derived_from": [
                {"key": e.key, "value": e.value, "tier": e.tier, "source": e.source, "anchors": e.anchors}
                for e in self.evidence
                if e.value
            ],
            "parse_error": self.parse_error,
        }


def _add_evidence(
    caps: SemanticCapabilities,
    key: str,
    value: bool,
    source: str,
    anchors: List[str],
) -> None:
    tier, _owner = CAPABILITY_REGISTRY.get(key, ("Experimental", "unknown"))
    if tier == CapabilityTier.EXPERIMENTAL.value:
        logger.warning("Blocked experimental capability key: %s", key)
        return
    ev = CapabilityEvidence(key=key, value=value, tier=tier, source=source, anchors=anchors)
    caps.evidence.append(ev)
    tier_map = {
        "Structural": caps.structural,
        "Authorization": caps.authorization,
        "TokenFlow": caps.token_flow,
        "Lifecycle": caps.lifecycle,
    }.get(tier)
    if tier_map is not None:
        tier_map[key] = value


def extract_semantic_capabilities(
    code: str,
    *,
    contract_mode: str = "",
    intent_modes: Optional[Dict[str, str]] = None,
) -> SemanticCapabilities:
    """
    AST-first capability extraction. No benchmark/detector conditionals.
    intent_modes may inform lifecycle heuristics only (ownership_mode, lifecycle_mode, supply_mode).
    """
    caps = SemanticCapabilities()
    intent_modes = intent_modes or {}

    struct_diag = diagnose_structure(code)
    struct_ok = struct_diag.valid
    _add_evidence(
        caps,
        "structurally_valid",
        struct_ok,
        "structural",
        [] if struct_ok else struct_diag.issues[:3],
    )

    try:
        ast = CashScriptAST(code, contract_mode=contract_mode)
    except Exception as exc:
        caps.parse_error = str(exc)
        return caps

    has_sig = len(ast.check_sig_calls) > 0
    has_multisig = any("checkMultiSig" in c.condition for c in ast.validations) or bool(
        re.search(r"checkMultiSig\s*\(", code)
    )
    _add_evidence(caps, "has_signature_auth", has_sig, "ast", _sig_anchors(ast))
    _add_evidence(caps, "has_multisig_auth", has_multisig, "ast", _multisig_anchors(code))
    _add_evidence(caps, "requires_signature", has_sig, "ast", _sig_anchors(ast))
    _add_evidence(caps, "requires_multisig", has_multisig, "ast", _multisig_anchors(code))

    preserves_cat, cat_anchors = _preserves_token_category_guard(code)
    preserves_amt, amt_anchors = _preserves_token_amount_guard(code)
    burns = bool(re.search(r"tx\.outputs\[\d+\]\.tokenCategory\s*==\s*0x\b", code))
    cat_constrained = bool(re.search(r"tx\.inputs\[[^\]]+\]\.tokenCategory\s*==", code))
    _add_evidence(
        caps,
        "preserves_token_category",
        preserves_cat,
        "ast",
        cat_anchors,
    )
    _add_evidence(
        caps,
        "preserves_token_amount",
        preserves_amt,
        "ast",
        amt_anchors,
    )
    _add_evidence(caps, "burns_output_tokens", burns, "heuristic", _grep_lines(code, r"tokenCategory\s*==\s*0x"))
    _add_evidence(
        caps,
        "token_category_constrained",
        cat_constrained,
        "heuristic",
        _grep_lines(code, r"inputs\[.*\]\.tokenCategory"),
    )

    supply_cap_ok, supply_anchors = _mint_supply_cap_in_requires(code)
    _add_evidence(caps, "enforces_supply_cap", supply_cap_ok, "ast", supply_anchors)

    reanchor = bool(re.search(r"lockingBytecode\s*==\s*this\.activeBytecode", code))
    migratory = bool(
        re.search(
            r"lockingBytecode\s*==\s*(?!this\.activeBytecode)(\w+)",
            code,
        )
        or re.search(
            r"recipientLockingBytecode|buyerLockingBytecode|sellerLockingBytecode|buyerPkh|sellerPkh",
            code,
        )
    )
    terminating = bool(
        re.search(r"tx\.outputs\[\d+\]\.value", code)
        and re.search(r"release|claim|purchase|redeem", code, re.I)
    )
    retained, retained_anchors = _capability_retained_guard(code)
    escaped = bool(re.search(r"0x02", code) and not retained)

    _add_evidence(caps, "reanchors_covenant", reanchor, "ast", _grep_lines(code, r"this\.activeBytecode"))
    _add_evidence(caps, "migratory_output", migratory, "heuristic", _grep_lines(code, r"lockingBytecode\s*=="))
    _add_evidence(caps, "terminating_output", terminating, "heuristic", _grep_lines(code, r"\.value"))
    _add_evidence(caps, "capability_retained", retained, "ast", retained_anchors)
    _add_evidence(caps, "capability_escaped", escaped, "heuristic", _grep_lines(code, r"0x02"))

    om = (intent_modes.get("ownership_mode") or "").lower()
    lm = (intent_modes.get("lifecycle_mode") or "").lower()
    if om == "soulbound":
        external = bool(
            re.search(r"lockingBytecode\s*==\s*(?!this\.activeBytecode)(\w+)", code)
            and "this.activeBytecode" not in code
        )
        _add_evidence(
            caps,
            "unrestricted_external_transfer",
            external,
            "heuristic",
            _grep_lines(code, r"lockingBytecode"),
        )
    if lm in ("state_transition", "persistent") and om != "soulbound":
        has_commit = bool(re.search(r"nftCommitment", code))
        has_sig_on_mutate = has_sig and has_commit
        _add_evidence(
            caps,
            "unrestricted_state_update",
            has_commit and not has_sig_on_mutate,
            "heuristic",
            _grep_lines(code, r"nftCommitment"),
        )

    return caps


def _sig_anchors(ast: CashScriptAST) -> List[str]:
    return [f"checkSig({c.sig}, {c.pubkey})" for c in ast.check_sig_calls[:5]]


def _multisig_anchors(code: str) -> List[str]:
    m = re.search(r"checkMultiSig\s*\([^)]+\)", code)
    return [m.group(0)[:80]] if m else []


def _preserves_token_category_guard(code: str) -> tuple[bool, List[str]]:
    pattern = re.compile(
        r"outputs\[[^\]]+\]\.tokenCategory\s*==\s*tx\.inputs\[this\.activeInputIndex\]\.tokenCategory",
        re.DOTALL,
    )
    m = pattern.search(code)
    if not m:
        return False, []
    return True, [re.sub(r"\s+", " ", m.group(0))[:120]]


def _preserves_token_amount_guard(code: str) -> tuple[bool, List[str]]:
    pattern = re.compile(
        r"outputs\[[^\]]+\]\.tokenAmount\s*==\s*tx\.inputs\[this\.activeInputIndex\]\.tokenAmount",
        re.DOTALL,
    )
    m = pattern.search(code)
    if not m:
        return False, []
    return True, [re.sub(r"\s+", " ", m.group(0))[:120]]


def _capability_retained_guard(code: str) -> tuple[bool, List[str]]:
    if not re.search(r"0x02", code):
        return False, []
    anchors: List[str] = []
    for m in re.finditer(r"require\s*\((.*?)\)\s*;", code, re.DOTALL):
        expr = m.group(1)
        if "lockingBytecode" in expr and "this.activeBytecode" in expr:
            anchors.append(expr.strip()[:120])
    return bool(anchors), anchors


def _mint_supply_cap_in_requires(code: str) -> tuple[bool, List[str]]:
    """True only when a require() inequality binds mint increment to maxSupply/totalSupply."""
    anchors: List[str] = []
    for m in re.finditer(r"require\s*\((.*?)\)\s*;", code, re.DOTALL):
        expr = m.group(1)
        if not re.search(r"<=|<", expr):
            continue
        if not re.search(r"maxSupply|totalSupply|remainingSupply", expr, re.IGNORECASE):
            continue
        if not re.search(r"totalMinted|mintAmount|currentSupply", expr, re.IGNORECASE):
            continue
        anchors.append(expr.strip()[:120])
    return bool(anchors), anchors


def _grep_lines(code: str, pattern: str, limit: int = 5) -> List[str]:
    anchors: List[str] = []
    for line in code.splitlines():
        if re.search(pattern, line):
            anchors.append(line.strip()[:120])
            if len(anchors) >= limit:
                break
    return anchors


def save_capability_trace(
    *,
    case_id: str,
    caps: SemanticCapabilities,
    requirement_results: Optional[Dict[str, Dict[str, Any]]] = None,
) -> Path:
    """Persist capability trace for benchmark/debug."""
    CAPABILITY_TRACE_DIR.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
    path = CAPABILITY_TRACE_DIR / f"{case_id}_{ts}.json"
    payload = {
        "case_id": case_id,
        "timestamp": ts,
        **caps.to_trace_dict(),
        "requirement_results": requirement_results or {},
    }
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return path
