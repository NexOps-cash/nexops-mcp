"""
Deterministic intent-invariant verification for the audit path.

Compares declared intent against enforced on-chain invariants without LLM involvement.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional, Tuple

from src.models import (
    AuditIssue,
    ConfidenceLevel,
    ExploitSeverity,
    FindingKind,
    IntentModel,
    Provenance,
    Severity,
    Triggerability,
)
from src.services.finding_policy import finalize
from src.services.sanity_checker import SanityChecker
from src.utils.split_conservation import (
    has_bch_value_conservation,
    has_token_amount_conservation,
)

# ── Intent text heuristics ───────────────────────────────────────────────────

_SPLIT_KEYWORDS = (
    "split",
    "payroll",
    "distribute",
    "revenue",
    "treasury",
    "employees",
    "partners",
    "recipients",
    "share",
)

_RECIPIENT_INTENT_MARKERS = (
    "recipient",
    "employee",
    "partner",
    "payroll",
    "distribute to",
    "lockingbytecode",
    "destination",
    "address",
)

_FIXED_AMOUNT_MARKERS = (
    "fixed salary",
    "fixed amount",
    "fixed salaries",
    "predetermined amount",
    "predetermined share",
    "each employee gets",
    "each gets",
    "per employee",
    "minimum amount",
    "at least",
    "exact amount",
    "specific amount",
)


class InvariantTier(str, Enum):
    """Security controls vs business/policy rules."""

    SECURITY = "security"
    BUSINESS = "business"


# Per-invariant tier: missing security controls enable unauthorized value movement.
INVARIANT_TIER_BY_ID: dict[str, InvariantTier] = {
    "auth_gate": InvariantTier.SECURITY,
    "value_conservation": InvariantTier.SECURITY,
    "fixed_amount_per_recipient": InvariantTier.BUSINESS,
    "recipient_binding": InvariantTier.BUSINESS,
    "token_category_preservation": InvariantTier.BUSINESS,
}


@dataclass
class InvariantStatus:
    invariant_id: str
    label: str
    status: str  # ENFORCED | MISSING | NOT_ENFORCEABLE_ONCHAIN
    detail: str = ""
    tier: InvariantTier = InvariantTier.BUSINESS


@dataclass
class InvariantMatrix:
    enforced: List[InvariantStatus] = field(default_factory=list)
    missing: List[InvariantStatus] = field(default_factory=list)
    not_enforceable: List[InvariantStatus] = field(default_factory=list)

    def format_for_prompt(self) -> str:
        lines: List[str] = []
        if self.enforced:
            lines.append("ENFORCED:")
            for item in self.enforced:
                lines.append(f"- {item.label}")
        if self.missing:
            lines.append("MISSING:")
            for item in self.missing:
                lines.append(f"- {item.label}")
        if self.not_enforceable:
            lines.append("NOT_ENFORCEABLE_ONCHAIN:")
            for item in self.not_enforceable:
                lines.append(f"- {item.label}")
        return "\n".join(lines) if lines else "No intent invariants derived."


def _intent_text(intent: str, model: Optional[IntentModel]) -> str:
    parts = [intent or ""]
    if model and model.purpose:
        parts.append(model.purpose)
    return " ".join(parts).lower()


def _is_split_intent(text: str, model: Optional[IntentModel]) -> bool:
    if model:
        ctype = (model.contract_type or "").lower()
        if ctype == "split_payment" or "split" in (model.features or []):
            return True
    return any(kw in text for kw in _SPLIT_KEYWORDS)


def _requires_recipient_binding(text: str) -> bool:
    return any(m in text for m in _RECIPIENT_INTENT_MARKERS)


def _requires_fixed_amounts(text: str) -> bool:
    return any(m in text for m in _FIXED_AMOUNT_MARKERS)


def _requires_treasury_prefunding(text: str) -> bool:
    return any(
        m in text
        for m in (
            "treasury must be funded",
            "treasury pre-funded",
            "treasury prefunded",
            "must be funded before",
        )
    )


def _has_recipient_binding(code: str) -> bool:
    """Constructor or literal lockingBytecode binding on outputs."""
    if re.search(
        r"tx\.outputs\[\d+\]\.lockingBytecode\s*==\s*(?:new\s+)?LockingBytecode",
        code,
    ):
        return True
    if re.search(
        r"tx\.outputs\[\d+\]\.lockingBytecode\s*==\s*\w+",
        code,
    ):
        # Exclude comparisons to this.activeBytecode (covenant continuation)
        for m in re.finditer(
            r"tx\.outputs\[\d+\]\.lockingBytecode\s*==\s*(\w+)",
            code,
        ):
            rhs = m.group(1)
            if rhs not in ("this", "tx"):
                return True
    return False


def _has_auth_gate(code: str) -> bool:
    return bool(re.search(r"checkSig|checkMultiSig", code))


def _has_token_category_preservation(code: str) -> bool:
    if "tokenCategory" not in code:
        return True  # not applicable
    return bool(
        re.search(
            r"tx\.outputs\[\d+\]\.tokenCategory\s*==\s*tx\.inputs\[this\.activeInputIndex\]\.tokenCategory",
            code,
        )
    )


def _has_value_or_token_conservation(code: str) -> bool:
    if has_bch_value_conservation(code):
        return True
    if "tokenAmount" in code and has_token_amount_conservation(code):
        return True
    return False


def _has_fixed_per_output_amounts(code: str) -> bool:
    """
    Per-output fixed amount enforcement (literal or constructor param),
    not merely sum conservation against input.
    """
    for m in re.finditer(
        r"require\s*\(\s*tx\.outputs\[(\d+)\]\.(value|tokenAmount)\s*==\s*([^)]+)\)",
        code,
    ):
        rhs = m.group(3).strip()
        if re.search(r"tx\.inputs\[", rhs):
            continue
        if re.search(r"activeInputIndex", rhs):
            continue
        if re.search(r"[\+\-\*/]", rhs):
            continue
        # Literal integer or identifier (constructor param)
        if re.match(r"^\d+$", rhs) or re.match(r"^[a-zA-Z_]\w*$", rhs):
            return True

    # Multiple distinct fixed requires (e.g. salaryAlice, salaryBob)
    fixed_refs = re.findall(
        r"tx\.outputs\[\d+\]\.(?:value|tokenAmount)\s*==\s*([a-zA-Z_]\w+)",
        code,
    )
    amount_params = {
        p
        for p in fixed_refs
        if p
        not in (
            "tx",
            "this",
            "inputVal",
            "inputAmount",
            "totalAmount",
        )
        and not p.startswith("tx")
    }
    if len(amount_params) >= 1 and _has_value_or_token_conservation(code):
        # At least one per-output param binding alongside conservation
        per_output = re.findall(
            r"tx\.outputs\[(\d+)\]\.(?:value|tokenAmount)\s*==\s*([a-zA-Z_]\w+)",
            code,
        )
        if len(per_output) >= 2:
            return True
    return False


def _tier_for_sanity_violation(violation: str) -> InvariantTier:
    """Classify SanityChecker messages as security-critical or business/policy."""
    v = violation.lower()
    if "multisig" in v:
        return InvariantTier.SECURITY
    if "timelock" in v:
        return InvariantTier.SECURITY
    if "activebytecode" in v or "covenant" in v:
        return InvariantTier.SECURITY
    if "sum-preservation" in v or "output-count" in v:
        return InvariantTier.SECURITY
    return InvariantTier.BUSINESS


def _classification_for_tier(
    tier: InvariantTier,
) -> Tuple[FindingKind, Severity, ExploitSeverity]:
    if tier == InvariantTier.SECURITY:
        return (
            FindingKind.VULNERABILITY,
            Severity.HIGH,
            ExploitSeverity.DIRECT_FUND_LOSS,
        )
    return (
        FindingKind.INVARIANT_GAP,
        Severity.MEDIUM,
        ExploitSeverity.PARTIAL_VIOLATION,
    )


def _append_missing(
    matrix: InvariantMatrix,
    invariant_id: str,
    label: str,
    detail: str,
) -> None:
    matrix.missing.append(
        InvariantStatus(
            invariant_id=invariant_id,
            label=label,
            status="MISSING",
            detail=detail,
            tier=INVARIANT_TIER_BY_ID.get(invariant_id, InvariantTier.BUSINESS),
        )
    )


def build_invariant_matrix(
    code: str,
    intent: str = "",
    intent_model: Optional[IntentModel] = None,
) -> InvariantMatrix:
    text = _intent_text(intent, intent_model)
    matrix = InvariantMatrix()

    if not intent and not intent_model:
        return matrix

    # Auth gate — common across patterns
    if _has_auth_gate(code):
        matrix.enforced.append(
            InvariantStatus("auth_gate", "authorization gate (signature)", "ENFORCED")
        )
    elif any(w in text for w in ("sign", "multisig", "owner must", "treasury")):
        _append_missing(
            matrix,
            "auth_gate",
            "authorization gate (signature)",
            "Intent requires signer but no checkSig/checkMultiSig found.",
        )

    if not _is_split_intent(text, intent_model):
        return matrix

    # Split / payroll invariants
    if _has_recipient_binding(code):
        matrix.enforced.append(
            InvariantStatus("recipient_binding", "recipient binding", "ENFORCED")
        )
    elif _requires_recipient_binding(text):
        _append_missing(
            matrix,
            "recipient_binding",
            "recipient binding",
            "Intent names recipients but outputs lack lockingBytecode binding.",
        )

    if _has_value_or_token_conservation(code):
        matrix.enforced.append(
            InvariantStatus("value_conservation", "value conservation", "ENFORCED")
        )
    else:
        _append_missing(
            matrix,
            "value_conservation",
            "value conservation",
            "Split intent requires sum-preservation across outputs.",
        )

    if "token" in text or (intent_model and "tokens" in (intent_model.features or [])):
        if _has_token_category_preservation(code):
            matrix.enforced.append(
                InvariantStatus(
                    "token_category_preservation",
                    "token category preservation",
                    "ENFORCED",
                )
            )
        else:
            _append_missing(
                matrix,
                "token_category_preservation",
                "token category preservation",
                "Token split requires tokenCategory checks on outputs.",
            )

    if _requires_fixed_amounts(text):
        if _has_fixed_per_output_amounts(code):
            matrix.enforced.append(
                InvariantStatus(
                    "fixed_amount_per_recipient",
                    "fixed amount per recipient",
                    "ENFORCED",
                )
            )
        else:
            _append_missing(
                matrix,
                "fixed_amount_per_recipient",
                "fixed amount per recipient",
                "Intent requires fixed per-recipient amounts but only sum conservation or variable splits found.",
            )

    if _requires_treasury_prefunding(text):
        matrix.not_enforceable.append(
            InvariantStatus(
                "treasury_prefunding",
                "treasury pre-funding",
                "NOT_ENFORCEABLE_ONCHAIN",
                "Treasury balance cannot be enforced by the contract; document as deployment requirement.",
            )
        )

    return matrix


def _emit_invariant_issue(
    *,
    rule_id: str,
    summary: str,
    description: str,
    recommendation: str,
    tier: InvariantTier,
) -> AuditIssue:
    kind, proposed_severity, exploit = _classification_for_tier(tier)
    finalized = finalize(
        kind=kind,
        proposed_severity=proposed_severity,
        summary=summary,
        rule_id=rule_id,
        text=description,
        exploit_severity=exploit,
        provenance=Provenance.DETERMINISTIC,
        triggerability=Triggerability.ATTACKER,
    )
    return AuditIssue(
        title=finalized.title,
        severity=finalized.severity,
        line=0,
        description=description,
        recommendation=recommendation,
        rule_id=rule_id,
        can_fix=True,
        source="deterministic",
        issue_class=finalized.issue_class,
        exploit_severity=finalized.exploit_severity,
        kind=finalized.kind,
        confidence=ConfidenceLevel.PROVEN,
        confidence_score=1.0,
        provenance=Provenance.DETERMINISTIC,
        triggerability=finalized.triggerability,
    )


def verify_intent_invariants(
    code: str,
    intent: str = "",
    intent_model: Optional[IntentModel] = None,
) -> List[AuditIssue]:
    """
    Run deterministic intent verification and emit AuditIssue objects for gaps.
    """
    matrix = build_invariant_matrix(code, intent, intent_model)
    issues: List[AuditIssue] = []

    for item in matrix.missing:
        summary = item.label.replace("_", " ")
        description = item.detail or f"Declared intent requires {item.label} but it is not enforced in code."
        issues.append(
            _emit_invariant_issue(
                rule_id=f"intent_{item.invariant_id}",
                summary=summary,
                description=description,
                recommendation=f"Add on-chain enforcement for: {item.label}.",
                tier=item.tier,
            )
        )

    # SanityChecker cross-check when structured model available
    if intent_model:
        sanity = SanityChecker.validate(code, intent_model)
        for violation in sanity.get("violations", []):
            if any(i.description == violation for i in issues):
                continue
            tier = _tier_for_sanity_violation(violation)
            issues.append(
                _emit_invariant_issue(
                    rule_id="intent_sanity_check",
                    summary="intent sanity check",
                    description=violation,
                    recommendation="Align contract with declared intent features.",
                    tier=tier,
                )
            )

    return issues
