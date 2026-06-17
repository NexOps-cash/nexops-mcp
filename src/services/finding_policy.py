"""
Central policy layer for audit finding classification.

Owns title generation, severity caps, issue_class mapping, and triggerability.
The LLM must not directly control final severity or security-branded titles.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from src.models import (
    ConfidenceLevel,
    ExploitSeverity,
    FindingKind,
    IssueClass,
    Provenance,
    Severity,
    Triggerability,
)

RULE_KIND_HINTS: dict[str, FindingKind] = {
    "output_binding_missing": FindingKind.INVARIANT_GAP,
    "partial_aggregation_risk": FindingKind.DESIGN_TRADE_OFF,
    "input_output_coupling": FindingKind.INVARIANT_GAP,
    "index_underflow": FindingKind.OPERATIONAL_RISK,
    "authorization_model_classifier": FindingKind.OBSERVATION,
}

RULE_ISSUE_CLASS_HINTS: dict[str, IssueClass] = {
    "output_binding_missing": IssueClass.CONTEXTUAL,
    "partial_aggregation_risk": IssueClass.CONTEXTUAL,
    "input_output_coupling": IssueClass.CONTEXTUAL,
    "index_underflow": IssueClass.CONTEXTUAL,
    "authorization_model_classifier": IssueClass.NOISE,
}

RULE_SEVERITY_CAP_OVERRIDES: dict[str, Severity] = {
    "compile_unknown_error": Severity.HIGH,
    "compile_environment_error": Severity.HIGH,
    "compile_timeout": Severity.HIGH,
    "compile_internal_error": Severity.HIGH,
    "compile_toolchain_error": Severity.HIGH,
}

# ── Severity caps per finding kind ───────────────────────────────────────────

SEVERITY_CAP: dict[FindingKind, Severity] = {
    FindingKind.VULNERABILITY: Severity.CRITICAL,
    FindingKind.INVARIANT_GAP: Severity.MEDIUM,
    FindingKind.OPERATIONAL_RISK: Severity.LOW,
    FindingKind.DEPLOYMENT_REQUIREMENT: Severity.LOW,
    FindingKind.DESIGN_TRADE_OFF: Severity.INFO,
    FindingKind.OBSERVATION: Severity.INFO,
}

TITLE_PREFIX: dict[FindingKind, str] = {
    FindingKind.VULNERABILITY: "Security Vulnerability",
    FindingKind.INVARIANT_GAP: "Policy Gap",
    FindingKind.OPERATIONAL_RISK: "Operational Risk",
    FindingKind.DEPLOYMENT_REQUIREMENT: "Deployment Requirement",
    FindingKind.DESIGN_TRADE_OFF: "Design Trade-off",
    FindingKind.OBSERVATION: "Observation",
}

# Rule IDs that are always attacker-triggerable security issues.
_ATTACKER_RULE_IDS = frozenset(
    {
        "capability_unrestricted_payout",
        "capability_missing_auth_state_mutation",
        "capability_unrestricted_nft_transfer",
        "minting_authority_escape",
        "token_category_drift",
        "token_amount_inflation",
        "authority_leak",
        "mutable_capability_leak",
        "unrestricted_token_transfer",
        "vulnerable_covenant.cash",
        "commitment_length_missing",
    }
)

# Text markers for non-attacker (operational / deployment / design) findings.
_NON_ATTACKER_MARKERS = (
    "insufficient fund",
    "insufficient balance",
    "underfund",
    "under-funded",
    "under funded",
    "treasury balance",
    "treasury may be",
    "treasury must be",
    "pre-fund",
    "prefund",
    "liquidity",
    "low balance",
    "not enough fund",
    "cannot pay",
    "fail if balance",
    "fail if insufficient",
    "may fail",
    "transaction may fail",
    "script can fail",
    "script failure",
    "fail at runtime",
    "no change output",
    "change output",
    "dust",
    "fee assumption",
    "operational",
    "honest user",
    "honest party",
    "deployer must",
    "off-chain",
    "external assumption",
    "design tradeoff",
    "design trade-off",
    "intentional rigidity",
    "exact equality",
    "equality constraint",
    "usability",
    "optimization",
    "maintainability",
)

_ATTACKER_MARKERS = (
    "unauthorized",
    "bypass",
    "attacker",
    "anyone can",
    "without signature",
    "without authorization",
    "wrong recipient",
    "redirect",
    "drain",
    "steal",
    "theft",
    "double spend",
    "mint escape",
    "authority leak",
    "missing authorization",
    "missing auth",
    "unrestricted payout",
    "unrestricted transfer",
    "policy gap",
    "not enforced",
    "missing enforcement",
    "fixed salary",
    "fixed amount",
    "predetermined amount",
)

_GRIEF_MARKERS = (
    "grief",
    "griefing",
    "denial-of-service",
    "denial of service",
    " dos",
    "bricking",
    "self-grief",
    "placement-driven",
    "subset processing",
    "input-order",
    "partial aggregation",
)


@dataclass
class FinalizedFinding:
    title: str
    severity: Severity
    issue_class: IssueClass
    exploit_severity: ExploitSeverity
    kind: FindingKind
    confidence: ConfidenceLevel
    triggerability: Triggerability


def classify_triggerability(
    *,
    text: str = "",
    rule_id: str = "",
    exploit_severity: ExploitSeverity = ExploitSeverity.NOT_APPLICABLE,
) -> Triggerability:
    """
    Lightweight triggerability: can someone intentionally benefit from triggering this?
    """
    rid = (rule_id or "").lower()
    if rid in _ATTACKER_RULE_IDS:
        return Triggerability.ATTACKER

    t = (text or "").lower()

    if any(m in t for m in _NON_ATTACKER_MARKERS):
        return Triggerability.NON_ATTACKER

    if exploit_severity == ExploitSeverity.DIRECT_FUND_LOSS:
        if any(m in t for m in _GRIEF_MARKERS):
            return Triggerability.NON_ATTACKER
        return Triggerability.ATTACKER

    if exploit_severity == ExploitSeverity.PARTIAL_VIOLATION:
        if any(m in t for m in _ATTACKER_MARKERS):
            return Triggerability.ATTACKER
        if any(m in t for m in _GRIEF_MARKERS):
            return Triggerability.NON_ATTACKER
        return Triggerability.UNKNOWN

    if any(m in t for m in _ATTACKER_MARKERS):
        return Triggerability.ATTACKER

    if any(m in t for m in _GRIEF_MARKERS):
        return Triggerability.NON_ATTACKER

    if rid.startswith("intent_"):
        # Intent invariant gaps are policy enforcement — attacker can exploit mis-payment.
        if "fixed" in t or "recipient" in t or "salary" in t or "amount" in t:
            return Triggerability.ATTACKER
        return Triggerability.UNKNOWN

    return Triggerability.UNKNOWN


def infer_kind(
    *,
    triggerability: Triggerability,
    semantic_label: str = "",
    exploit_severity: ExploitSeverity = ExploitSeverity.NOT_APPLICABLE,
    rule_id: str = "",
    text: str = "",
) -> FindingKind:
    """Map triggerability + context to FindingKind."""
    label = (semantic_label or "").strip().lower()
    rid = (rule_id or "").lower()
    if rid in RULE_KIND_HINTS:
        return RULE_KIND_HINTS[rid]

    if rid.startswith("intent_"):
        return FindingKind.INVARIANT_GAP

    t = (text or "").lower()

    if label == "design_tradeoff":
        return FindingKind.DESIGN_TRADE_OFF
    if label == "assumption":
        return FindingKind.DEPLOYMENT_REQUIREMENT
    if label == "funds_unspendable":
        return FindingKind.VULNERABILITY
    if label == "safe":
        return FindingKind.OBSERVATION

    if triggerability == Triggerability.NON_ATTACKER:
        if any(
            m in t
            for m in (
                "treasury",
                "pre-fund",
                "prefund",
                "off-chain",
                "external",
                "oracle",
                "deployment",
                "assumption",
            )
        ):
            return FindingKind.DEPLOYMENT_REQUIREMENT
        if any(
            m in t
            for m in (
                "design",
                "tradeoff",
                "trade-off",
                "change output",
                "dust",
                "no change",
                "rigidity",
                "equality",
            )
        ):
            return FindingKind.DESIGN_TRADE_OFF
        return FindingKind.OPERATIONAL_RISK

    if triggerability == Triggerability.ATTACKER:
        if label == "exploit" or exploit_severity == ExploitSeverity.DIRECT_FUND_LOSS:
            return FindingKind.VULNERABILITY
        if label == "exploit" or exploit_severity == ExploitSeverity.PARTIAL_VIOLATION:
            return FindingKind.VULNERABILITY
        if "policy" in t or "intent" in t or "not enforced" in t or "missing" in t:
            return FindingKind.INVARIANT_GAP
        return FindingKind.VULNERABILITY

    # UNKNOWN — use semantic label hints
    if label == "exploit":
        return FindingKind.VULNERABILITY
    if label == "design_tradeoff":
        return FindingKind.DESIGN_TRADE_OFF
    if label == "assumption":
        return FindingKind.DEPLOYMENT_REQUIREMENT

    if rid.startswith("lnc-") or rid.startswith("compile_"):
        return FindingKind.OBSERVATION

    return FindingKind.OBSERVATION


def derive_confidence(
    *,
    provenance: Provenance,
    confidence_score: Optional[float] = None,
    kind: FindingKind = FindingKind.OBSERVATION,
) -> ConfidenceLevel:
    if kind in (FindingKind.DESIGN_TRADE_OFF, FindingKind.OBSERVATION):
        return ConfidenceLevel.INFORMATIONAL
    if provenance == Provenance.DETERMINISTIC:
        return ConfidenceLevel.PROVEN
    if provenance == Provenance.HYBRID:
        return ConfidenceLevel.FIRM
    # LLM
    if confidence_score is None:
        return ConfidenceLevel.LIKELY
    score = max(0.0, min(1.0, float(confidence_score)))
    if score >= 0.85:
        return ConfidenceLevel.FIRM
    if score >= 0.60:
        return ConfidenceLevel.LIKELY
    return ConfidenceLevel.SPECULATIVE


def kind_to_semantic_category(kind: FindingKind) -> str:
    """Legacy semantic_category for scoring.py — scoring unchanged."""
    return {
        FindingKind.VULNERABILITY: "major_protocol_flaw",
        FindingKind.INVARIANT_GAP: "moderate_logic_risk",
        FindingKind.OPERATIONAL_RISK: "minor_design_risk",
        FindingKind.DEPLOYMENT_REQUIREMENT: "minor_design_risk",
        FindingKind.DESIGN_TRADE_OFF: "moderate_logic_risk",
        FindingKind.OBSERVATION: "none",
    }.get(kind, "none")


def _clamp_severity(proposed: Severity, cap: Severity) -> Severity:
    order = [
        Severity.INFO,
        Severity.LOW,
        Severity.MEDIUM,
        Severity.HIGH,
        Severity.CRITICAL,
    ]
    if order.index(proposed) > order.index(cap):
        return cap
    return proposed


def _default_exploit_for_kind(kind: FindingKind) -> ExploitSeverity:
    if kind == FindingKind.VULNERABILITY:
        return ExploitSeverity.DIRECT_FUND_LOSS
    if kind == FindingKind.INVARIANT_GAP:
        return ExploitSeverity.PARTIAL_VIOLATION
    if kind == FindingKind.DESIGN_TRADE_OFF:
        return ExploitSeverity.GRIEFING
    return ExploitSeverity.NOT_APPLICABLE


def _default_issue_class(
    kind: FindingKind,
    confidence: ConfidenceLevel,
    deferred_validation: bool = False,
) -> IssueClass:
    if deferred_validation:
        return IssueClass.CONTEXTUAL
    if kind in (FindingKind.DESIGN_TRADE_OFF, FindingKind.OBSERVATION):
        return IssueClass.NOISE if kind == FindingKind.OBSERVATION else IssueClass.CONTEXTUAL
    if kind in (FindingKind.OPERATIONAL_RISK, FindingKind.DEPLOYMENT_REQUIREMENT):
        return IssueClass.CONTEXTUAL
    if confidence == ConfidenceLevel.SPECULATIVE:
        return IssueClass.CONTEXTUAL
    if confidence == ConfidenceLevel.INFORMATIONAL:
        return IssueClass.NOISE
    if kind == FindingKind.INVARIANT_GAP:
        return IssueClass.REAL_ISSUE
    if kind == FindingKind.VULNERABILITY:
        return IssueClass.REAL_ISSUE
    return IssueClass.CONTEXTUAL


def _proposed_severity_for_kind(kind: FindingKind) -> Severity:
    defaults = {
        FindingKind.VULNERABILITY: Severity.HIGH,
        FindingKind.INVARIANT_GAP: Severity.MEDIUM,
        FindingKind.OPERATIONAL_RISK: Severity.LOW,
        FindingKind.DEPLOYMENT_REQUIREMENT: Severity.LOW,
        FindingKind.DESIGN_TRADE_OFF: Severity.INFO,
        FindingKind.OBSERVATION: Severity.INFO,
    }
    return defaults.get(kind, Severity.MEDIUM)


def build_title(kind: FindingKind, summary: str) -> str:
    prefix = TITLE_PREFIX.get(kind, "Finding")
    summary = (summary or "Review required").strip()
    if summary.lower().startswith(prefix.lower()):
        return summary
    # Keep titles concise — first sentence or 80 chars
    short = summary.split(".")[0].strip()
    if len(short) > 80:
        short = short[:77] + "..."
    return f"{prefix}: {short}"


def finalize(
    *,
    kind: Optional[FindingKind] = None,
    proposed_severity: Optional[Severity] = None,
    summary: str = "",
    rule_id: str = "",
    semantic_label: str = "",
    text: str = "",
    exploit_severity: ExploitSeverity = ExploitSeverity.NOT_APPLICABLE,
    provenance: Provenance = Provenance.DETERMINISTIC,
    confidence_score: Optional[float] = None,
    deferred_validation: bool = False,
    triggerability: Optional[Triggerability] = None,
) -> FinalizedFinding:
    """
    Single chokepoint: kind, severity, title, issue_class from policy — not raw LLM.
    """
    trig = triggerability or classify_triggerability(
        text=text,
        rule_id=rule_id,
        exploit_severity=exploit_severity,
    )
    resolved_kind = kind or infer_kind(
        triggerability=trig,
        semantic_label=semantic_label,
        exploit_severity=exploit_severity,
        rule_id=rule_id,
        text=text,
    )

    confidence = derive_confidence(
        provenance=provenance,
        confidence_score=confidence_score,
        kind=resolved_kind,
    )

    cap = SEVERITY_CAP.get(resolved_kind, Severity.MEDIUM)
    rid_lower = (rule_id or "").lower()
    if rid_lower in RULE_SEVERITY_CAP_OVERRIDES:
        cap = RULE_SEVERITY_CAP_OVERRIDES[rid_lower]
    base_sev = proposed_severity or _proposed_severity_for_kind(resolved_kind)
    severity = _clamp_severity(base_sev, cap)

    if confidence == ConfidenceLevel.SPECULATIVE:
        severity = _clamp_severity(severity, Severity.MEDIUM)
    if confidence == ConfidenceLevel.INFORMATIONAL:
        severity = Severity.INFO

    # Non-attacker kinds must never present as CRITICAL/HIGH security findings.
    if trig == Triggerability.NON_ATTACKER and resolved_kind != FindingKind.VULNERABILITY:
        non_attacker_cap = SEVERITY_CAP[resolved_kind]
        if rid_lower not in RULE_SEVERITY_CAP_OVERRIDES:
            severity = _clamp_severity(severity, non_attacker_cap)

    resolved_exploit = exploit_severity
    if resolved_kind == FindingKind.DESIGN_TRADE_OFF:
        resolved_exploit = ExploitSeverity.GRIEFING
    elif resolved_kind in (
        FindingKind.DEPLOYMENT_REQUIREMENT,
        FindingKind.OPERATIONAL_RISK,
        FindingKind.OBSERVATION,
    ):
        if resolved_exploit == ExploitSeverity.DIRECT_FUND_LOSS:
            resolved_exploit = ExploitSeverity.NOT_APPLICABLE
    elif resolved_exploit == ExploitSeverity.NOT_APPLICABLE:
        resolved_exploit = _default_exploit_for_kind(resolved_kind)
    if trig == Triggerability.NON_ATTACKER:
        if resolved_exploit == ExploitSeverity.DIRECT_FUND_LOSS:
            resolved_exploit = ExploitSeverity.NOT_APPLICABLE

    issue_class = _default_issue_class(
        resolved_kind, confidence, deferred_validation=deferred_validation
    )
    if rid_lower in RULE_ISSUE_CLASS_HINTS:
        issue_class = RULE_ISSUE_CLASS_HINTS[rid_lower]
    if confidence == ConfidenceLevel.SPECULATIVE and issue_class == IssueClass.REAL_ISSUE:
        issue_class = IssueClass.CONTEXTUAL

    title = build_title(resolved_kind, summary or text or rule_id)

    return FinalizedFinding(
        title=title,
        severity=severity,
        issue_class=issue_class,
        exploit_severity=resolved_exploit,
        kind=resolved_kind,
        confidence=confidence,
        triggerability=trig,
    )


def is_exploitable(
    reason: str = "",
    exploit: str = "",
    message: str = "",
) -> bool:
    """
    Backward-compatible helper for deterministic paths.
    True when triggerability is ATTACKER (or unknown with loss markers).
    """
    text = f"{reason} {exploit} {message}"
    trig = classify_triggerability(text=text)
    if trig == Triggerability.ATTACKER:
        return True
    if trig == Triggerability.NON_ATTACKER:
        return False
    return True
