"""Policy mapping for Semantic Security Judge V2 structured judgments."""

from src.models import (
    ExploitSeverity,
    FindingKind,
    SemanticJudgment,
    SemanticVerdict,
    StructuredSemanticFinding,
    TrustAssumption,
    Triggerability,
    ValueImpact,
)
from src.services.finding_policy import (
    adjust_confidence_from_uncertainty,
    finalize_from_judgment,
    map_judgment_triggerability,
    resolve_exploit_severity_from_value_impact,
    resolve_kind_from_judgment,
)


def _finding(**kwargs) -> StructuredSemanticFinding:
    defaults = {
        "reasoning_steps": ["a", "b", "c", "d"],
        "confidence": 0.9,
    }
    defaults.update(kwargs)
    return StructuredSemanticFinding(**defaults)


def test_attacker_auth_impact_vulnerability():
    f = _finding(attacker_gain=True, authorization_impact=True, value_impact=ValueImpact.MEDIUM)
    assert resolve_kind_from_judgment(f) == FindingKind.VULNERABILITY
    assert map_judgment_triggerability(f) == Triggerability.ATTACKER


def test_attacker_low_value_invariant_gap():
    f = _finding(attacker_gain=True, authorization_impact=False, value_impact=ValueImpact.LOW)
    assert resolve_kind_from_judgment(f) == FindingKind.INVARIANT_GAP
    assert resolve_kind_from_judgment(f) != FindingKind.VULNERABILITY


def test_external_funding_deployment_requirement():
    f = _finding(
        attacker_gain=False,
        trust_assumption=TrustAssumption.EXTERNAL_FUNDING,
        value_impact=ValueImpact.NONE,
    )
    assert resolve_kind_from_judgment(f) == FindingKind.DEPLOYMENT_REQUIREMENT
    assert map_judgment_triggerability(f) == Triggerability.NON_ATTACKER


def test_policy_gap_without_attacker_gain():
    f = _finding(attacker_gain=False, authorization_impact=True, value_impact=ValueImpact.NONE)
    assert resolve_kind_from_judgment(f) == FindingKind.INVARIANT_GAP


def test_design_tradeoff_ignores_exploit_class():
    f = _finding(
        attacker_gain=False,
        value_impact=ValueImpact.LOW,
        exploit_class="griefing",
    )
    assert resolve_kind_from_judgment(f) == FindingKind.DESIGN_TRADE_OFF


def test_exploit_severity_from_value_impact_only():
    sev = resolve_exploit_severity_from_value_impact(FindingKind.VULNERABILITY, ValueImpact.HIGH)
    assert sev == ExploitSeverity.DIRECT_FUND_LOSS
    sev2 = resolve_exploit_severity_from_value_impact(
        FindingKind.VULNERABILITY,
        ValueImpact.HIGH,
    )
    assert sev2 == ExploitSeverity.DIRECT_FUND_LOSS


def test_evidence_gaps_cap_confidence():
    f = _finding(evidence_gaps=["off-chain balance unknown"], confidence=0.95)
    assert adjust_confidence_from_uncertainty(f) <= 0.6


def test_funds_unspendable_special_case():
    judgment = SemanticJudgment(
        verdict=SemanticVerdict.FINDING,
        finding=_finding(gap_id="semantic.funds_unspendable", affected_invariant="funds_unspendable"),
    )
    finalized = finalize_from_judgment(judgment)
    assert finalized is not None
    assert finalized.kind == FindingKind.VULNERABILITY
