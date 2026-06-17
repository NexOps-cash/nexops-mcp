"""Tests for finding_policy classification and severity caps."""

import pytest

from src.models import (
    ConfidenceLevel,
    ExploitSeverity,
    FindingKind,
    Provenance,
    Severity,
    Triggerability,
)
from src.services.finding_policy import (
    build_title,
    classify_triggerability,
    finalize,
    infer_kind,
)


def test_treasury_underfunded_is_non_attacker():
    trig = classify_triggerability(
        text="Treasury may be underfunded relative to payroll obligations."
    )
    assert trig == Triggerability.NON_ATTACKER


def test_missing_salary_enforcement_is_attacker():
    trig = classify_triggerability(
        text="Contract does not enforce fixed salary amounts per recipient."
    )
    assert trig == Triggerability.ATTACKER


def test_no_change_output_is_non_attacker():
    trig = classify_triggerability(
        text="Contract does not handle change outputs or dust."
    )
    assert trig == Triggerability.NON_ATTACKER


def test_operational_finding_never_security_title():
    result = finalize(
        summary="Treasury may be underfunded",
        text="Treasury may be underfunded relative to payroll obligations.",
        semantic_label="exploit",
        exploit_severity=ExploitSeverity.DIRECT_FUND_LOSS,
        provenance=Provenance.LLM,
        confidence_score=0.95,
    )
    assert result.kind in (
        FindingKind.OPERATIONAL_RISK,
        FindingKind.DEPLOYMENT_REQUIREMENT,
    )
    assert result.severity not in (Severity.CRITICAL, Severity.HIGH)
    assert "Security Vulnerability" not in result.title
    assert "Major Protocol Flaw" not in result.title


def test_design_tradeoff_capped_to_info():
    result = finalize(
        summary="No change output support",
        text="Contract does not handle change outputs — intentional rigidity.",
        semantic_label="design_tradeoff",
        provenance=Provenance.LLM,
        confidence_score=0.9,
    )
    assert result.kind == FindingKind.DESIGN_TRADE_OFF
    assert result.severity == Severity.INFO
    assert result.title.startswith("Design Trade-off:")


def test_invariant_gap_medium_proven():
    result = finalize(
        kind=FindingKind.INVARIANT_GAP,
        summary="fixed amount per recipient",
        rule_id="intent_fixed_amount_per_recipient",
        text="Intent requires fixed per-recipient amounts but only sum conservation found.",
        exploit_severity=ExploitSeverity.PARTIAL_VIOLATION,
        provenance=Provenance.DETERMINISTIC,
        triggerability=Triggerability.ATTACKER,
    )
    assert result.severity == Severity.MEDIUM
    assert result.kind == FindingKind.INVARIANT_GAP
    assert result.triggerability == Triggerability.ATTACKER
    assert result.title.startswith("Policy Gap:")


def test_speculative_llm_capped_at_medium():
    result = finalize(
        summary="Possible bypass",
        text="Attacker might bypass authorization under edge cases.",
        semantic_label="exploit",
        exploit_severity=ExploitSeverity.DIRECT_FUND_LOSS,
        provenance=Provenance.LLM,
        confidence_score=0.35,
    )
    assert result.confidence == ConfidenceLevel.SPECULATIVE
    assert result.severity == Severity.MEDIUM


def test_infer_kind_from_semantic_labels():
    assert (
        infer_kind(
            triggerability=Triggerability.NON_ATTACKER,
            semantic_label="design_tradeoff",
        )
        == FindingKind.DESIGN_TRADE_OFF
    )
    assert (
        infer_kind(
            triggerability=Triggerability.NON_ATTACKER,
            semantic_label="assumption",
        )
        == FindingKind.DEPLOYMENT_REQUIREMENT
    )


def test_build_title_does_not_duplicate_prefix():
    title = build_title(FindingKind.OPERATIONAL_RISK, "Operational Risk: low balance")
    assert title.count("Operational Risk") == 1
