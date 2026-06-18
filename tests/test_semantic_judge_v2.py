"""Tests for Semantic Security Judge V2 parse and guards."""

import json

from src.models import AuditFactBundle, SemanticVerdict, TrustAssumption, ValueImpact
from src.services.semantic_judge import (
    apply_judgment_guards,
    parse_judgment_response,
    parse_legacy_semantic_response,
)


def _minimal_bundle(**kwargs) -> AuditFactBundle:
    data = {
        "bundle_version": "1.0",
        "contract": {"contract_mode": "generic"},
        "invariant_matrix": {"entries": []},
        "capabilities": {"evidence": []},
        "existing_findings": [],
    }
    data.update(kwargs)
    return AuditFactBundle(**data)


def test_parse_valid_v2_json():
    payload = {
        "judge_version": "2.0",
        "verdict": "no_issue",
        "intent_fidelity_score": 9,
        "intent_fidelity_notes": "ok",
    }
    j = parse_judgment_response(json.dumps(payload))
    assert j.verdict == SemanticVerdict.NO_ISSUE
    assert j.intent_fidelity_score == 9


def test_reject_finding_without_reasoning_steps():
    payload = {
        "verdict": "finding",
        "intent_fidelity_score": 5,
        "finding": {
            "gap_id": "semantic.test",
            "attacker_gain": False,
            "value_impact": "none",
            "reasoning_steps": ["only", "two"],
            "summary": "test",
            "confidence": 0.8,
        },
    }
    j = parse_judgment_response(json.dumps(payload))
    guarded = apply_judgment_guards(j, _minimal_bundle())
    assert guarded.verdict == SemanticVerdict.NO_ISSUE


def test_contradicts_fact_ids_caps_confidence():
    payload = {
        "verdict": "finding",
        "finding": {
            "gap_id": "semantic.test",
            "attacker_gain": False,
            "value_impact": "none",
            "contradicts_fact_ids": ["cap.has_signature_auth"],
            "reasoning_steps": ["1", "2", "3", "4"],
            "summary": "test",
            "confidence": 0.9,
        },
    }
    j = parse_judgment_response(json.dumps(payload))
    guarded = apply_judgment_guards(j, _minimal_bundle())
    assert guarded.finding is not None
    assert guarded.finding.confidence <= 0.5


def test_legacy_adapter_produces_resolvable_judgment():
    legacy = {
        "category": "EXPLOIT",
        "exploit_severity": "direct_fund_loss",
        "explanation": "Unauthorized drain.",
        "confidence": 0.9,
        "business_logic_score": 3,
        "business_logic_notes": "Fix auth.",
    }
    j = parse_legacy_semantic_response(legacy)
    assert j.verdict == SemanticVerdict.FINDING
    assert j.finding is not None
    assert j.finding.attacker_gain is True
    assert j.finding.value_impact == ValueImpact.HIGH


def test_legacy_assumption_maps_external_funding():
    legacy = {
        "category": "ASSUMPTION",
        "exploit_severity": "n/a",
        "explanation": "Needs external funding.",
        "confidence": 0.87,
        "business_logic_score": 6,
        "business_logic_notes": "Document funding.",
    }
    j = parse_legacy_semantic_response(legacy)
    assert j.finding is not None
    assert j.finding.trust_assumption == TrustAssumption.EXTERNAL_FUNDING
    assert j.finding.attacker_gain is False
