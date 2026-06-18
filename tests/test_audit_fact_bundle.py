"""Tests for AuditFactBundle v1 assembly."""

from src.models import AuditIssue, FindingKind, Provenance, Severity
from src.services.audit_fact_bundle import build_audit_fact_bundle, bundle_to_prompt_json
from src.services.intent_invariants import InvariantMatrix, InvariantStatus, InvariantTier
from src.services.semantic_capabilities import SemanticCapabilities


def test_bundle_includes_core_sections():
    matrix = InvariantMatrix(
        enforced=[
            InvariantStatus(
                "auth_gate",
                "authorization gate",
                "ENFORCED",
                tier=InvariantTier.SECURITY,
            )
        ],
        missing=[
            InvariantStatus(
                "fixed_amount_per_recipient",
                "fixed amount per recipient",
                "MISSING",
                tier=InvariantTier.BUSINESS,
            )
        ],
    )
    caps = SemanticCapabilities(
        authorization={"has_signature_auth": True},
        evidence=[],
    )
    issues = [
        AuditIssue(
            title="Policy Gap: fixed amount",
            severity=Severity.MEDIUM,
            line=10,
            description="missing salary",
            recommendation="add require",
            rule_id="intent_fixed_amount_per_recipient",
            kind=FindingKind.INVARIANT_GAP,
            provenance=Provenance.DETERMINISTIC,
        )
    ]
    bundle = build_audit_fact_bundle(
        code="pragma cashscript ^0.13.0; contract T() { function f() { require(true); } }",
        intent="payroll with fixed salary",
        intent_model=None,
        invariant_matrix=matrix,
        sem_caps=caps,
        engine_invariants={},
        existing_issues=issues,
        effective_mode="split_payment",
    )
    assert bundle.bundle_version == "1.0"
    assert bundle.contract["contract_mode"] == "split_payment"
    assert "fingerprint" not in bundle_to_prompt_json(bundle).lower()
    assert len(bundle.invariant_matrix["entries"]) == 2
    assert bundle.existing_findings[0].rule_id == "intent_fixed_amount_per_recipient"
    assert bundle.existing_findings[0].finding_id.startswith("intent.")


def test_fact_id_stability():
    matrix = InvariantMatrix(
        enforced=[
            InvariantStatus("auth_gate", "authorization gate", "ENFORCED", tier=InvariantTier.SECURITY)
        ]
    )
    entry = matrix.enforced[0]
    assert entry.fact_id == "inv.auth_gate"
