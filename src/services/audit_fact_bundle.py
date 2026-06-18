"""
AuditFactBundle v1 — canonical fact assembly for Semantic Security Judge V2.

Pure data assembly; no LLM or policy logic.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from src.models import AuditFactBundle, AuditIssue, ExistingFindingEntry, IntentModel
from src.services.intent_invariants import (
    InvariantMatrix,
    _is_split_intent,
    _requires_fixed_amounts,
    _requires_recipient_binding,
    _intent_text,
)
from src.services.semantic_capabilities import SemanticCapabilities

BUNDLE_VERSION = "1.0"


def _json_safe(value: Any) -> Any:
    """Recursively convert sets and other non-JSON types for bundle prompts."""
    if isinstance(value, set):
        return sorted(value)
    if isinstance(value, dict):
        return {str(k): _json_safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_safe(v) for v in value]
    return value


def _derived_intent_patterns(intent: str, intent_model: Optional[IntentModel]) -> List[str]:
    text = _intent_text(intent, intent_model)
    patterns: List[str] = []
    if _is_split_intent(text, intent_model):
        patterns.append("split_payment")
    if _requires_fixed_amounts(text):
        patterns.append("fixed_amount")
    if _requires_recipient_binding(text):
        patterns.append("recipient_binding")
    if intent_model and intent_model.contract_type:
        patterns.append(intent_model.contract_type)
    return patterns


def _invariant_matrix_entries(matrix: InvariantMatrix) -> List[Dict[str, Any]]:
    entries: List[Dict[str, Any]] = []
    for item in matrix.all_entries():
        entries.append(
            {
                "invariant_id": item.invariant_id,
                "label": item.label,
                "status": item.status,
                "tier": item.tier.value,
                "detail": item.detail,
                "fact_id": item.fact_id,
            }
        )
    return entries


def _capabilities_section(sem_caps: SemanticCapabilities) -> Dict[str, Any]:
    trace = sem_caps.to_trace_dict()
    evidence: List[Dict[str, Any]] = []
    for e in sem_caps.evidence:
        evidence.append(
            {
                "fact_id": f"cap.{e.key}",
                "key": e.key,
                "value": e.value,
                "tier": e.tier,
                "source": e.source,
                "anchors": e.anchors,
            }
        )
    return {
        "by_tier": trace.get("by_tier", {}),
        "evidence": evidence,
    }


def _authorization_section(
    sem_caps: SemanticCapabilities,
    intent_model: Optional[IntentModel],
) -> Dict[str, Any]:
    auth = sem_caps.authorization
    threshold = intent_model.threshold if intent_model else None
    signers = list(intent_model.signers) if intent_model and intent_model.signers else []
    return {
        "has_checksig": bool(auth.get("has_signature_auth")),
        "has_multisig": bool(auth.get("has_multisig_auth")),
        "multisig_threshold": threshold,
        "signer_count": len(signers) if signers else None,
        "timelock_evidence": bool(sem_caps.lifecycle.get("reanchors_covenant")),
        "covenant_continuation": bool(sem_caps.lifecycle.get("capability_retained")),
    }


def _existing_findings(issues: List[AuditIssue]) -> List[ExistingFindingEntry]:
    out: List[ExistingFindingEntry] = []
    for issue in issues:
        prefix = "det."
        if issue.rule_id.startswith("intent_"):
            prefix = "intent."
        elif issue.rule_id.startswith("semantic_"):
            prefix = "semantic."
        finding_id = f"{prefix}{issue.rule_id}"
        out.append(
            ExistingFindingEntry(
                finding_id=finding_id,
                rule_id=issue.rule_id,
                provenance=issue.provenance.value,
                kind=issue.kind.value,
                severity=issue.severity.value,
                summary=issue.title,
                line=issue.line,
            )
        )
    return out


def build_audit_fact_bundle(
    *,
    code: str,
    intent: str,
    intent_model: Optional[IntentModel],
    invariant_matrix: InvariantMatrix,
    sem_caps: SemanticCapabilities,
    engine_invariants: Dict[str, Any],
    existing_issues: List[AuditIssue],
    effective_mode: str,
) -> AuditFactBundle:
    intent_payload: Dict[str, Any] = {
        "raw_text": intent or "",
        "derived_patterns": _derived_intent_patterns(intent, intent_model),
    }
    if intent_model is not None:
        intent_payload["intent_model"] = intent_model.model_dump()

    value_flow: Dict[str, Any] = {}
    if engine_invariants:
        value_flow = _json_safe(
            {
                "value_flow": engine_invariants.get("value_flow", {}),
                "output_constraints": engine_invariants.get("output_constraints", {}),
                "coupling": engine_invariants.get("coupling", {}),
            }
        )

    findings = _existing_findings(existing_issues)

    return AuditFactBundle(
        bundle_version=BUNDLE_VERSION,
        contract={"contract_mode": effective_mode or "generic"},
        intent=intent_payload,
        invariant_matrix={"entries": _invariant_matrix_entries(invariant_matrix)},
        capabilities=_capabilities_section(sem_caps),
        value_flow=value_flow,
        authorization=_authorization_section(sem_caps, intent_model),
        existing_findings=findings,
        coverage={
            "deterministic_finding_count": len(findings),
            "invariant_entry_count": len(invariant_matrix.all_entries()),
        },
        judge_instructions={
            "do_not_duplicate_prefixes": ["det.", "intent.", "semantic_"],
            "scope": "delta_only",
        },
    )


def bundle_to_prompt_json(bundle: AuditFactBundle) -> str:
    return json.dumps(bundle.model_dump(), indent=2)


def bundle_to_prompt_section(bundle: AuditFactBundle) -> str:
    return f"AUDIT_FACT_BUNDLE (authoritative):\n{bundle_to_prompt_json(bundle)}"
