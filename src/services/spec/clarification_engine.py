"""Clarification engine — batch low-confidence graph nodes only."""

from __future__ import annotations

from typing import List, Optional

from pydantic import BaseModel, Field

from src.services.spec.constraint_graph import ConstraintGraph, GraphNode, NodeCategory
from src.services.spec.validator_v2 import GraphValidationResult, ValidatorV2


class ClarificationBatch(BaseModel):
    questions: List[str] = Field(default_factory=list)
    target_node_ids: List[str] = Field(default_factory=list)
    field_paths: List[str] = Field(default_factory=list)
    is_complete: bool = False


_QUESTION_TEMPLATES = {
    ("Authorization", "signers"): "Who are the authorized signers for this contract?",
    ("Authorization", "threshold"): "What multisig threshold is required (e.g. 2-of-3)?",
    ("Authorization", "holders"): "How many key holders should govern this treasury?",
    ("Authorization", "weights"): "What voting weights should each holder have?",
    ("Policy", "duration_days"): "What is the vesting or lock duration in days?",
    ("Policy", "initial_threshold"): "What is the initial approval threshold?",
    ("Policy", "final_threshold"): "What is the final approval threshold after vesting?",
    ("Policy", "recipients"): "Who should receive the split payouts?",
    ("Policy", "shares"): "What percentage should each recipient receive?",
    ("Time", "timeout_days"): "After how many days should a refund path unlock?",
    ("Constraint", "hash_preimage"): "What hash preimage condition should unlock funds?",
    ("Asset", "asset_type"): "What asset type is held (BCH, token, NFT)?",
}


class ClarificationEngine:
    @staticmethod
    def _question_for_node(node: GraphNode, field_path: str = "") -> Optional[str]:
        key = (node.category.value.replace("LifecycleState", "LifecycleState"), field_path)
        cat = node.category.value
        if field_path:
            tpl = _QUESTION_TEMPLATES.get((cat, field_path))
            if tpl:
                return tpl
        if node.category == NodeCategory.AUTHORIZATION:
            if not node.params.get("signers") and node.kind == "Threshold":
                return _QUESTION_TEMPLATES.get(("Authorization", "signers"))
            if node.params.get("threshold") is None and node.kind == "Threshold":
                return _QUESTION_TEMPLATES.get(("Authorization", "threshold"))
        if node.category == NodeCategory.POLICY and (node.kind or "").lower() == "decay":
            for f in ("duration_days", "initial_threshold", "final_threshold"):
                if node.params.get(f) is None:
                    return _QUESTION_TEMPLATES.get(("Policy", f))
        if node.category == NodeCategory.POLICY and (node.kind or "").lower() == "distribution":
            if not node.params.get("recipients"):
                return _QUESTION_TEMPLATES.get(("Policy", "recipients"))
        return f"Please clarify: {node.label or node.category.value}"

    @classmethod
    def build_batch(
        cls,
        graph: ConstraintGraph,
        validation: Optional[GraphValidationResult] = None,
        max_questions: int = 3,
    ) -> ClarificationBatch:
        validation = validation or ValidatorV2.validate(graph)
        if validation.is_complete:
            return ClarificationBatch(is_complete=True)

        questions: List[str] = []
        node_ids: List[str] = []
        field_paths: List[str] = []

        for issue in validation.blocking_issues:
            if issue.node_id and issue.node_id not in node_ids:
                node = graph.node_by_id(issue.node_id)
                if node:
                    q = cls._question_for_node(node, issue.field_path)
                    if q:
                        questions.append(q)
                        node_ids.append(issue.node_id)
                        field_paths.append(issue.field_path)
            if len(questions) >= max_questions:
                break

        if len(questions) < max_questions:
            for node_id in validation.low_confidence_node_ids:
                if node_id in node_ids:
                    continue
                node = graph.node_by_id(node_id)
                if not node:
                    continue
                q = cls._question_for_node(node)
                if q:
                    questions.append(q)
                    node_ids.append(node_id)
                    field_paths.append("")
                if len(questions) >= max_questions:
                    break

        return ClarificationBatch(
            questions=questions,
            target_node_ids=node_ids,
            field_paths=field_paths,
            is_complete=len(questions) == 0 and len(validation.blocking_issues) == 0,
        )
