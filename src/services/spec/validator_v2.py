"""Validator v2 — graph-native issue detection."""

from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

from src.services.spec.constraint_graph import (
    ConfidenceLevel,
    ConstraintGraph,
    GraphNode,
    NodeCategory,
    Provenance,
)
from src.services.spec.graph_pattern_detection import GraphPatternDetection


class IssueSeverity(str, Enum):
    ERROR = "error"
    WARNING = "warning"
    INFO = "info"


class IssueClass(str, Enum):
    MISSING = "missing"
    AMBIGUOUS = "ambiguous"
    CONTRADICTORY = "contradictory"
    UNSUPPORTED = "unsupported"
    DANGEROUS = "dangerous"


class GraphValidationIssue(BaseModel):
    issue_class: IssueClass
    severity: IssueSeverity = IssueSeverity.ERROR
    node_id: Optional[str] = None
    message: str
    field_path: str = ""


class GraphValidationResult(BaseModel):
    issues: List[GraphValidationIssue] = Field(default_factory=list)
    is_complete: bool = False
    low_confidence_node_ids: List[str] = Field(default_factory=list)

    @property
    def blocking_issues(self) -> List[GraphValidationIssue]:
        return [i for i in self.issues if i.severity == IssueSeverity.ERROR]


class ValidatorV2:
    """Validate ConstraintGraph structure and completeness."""

    @classmethod
    def validate(cls, graph: ConstraintGraph) -> GraphValidationResult:
        issues: List[GraphValidationIssue] = []
        patterns = set(GraphPatternDetection.detect_patterns(graph))
        meaningful_nodes = [
            n for n in graph.nodes
            if n.category in (
                NodeCategory.AUTHORIZATION,
                NodeCategory.POLICY,
                NodeCategory.BRANCH,
                NodeCategory.CONSTRAINT,
                NodeCategory.LIFECYCLE_STATE,
            )
        ]

        if not patterns and not meaningful_nodes:
            issues.append(GraphValidationIssue(
                issue_class=IssueClass.MISSING,
                message="No contract pattern identified yet",
                field_path="contract_type",
            ))

        if not graph.intent.strip():
            issues.append(GraphValidationIssue(
                issue_class=IssueClass.MISSING,
                message="Intent description is empty",
            ))

        auth_nodes = graph.nodes_by_category(NodeCategory.AUTHORIZATION)
        policy_nodes = graph.nodes_by_category(NodeCategory.POLICY)

        if any("multisig" in p or "escrow" in p for p in patterns):
            if not auth_nodes:
                issues.append(GraphValidationIssue(
                    issue_class=IssueClass.MISSING,
                    message="Multisig/escrow pattern requires Authorization node",
                ))
            else:
                for auth in auth_nodes:
                    if auth.kind == "Threshold":
                        signers = auth.params.get("signers", [])
                        threshold = auth.params.get("threshold")
                        if not signers:
                            issues.append(GraphValidationIssue(
                                issue_class=IssueClass.MISSING,
                                node_id=auth.id,
                                field_path="signers",
                                message="Signers not specified",
                            ))
                        if threshold is None:
                            issues.append(GraphValidationIssue(
                                issue_class=IssueClass.MISSING,
                                node_id=auth.id,
                                field_path="threshold",
                                message="Threshold not specified",
                            ))
                        elif isinstance(signers, list) and threshold > len(signers):
                            issues.append(GraphValidationIssue(
                                issue_class=IssueClass.CONTRADICTORY,
                                node_id=auth.id,
                                message="Threshold exceeds signer count",
                            ))

        if any("weighted_multisig" in p or "treasury" in p for p in patterns):
            for auth in auth_nodes:
                if auth.kind == "Weighted":
                    holders = auth.params.get("holders")
                    weights = auth.params.get("weights")
                    if holders is None:
                        issues.append(GraphValidationIssue(
                            issue_class=IssueClass.MISSING,
                            node_id=auth.id,
                            field_path="holders",
                            message="Holder count not specified",
                        ))
                    if not weights:
                        issues.append(GraphValidationIssue(
                            issue_class=IssueClass.MISSING,
                            node_id=auth.id,
                            field_path="weights",
                            message="Voting weights not specified",
                        ))

        if "linear_decay" in patterns:
            decay_policies = [p for p in policy_nodes if (p.kind or "").lower() == "decay"]
            if not decay_policies:
                issues.append(GraphValidationIssue(
                    issue_class=IssueClass.MISSING,
                    message="Linear decay pattern requires Policy:Decay node",
                ))
            for pol in decay_policies:
                for field in ("initial_threshold", "final_threshold", "duration_days"):
                    if pol.params.get(field) is None:
                        issues.append(GraphValidationIssue(
                            issue_class=IssueClass.MISSING,
                            node_id=pol.id,
                            field_path=field,
                            message=f"{field} not specified for vesting/decay",
                        ))

        if "split" in patterns:
            dist = [p for p in policy_nodes if (p.kind or "").lower() == "distribution"]
            if not dist:
                issues.append(GraphValidationIssue(
                    issue_class=IssueClass.MISSING,
                    message="Split pattern requires Policy:Distribution node",
                ))
            for pol in dist:
                recipients = pol.params.get("recipients", [])
                shares = pol.params.get("shares", [])
                if not recipients:
                    issues.append(GraphValidationIssue(
                        issue_class=IssueClass.MISSING,
                        node_id=pol.id,
                        field_path="recipients",
                        message="Recipients not specified",
                    ))
                if shares and isinstance(shares, list) and isinstance(recipients, list):
                    if len(shares) != len(recipients):
                        issues.append(GraphValidationIssue(
                            issue_class=IssueClass.CONTRADICTORY,
                            node_id=pol.id,
                            message="Share count does not match recipient count",
                        ))
                    if sum(shares) != 100:
                        issues.append(GraphValidationIssue(
                            issue_class=IssueClass.WARNING,
                            severity=IssueSeverity.WARNING,
                            node_id=pol.id,
                            message="Shares do not sum to 100",
                        ))

        low_ids: List[str] = []
        for node in graph.nodes:
            if node.confidence in (ConfidenceLevel.LOW, ConfidenceLevel.UNKNOWN):
                low_ids.append(node.id)
                issues.append(GraphValidationIssue(
                    issue_class=IssueClass.AMBIGUOUS,
                    severity=IssueSeverity.WARNING,
                    node_id=node.id,
                    message=f"Low confidence on {node.label or node.category.value}",
                ))

        blocking = [i for i in issues if i.severity == IssueSeverity.ERROR]
        return GraphValidationResult(
            issues=issues,
            is_complete=len(blocking) == 0 and not low_ids,
            low_confidence_node_ids=low_ids,
        )
