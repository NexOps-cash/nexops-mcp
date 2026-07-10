"""Confidence scoring for Constraint Graph nodes."""

from __future__ import annotations

from typing import List

from src.services.spec.constraint_graph import (
    ConfidenceLevel,
    ConstraintGraph,
    FieldConfidence,
    GraphNode,
    Provenance,
)


class ConfidenceEngine:
    """Assign and refresh per-node confidence from extraction provenance."""

    @staticmethod
    def score_node(node: GraphNode) -> ConfidenceLevel:
        if node.provenance.source == "user":
            return ConfidenceLevel.HIGH
        if node.confidence != ConfidenceLevel.UNKNOWN:
            return node.confidence
        params = node.params or {}
        filled = sum(1 for v in params.values() if v not in (None, "", []))
        total = max(len(params), 1)
        ratio = filled / total
        if ratio >= 0.8:
            return ConfidenceLevel.HIGH
        if ratio >= 0.4:
            return ConfidenceLevel.MEDIUM
        return ConfidenceLevel.LOW

    @classmethod
    def apply(cls, graph: ConstraintGraph) -> ConstraintGraph:
        for node in graph.nodes:
            level = cls.score_node(node)
            node.confidence = level
            graph.set_confidence(node.id, level)
        return graph

    @staticmethod
    def batch_low_confidence(graph: ConstraintGraph) -> List[FieldConfidence]:
        return [
            fc for fc in graph.field_confidences
            if fc.confidence in (ConfidenceLevel.LOW, ConfidenceLevel.UNKNOWN)
        ]

    @staticmethod
    def mark_user_confirmed(graph: ConstraintGraph, node_id: str) -> None:
        node = graph.node_by_id(node_id)
        if node:
            node.confidence = ConfidenceLevel.HIGH
            node.provenance = Provenance(source="user", rationale="confirmed in review")
        graph.set_confidence(node_id, ConfidenceLevel.HIGH)
