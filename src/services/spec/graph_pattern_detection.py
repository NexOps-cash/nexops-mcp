"""Graph-native pattern detection from topology and pattern_tags."""

from __future__ import annotations

from typing import List, Set

from src.services.spec.constraint_graph import ConstraintGraph, NodeCategory


# Topology → pattern tag inference (replaces keyword primary in interactive mode)
_TOPOLOGY_RULES: List[tuple] = [
    ({"Decay", "Linear"}, ["linear_decay", "timelock"]),
    ({"Distribution"}, ["split"]),
    ({"Preimage"}, ["hashlock"]),
    ({"Refund"}, ["refundable", "escrow"]),
    ({"Threshold"}, ["multisig"]),
    ({"Weighted"}, ["weighted_multisig", "treasury"]),
]


class GraphPatternDetection:
    @staticmethod
    def detect_patterns(graph: ConstraintGraph) -> List[str]:
        tags: Set[str] = set()
        for node in graph.nodes:
            tags.update(node.pattern_tags)
            if node.category == NodeCategory.POLICY:
                kind = (node.kind or "").lower()
                if kind == "decay":
                    tags.update(["linear_decay", "timelock", "vault"])
                elif kind == "distribution":
                    tags.add("split")
                elif kind == "recovery":
                    tags.update(["vault", "recovery"])
            elif node.category == NodeCategory.CONSTRAINT:
                if node.kind == "Preimage":
                    tags.add("hashlock")
                elif node.kind == "Predicate":
                    tags.add("conditional_spend")
            elif node.category == NodeCategory.BRANCH:
                if node.kind == "Refund":
                    tags.update(["refundable", "escrow"])
            elif node.category == NodeCategory.AUTHORIZATION:
                if node.kind == "Weighted":
                    tags.update(["weighted_multisig", "treasury"])
                elif node.kind == "Threshold":
                    tags.add("multisig")
            elif node.category == NodeCategory.LIFECYCLE_STATE:
                if node.pattern_tags:
                    tags.update(node.pattern_tags)

        for node in graph.nodes:
            for kinds, inferred in _TOPOLOGY_RULES:
                if node.kind in kinds or node.variant in kinds:
                    tags.update(inferred)

        if "linear_decay" in tags and "vault" in tags:
            tags.add("timelock")
        return sorted(tags)

    @staticmethod
    def apply_to_graph(graph: ConstraintGraph) -> ConstraintGraph:
        patterns = GraphPatternDetection.detect_patterns(graph)
        phases = graph.nodes_by_category(NodeCategory.PHASE)
        if phases:
            existing = set(phases[0].pattern_tags)
            phases[0].pattern_tags = sorted(existing | set(patterns))
        return graph
