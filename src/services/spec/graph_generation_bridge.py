"""Phase 6 bridge — generation consumes Module DAG from ConstraintGraph."""

from __future__ import annotations

from typing import Optional, Tuple

from src.models import ContractSpecification, ExecutionPlan, PlanningReport, UTXOArchitecture
from src.services.spec.constraint_graph import ConstraintGraph
from src.services.spec.graph_pipeline import build_planning_report
from src.services.spec.phase2_adapter import resolve_effective_mode


class GraphGenerationBridge:
    """
    Resolves generation inputs from graph-native Module DAG.
    effective_mode remains a derived shim for golden/benchmark paths only.
    """

    @staticmethod
    def resolve_from_graph(
        graph: ConstraintGraph,
        *,
        benchmark_mode: bool = False,
    ) -> Tuple[ExecutionPlan, UTXOArchitecture, PlanningReport, ContractSpecification]:
        plan, utxo, report = build_planning_report(graph)
        spec = graph.to_specification()
        spec.intent = graph.intent

        if benchmark_mode:
            # Shim: single effective_mode label for legacy golden runners
            report.effective_mode = resolve_effective_mode(utxo, plan)

        return plan, utxo, report, spec

    @staticmethod
    def effective_mode_shim(
        graph: Optional[ConstraintGraph],
        plan: ExecutionPlan,
        utxo: UTXOArchitecture,
    ) -> str:
        """Derived label only — not the routing decision when graph is present."""
        if graph is not None:
            _, _, report = build_planning_report(graph)
            return report.effective_mode or resolve_effective_mode(utxo, plan)
        return resolve_effective_mode(utxo, plan)
