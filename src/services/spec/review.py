"""Human-readable specification review and confirm/modify transitions."""

from __future__ import annotations

from typing import Any, Dict, Optional

from src.models import (
    ContractSpecification,
    ExecutionPlan,
    SpecStatus,
    SpecificationReview,
    UTXOArchitecture,
)
from src.services.spec.architecture import ArchitectureBuilder
from src.services.spec.constraint_graph import ConstraintGraph, NodeCategory
from src.services.spec.detection import is_founder_vesting_spec
from src.services.spec.graph_pattern_detection import GraphPatternDetection
from src.services.spec.graph_pipeline import build_planning_report
from src.services.spec.planner import ModulePlanner


def render_graph_specification(
    graph: ConstraintGraph,
    utxo_architecture: Optional[UTXOArchitecture] = None,
) -> SpecificationReview:
    """Render review sections from ConstraintGraph (SSOT)."""
    spec = graph.to_specification()
    sections: dict = {
        "Patterns": GraphPatternDetection.detect_patterns(graph),
        "Actors": [],
        "Lifecycle": [],
        "Policies": [],
        "Invariants": [],
        "Access Control": [],
        "Time Rules": [],
        "Assets": [],
        "Operations": [],
        "Security": [],
        "Core Pattern": [graph.intent or spec.intent or "Unnamed contract"],
    }

    for node in graph.nodes:
        if node.category == NodeCategory.ACTOR:
            sections["Actors"].append(node.label or str(node.params))
        elif node.category == NodeCategory.LIFECYCLE_STATE:
            sections["Lifecycle"].append(node.label or node.kind)
        elif node.category == NodeCategory.POLICY:
            sections["Policies"].append(
                f"{node.kind}/{node.variant}: {node.params}" if node.variant else f"{node.kind}: {node.params}"
            )
        elif node.category == NodeCategory.SECURITY_INVARIANT:
            sections["Invariants"].append(node.label or node.kind)
        elif node.category == NodeCategory.AUTHORIZATION:
            sections["Access Control"].append(f"{node.kind}: {node.params}")
        elif node.category == NodeCategory.TIME:
            sections["Time Rules"].append(f"{node.label}: {node.params}")
        elif node.category == NodeCategory.ASSET:
            sections["Assets"].append(f"{node.label}: {node.params}")
        elif node.category == NodeCategory.BRANCH:
            sections["Operations"].append(f"Branch {node.label} ({node.kind})")

    if utxo_architecture is None:
        _, utxo_architecture, _ = build_planning_report(graph)

    for tx in utxo_architecture.transactions:
        sections["Operations"].append(
            f"{tx.name}: [{', '.join(tx.inputs)}] -> [{', '.join(tx.outputs)}]"
        )

    return SpecificationReview(
        sections=sections,
        utxo_architecture=utxo_architecture,
        spec_snapshot=spec.model_copy(deep=True),
        constraint_graph=graph.model_dump(),
    )


def apply_graph_edits(graph: ConstraintGraph, edits: Dict[str, Any]) -> ConstraintGraph:
    """Apply review UI mutations to graph nodes."""
    node_edits = edits.get("nodes") or []
    for edit in node_edits:
        node_id = edit.get("id")
        node = graph.node_by_id(node_id) if node_id else None
        if not node:
            continue
        if "params" in edit and isinstance(edit["params"], dict):
            node.params.update(edit["params"])
        if "label" in edit:
            node.label = str(edit["label"])
        if "confidence" in edit:
            from src.services.spec.constraint_graph import ConfidenceLevel
            node.confidence = ConfidenceLevel(str(edit["confidence"]))
    if edits.get("intent"):
        graph.intent = str(edits["intent"])
    graph.version += 1
    return graph


def render_specification(
    spec: ContractSpecification,
    utxo_architecture: Optional[UTXOArchitecture] = None,
) -> SpecificationReview:
    sections: dict = {
        "Core Pattern": [spec.intent or "Unnamed contract"],
        "Access Control": [],
        "Time Rules": [],
        "Assets": [],
        "Operations": [],
        "Security": [],
    }

    for cap in spec.capabilities:
        if cap.name in ("weighted_multisig", "multisig", "escrow"):
            sections["Access Control"].append(cap.name.replace("_", " ").title())
        elif cap.name == "linear_decay" and not is_founder_vesting_spec(spec):
            sections["Time Rules"].append("Linear threshold change")
        elif cap.name in ("treasury", "vault", "withdrawal_policy", "auction"):
            if is_founder_vesting_spec(spec) and cap.name == "vault":
                sections["Core Pattern"].append("Founder vesting vault")
            else:
                sections["Assets"].append(cap.name.replace("_", " ").title())
        elif cap.name == "timelock" and is_founder_vesting_spec(spec):
            sections["Time Rules"].append("Cliff timelock / vesting schedule")
        elif cap.name == "split" and is_founder_vesting_spec(spec):
            sections["Operations"].append("Founder token split on release")

    if is_founder_vesting_spec(spec):
        if spec.parameters.get("timeout_days"):
            sections["Time Rules"].append(f"Cliff lock: {spec.parameters['timeout_days']} days")
        if spec.parameters.get("vesting_years"):
            sections["Time Rules"].append(f"Total vesting: {spec.parameters['vesting_years']} years")
        if spec.parameters.get("recipients"):
            sections["Operations"].append(f"Recipients: {spec.parameters['recipients']}")
        if spec.parameters.get("shares"):
            sections["Operations"].append(f"Split: {spec.parameters['shares']}")

    if spec.parameters.get("holders"):
        sections["Access Control"].append(f"Key holders: {spec.parameters['holders']}")
    if spec.parameters.get("weights"):
        sections["Access Control"].append(f"Voting weights: {spec.parameters['weights']}")
    if not is_founder_vesting_spec(spec) and spec.parameters.get("initial_threshold") is not None:
        sections["Time Rules"].append(f"Initial threshold: {spec.parameters['initial_threshold']}")
    if not is_founder_vesting_spec(spec) and spec.parameters.get("final_threshold") is not None:
        sections["Time Rules"].append(f"Final threshold: {spec.parameters['final_threshold']}")
    if not is_founder_vesting_spec(spec) and spec.parameters.get("duration_days"):
        sections["Time Rules"].append(f"Duration: {spec.parameters['duration_days']} days")
    if spec.parameters.get("asset_type"):
        sections["Assets"].append(f"Asset: {spec.parameters['asset_type']}")
    if spec.parameters.get("signers"):
        sections["Access Control"].append(f"Signers: {spec.parameters['signers']}")
    if spec.parameters.get("threshold"):
        sections["Access Control"].append(f"Threshold: {spec.parameters['threshold']}")
    if spec.parameters.get("timeout_days") and not is_founder_vesting_spec(spec):
        sections["Time Rules"].append(f"Refund timeout: {spec.parameters['timeout_days']} days")
    if spec.parameters.get("start_price") is not None:
        sections["Assets"].append(f"Start price: {spec.parameters['start_price']} satoshis")
    if spec.parameters.get("min_price") is not None:
        sections["Assets"].append(f"Floor price: {spec.parameters['min_price']} satoshis")

    sections["Security"].extend([
        "Authorization required on spend paths",
        "Value preservation on covenant continuation",
    ])

    if utxo_architecture is None:
        modules, _ = ModulePlanner.select_modules(spec)
        plan = ExecutionPlan(modules=modules, order=[m.name for m in modules])
        utxo_architecture = ArchitectureBuilder.build(plan, spec)

    for tx in utxo_architecture.transactions:
        sections["Operations"].append(
            f"{tx.name}: [{', '.join(tx.inputs)}] -> [{', '.join(tx.outputs)}]"
        )
    for state in utxo_architecture.state_objects:
        sections["Security"].append(f"State {state.name}: {state.storage}")

    return SpecificationReview(
        sections=sections,
        utxo_architecture=utxo_architecture,
        spec_snapshot=spec.model_copy(deep=True),
    )


def confirm_specification(spec: ContractSpecification) -> ContractSpecification:
    spec.status = SpecStatus.CONFIRMED
    return spec


def modify_specification(spec: ContractSpecification) -> ContractSpecification:
    spec.status = SpecStatus.NEEDS_INPUT
    return spec
