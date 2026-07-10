"""
Constraint Graph — single source of truth for specification interaction (v2).

Evolved from ExecutionPlan + UTXOArchitecture. Distinct from covenant StateObject
(blockchain storage); lifecycle uses LifecycleState category nodes.
"""

from __future__ import annotations

import uuid
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

from pydantic import BaseModel, Field

from src.models import (
    CapabilityInstance,
    ContractSpecification,
    ExecutionPlan,
    GenerationModule,
    SpecStatus,
    UTXOArchitecture,
)


class NodeCategory(str, Enum):
    ACTOR = "Actor"
    ASSET = "Asset"
    AUTHORIZATION = "Authorization"
    TIME = "Time"
    VALUE_FLOW = "ValueFlow"
    CONSTRAINT = "Constraint"
    SECURITY_INVARIANT = "SecurityInvariant"
    RECOVERY = "Recovery"
    EXTERNAL_DEPENDENCY = "ExternalDependency"
    PHASE = "Phase"
    BRANCH = "Branch"
    POLICY = "Policy"
    LIFECYCLE_STATE = "LifecycleState"


class EdgeKind(str, Enum):
    AUTHORIZES = "authorizes"
    GATES = "gates"
    DISTRIBUTES = "distributes"
    CONTINUES = "continues"
    SELECTS = "selects"
    INVARIANT_APPLIES = "invariant_applies"
    ENTERS = "enters"
    EXITS = "exits"
    GUARDED_BY = "guarded_by"
    FLOWS_TO = "flows_to"


class ConfidenceLevel(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"


class LifecycleStateName(str, Enum):
    DRAFT = "Draft"
    FUNDED = "Funded"
    LOCKED = "Locked"
    CLAIMABLE = "Claimable"
    CLAIMED = "Claimed"
    RECOVERED = "Recovered"
    CLOSED = "Closed"


class Provenance(BaseModel):
    source: str = "extractor"  # extractor | user | projection | mapper
    source_span: Optional[str] = None
    rationale: str = ""


class FieldConfidence(BaseModel):
    node_id: str
    field_path: str = ""
    confidence: ConfidenceLevel = ConfidenceLevel.UNKNOWN
    provenance: Provenance = Field(default_factory=Provenance)


class GraphNode(BaseModel):
    id: str
    category: NodeCategory
    label: str = ""
    kind: str = ""  # e.g. Predicate, Preimage, Decay, Linear
    variant: str = ""
    params: Dict[str, Any] = Field(default_factory=dict)
    pattern_tags: List[str] = Field(default_factory=list)
    confidence: ConfidenceLevel = ConfidenceLevel.UNKNOWN
    provenance: Provenance = Field(default_factory=Provenance)

    @staticmethod
    def new_id(prefix: str = "n") -> str:
        return f"{prefix}_{uuid.uuid4().hex[:8]}"


class GraphEdge(BaseModel):
    id: str = Field(default_factory=lambda: f"e_{uuid.uuid4().hex[:8]}")
    source_id: str
    target_id: str
    kind: EdgeKind
    params: Dict[str, Any] = Field(default_factory=dict)  # share, amount_sat, etc.


class ConstraintGraph(BaseModel):
    """Authoritative specification artifact after extraction."""

    version: int = 1
    intent: str = ""
    nodes: List[GraphNode] = Field(default_factory=list)
    edges: List[GraphEdge] = Field(default_factory=list)
    field_confidences: List[FieldConfidence] = Field(default_factory=list)
    status: SpecStatus = SpecStatus.DRAFT

    def node_by_id(self, node_id: str) -> Optional[GraphNode]:
        for n in self.nodes:
            if n.id == node_id:
                return n
        return None

    def nodes_by_category(self, category: NodeCategory) -> List[GraphNode]:
        return [n for n in self.nodes if n.category == category]

    def add_node(self, node: GraphNode) -> GraphNode:
        self.nodes.append(node)
        return node

    def add_edge(self, source_id: str, target_id: str, kind: EdgeKind, **params: Any) -> GraphEdge:
        edge = GraphEdge(source_id=source_id, target_id=target_id, kind=kind, params=params)
        self.edges.append(edge)
        return edge

    def set_confidence(self, node_id: str, level: ConfidenceLevel, field_path: str = "") -> None:
        for fc in self.field_confidences:
            if fc.node_id == node_id and fc.field_path == field_path:
                fc.confidence = level
                return
        self.field_confidences.append(
            FieldConfidence(node_id=node_id, field_path=field_path, confidence=level)
        )

    def low_confidence_nodes(self) -> List[GraphNode]:
        low_ids = {
            fc.node_id
            for fc in self.field_confidences
            if fc.confidence in (ConfidenceLevel.LOW, ConfidenceLevel.UNKNOWN)
        }
        return [n for n in self.nodes if n.id in low_ids or n.confidence in (
            ConfidenceLevel.LOW, ConfidenceLevel.UNKNOWN
        )]

    # ─── Projection: graph → ContractSpecification (one-way summary) ───

    def to_specification(self) -> ContractSpecification:
        """Project graph to legacy ContractSpecification for API compat."""
        caps: List[CapabilityInstance] = []
        params: Dict[str, Any] = {}
        seen_caps: set[str] = set()

        for node in self.nodes:
            if node.category == NodeCategory.AUTHORIZATION:
                if node.kind == "Threshold" or "threshold" in node.params:
                    if "multisig" not in seen_caps:
                        caps.append(CapabilityInstance(name="multisig"))
                        seen_caps.add("multisig")
                    params.setdefault("signers", node.params.get("signers", []))
                    params.setdefault("threshold", node.params.get("threshold"))
                if node.kind == "Weighted" or "weights" in node.params:
                    if "weighted_multisig" not in seen_caps:
                        caps.append(CapabilityInstance(name="weighted_multisig"))
                        seen_caps.add("weighted_multisig")
                    params.setdefault("holders", node.params.get("holders"))
                    params.setdefault("weights", node.params.get("weights"))
            elif node.category == NodeCategory.POLICY:
                kind = (node.kind or "").lower()
                if kind == "decay":
                    if "linear_decay" not in seen_caps:
                        caps.append(CapabilityInstance(name="linear_decay"))
                        seen_caps.add("linear_decay")
                    params.update({k: v for k, v in node.params.items() if k in (
                        "initial_threshold", "final_threshold", "duration_days", "lifecycle_mode"
                    )})
                elif kind == "distribution":
                    if "split" not in seen_caps:
                        caps.append(CapabilityInstance(name="split"))
                        seen_caps.add("split")
                    params.setdefault("recipients", node.params.get("recipients", []))
                    params.setdefault("shares", node.params.get("shares", []))
                elif kind == "recovery":
                    if "vault" not in seen_caps:
                        caps.append(CapabilityInstance(name="vault"))
                        seen_caps.add("vault")
            elif node.category == NodeCategory.TIME:
                if node.params.get("timeout_days"):
                    if "escrow" not in seen_caps:
                        caps.append(CapabilityInstance(name="escrow"))
                        seen_caps.add("escrow")
                    params["timeout_days"] = node.params["timeout_days"]
            elif node.category == NodeCategory.ASSET:
                if node.params.get("asset_type"):
                    params["asset_type"] = node.params["asset_type"]
                if node.params.get("token_category"):
                    params["token_category"] = node.params["token_category"]

        for edge in self.edges:
            if edge.kind == EdgeKind.DISTRIBUTES:
                if edge.params.get("share") is not None:
                    shares = params.setdefault("shares", [])
                    if isinstance(shares, list):
                        share = edge.params["share"]
                        if share not in shares:
                            shares.append(share)

        return ContractSpecification(
            intent=self.intent,
            capabilities=caps,
            parameters=params,
            status=self.status,
        )

    def _collect_pattern_tags(self) -> List[str]:
        tags: List[str] = []
        for node in self.nodes:
            tags.extend(node.pattern_tags)
        return tags

    # ─── Bridge: ContractSpecification → graph ───

    @classmethod
    def from_specification(cls, spec: ContractSpecification) -> ConstraintGraph:
        """Build graph from legacy spec (lossy but deterministic)."""
        graph = cls(intent=spec.intent, status=spec.status)
        cap_names = {c.name for c in spec.capabilities}
        params = dict(spec.parameters)

        phase = graph.add_node(GraphNode(
            id=GraphNode.new_id("phase"),
            category=NodeCategory.PHASE,
            label="main",
            kind="Main",
            pattern_tags=sorted(cap_names),
            confidence=ConfidenceLevel.HIGH if cap_names else ConfidenceLevel.LOW,
            provenance=Provenance(source="projection"),
        ))

        if not cap_names:
            return graph

        for state_name in (
            LifecycleStateName.DRAFT,
            LifecycleStateName.FUNDED,
            LifecycleStateName.LOCKED,
        ):
            if "escrow" in cap_names or "vault" in cap_names:
                ls = graph.add_node(GraphNode(
                    id=GraphNode.new_id("ls"),
                    category=NodeCategory.LIFECYCLE_STATE,
                    label=state_name.value,
                    kind=state_name.value,
                    confidence=ConfidenceLevel.MEDIUM,
                    provenance=Provenance(source="projection"),
                ))
                graph.add_edge(phase.id, ls.id, EdgeKind.ENTERS)

        asset_type = params.get("asset_type")
        if asset_type:
            asset = graph.add_node(GraphNode(
                id=GraphNode.new_id("asset"),
                category=NodeCategory.ASSET,
                label=str(asset_type),
                params={"asset_type": asset_type},
                confidence=ConfidenceLevel.HIGH,
                provenance=Provenance(source="projection"),
            ))
            graph.add_edge(phase.id, asset.id, EdgeKind.GUARDED_BY)

        if "multisig" in cap_names or "escrow" in cap_names:
            auth = graph.add_node(GraphNode(
                id=GraphNode.new_id("auth"),
                category=NodeCategory.AUTHORIZATION,
                label="multisig",
                kind="Threshold",
                params={
                    "signers": params.get("signers", []),
                    "threshold": params.get("threshold"),
                },
                pattern_tags=["multisig"],
                confidence=ConfidenceLevel.HIGH if params.get("signers") else ConfidenceLevel.LOW,
                provenance=Provenance(source="projection"),
            ))
            graph.add_edge(auth.id, phase.id, EdgeKind.AUTHORIZES)

        if "weighted_multisig" in cap_names or "treasury" in cap_names:
            auth = graph.add_node(GraphNode(
                id=GraphNode.new_id("auth"),
                category=NodeCategory.AUTHORIZATION,
                label="weighted_multisig",
                kind="Weighted",
                params={
                    "holders": params.get("holders"),
                    "weights": params.get("weights"),
                },
                pattern_tags=["weighted_multisig", "treasury"],
                confidence=ConfidenceLevel.HIGH if params.get("holders") else ConfidenceLevel.LOW,
                provenance=Provenance(source="projection"),
            ))
            graph.add_edge(auth.id, phase.id, EdgeKind.AUTHORIZES)

        if "linear_decay" in cap_names:
            policy = graph.add_node(GraphNode(
                id=GraphNode.new_id("policy"),
                category=NodeCategory.POLICY,
                label="vesting_decay",
                kind="Decay",
                variant="Linear",
                params={
                    "initial_threshold": params.get("initial_threshold"),
                    "final_threshold": params.get("final_threshold"),
                    "duration_days": params.get("duration_days"),
                    "lifecycle_mode": params.get("lifecycle_mode", "vesting"),
                },
                pattern_tags=["linear_decay", "timelock"],
                confidence=ConfidenceLevel.MEDIUM,
                provenance=Provenance(source="projection"),
            ))
            graph.add_edge(policy.id, phase.id, EdgeKind.GATES)

        if "split" in cap_names:
            recipients = params.get("recipients", [])
            shares = params.get("shares", [])
            policy = graph.add_node(GraphNode(
                id=GraphNode.new_id("policy"),
                category=NodeCategory.POLICY,
                label="distribution",
                kind="Distribution",
                variant="WeightedSplit" if shares else "EqualSplit",
                params={"recipients": recipients, "shares": shares},
                pattern_tags=["split"],
                confidence=ConfidenceLevel.MEDIUM,
                provenance=Provenance(source="projection"),
            ))
            for i, recipient in enumerate(recipients if isinstance(recipients, list) else []):
                actor = graph.add_node(GraphNode(
                    id=GraphNode.new_id("actor"),
                    category=NodeCategory.ACTOR,
                    label=str(recipient),
                    params={"role": "recipient"},
                    confidence=ConfidenceLevel.MEDIUM,
                    provenance=Provenance(source="projection"),
                ))
                share = shares[i] if isinstance(shares, list) and i < len(shares) else None
                graph.add_edge(policy.id, actor.id, EdgeKind.DISTRIBUTES, share=share)

        if params.get("timeout_days"):
            time_node = graph.add_node(GraphNode(
                id=GraphNode.new_id("time"),
                category=NodeCategory.TIME,
                label="refund_timeout",
                params={"timeout_days": params["timeout_days"]},
                pattern_tags=["escrow", "timelock"],
                confidence=ConfidenceLevel.MEDIUM,
                provenance=Provenance(source="projection"),
            ))
            refund_branch = graph.add_node(GraphNode(
                id=GraphNode.new_id("branch"),
                category=NodeCategory.BRANCH,
                label="refund",
                kind="Refund",
                pattern_tags=["refundable"],
                confidence=ConfidenceLevel.MEDIUM,
                provenance=Provenance(source="projection"),
            ))
            graph.add_edge(time_node.id, refund_branch.id, EdgeKind.GATES)

        if "hashlock" in cap_names or params.get("hash_preimage"):
            constraint = graph.add_node(GraphNode(
                id=GraphNode.new_id("constraint"),
                category=NodeCategory.CONSTRAINT,
                label="hashlock",
                kind="Preimage",
                params={"hash_preimage": params.get("hash_preimage")},
                pattern_tags=["hashlock"],
                confidence=ConfidenceLevel.LOW,
                provenance=Provenance(source="projection"),
            ))
            claim_branch = graph.add_node(GraphNode(
                id=GraphNode.new_id("branch"),
                category=NodeCategory.BRANCH,
                label="claim",
                kind="Claim",
                pattern_tags=["hashlock"],
                confidence=ConfidenceLevel.MEDIUM,
                provenance=Provenance(source="projection"),
            ))
            graph.add_edge(constraint.id, claim_branch.id, EdgeKind.GUARDED_BY)

        inv = graph.add_node(GraphNode(
            id=GraphNode.new_id("inv"),
            category=NodeCategory.SECURITY_INVARIANT,
            label="value_preservation",
            kind="Conservation",
            params={"rule": "outputs_sum_lte_inputs"},
            confidence=ConfidenceLevel.HIGH,
            provenance=Provenance(source="projection"),
        ))
        graph.add_edge(inv.id, phase.id, EdgeKind.INVARIANT_APPLIES)

        return graph

    # ─── Bridge: ExecutionPlan + UTXO → graph ───

    @classmethod
    def from_execution_plan(
        cls,
        plan: ExecutionPlan,
        utxo: Optional[UTXOArchitecture] = None,
        intent: str = "",
    ) -> ConstraintGraph:
        spec = ContractSpecification(
            intent=intent,
            capabilities=[
                CapabilityInstance(name=m.capability) for m in plan.modules
            ],
            parameters=dict(plan.shared_parameters),
        )
        graph = cls.from_specification(spec)
        graph.intent = intent or graph.intent

        if utxo:
            for tx in utxo.transactions:
                tx_node = graph.add_node(GraphNode(
                    id=GraphNode.new_id("tx"),
                    category=NodeCategory.PHASE,
                    label=tx.name,
                    kind="Transaction",
                    params={"inputs": tx.inputs, "outputs": tx.outputs},
                    confidence=ConfidenceLevel.HIGH,
                    provenance=Provenance(source="mapper", rationale="from UTXOArchitecture"),
                ))
                main_phases = graph.nodes_by_category(NodeCategory.PHASE)
                if main_phases:
                    graph.add_edge(main_phases[0].id, tx_node.id, EdgeKind.CONTINUES)

        return graph

    def to_execution_plan(self) -> Tuple[ExecutionPlan, UTXOArchitecture]:
        """Derive ExecutionPlan from graph topology (lossy)."""
        from src.services.spec.graph_planner import GraphModulePlanner

        spec = self.to_specification()
        modules, _ = GraphModulePlanner.select_modules(self)
        if not modules:
            modules, _ = __import__(
                "src.services.spec.planner", fromlist=["ModulePlanner"]
            ).ModulePlanner.select_modules(spec)

        plan = ExecutionPlan(
            modules=modules,
            order=[m.name for m in modules],
            dependencies={m.name: list(m.depends_on) for m in modules},
            shared_parameters=dict(spec.parameters),
        )

        contracts = [c.model_dump() for c in []]
        from src.models import ContractNode, TransactionSpec, StateObject

        tx_nodes = [n for n in self.nodes if n.category == NodeCategory.PHASE and n.kind == "Transaction"]
        transactions = [
            TransactionSpec(
                name=n.label,
                inputs=list(n.params.get("inputs", [])),
                outputs=list(n.params.get("outputs", [])),
            )
            for n in tx_nodes
        ]
        if not transactions:
            transactions = [TransactionSpec(name="fund", inputs=["deposit"], outputs=["vault"])]

        utxo = UTXOArchitecture(
            contracts=[ContractNode(id="main", type="covenant")],
            transactions=transactions,
            state_objects=[StateObject(name="commitment", storage="output")],
        )
        _ = contracts  # reserved for future cross-contract refs
        return plan, utxo

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> ConstraintGraph:
        return cls.model_validate(data)
