"""Module DAG planner derived from ConstraintGraph phase order and policies."""

from __future__ import annotations

from typing import Dict, List, Tuple

from src.models import GenerationModule
from src.services.spec.constraint_graph import ConstraintGraph, NodeCategory
from src.services.spec.graph_pattern_detection import GraphPatternDetection


def _dedupe_modules(modules: List[GenerationModule]) -> List[GenerationModule]:
    seen: set[str] = set()
    out: List[GenerationModule] = []
    for mod in modules:
        if mod.name in seen:
            continue
        seen.add(mod.name)
        out.append(mod)
    return out


class GraphModulePlanner:
    """Derive GenerationModule DAG from graph topology."""

    @staticmethod
    def select_modules(graph: ConstraintGraph) -> Tuple[List[GenerationModule], Dict[str, str]]:
        patterns = GraphPatternDetection.detect_patterns(graph)
        pattern_set = set(patterns)
        spec = graph.to_specification()
        params = dict(spec.parameters)
        decisions: Dict[str, str] = {}
        modules: List[GenerationModule] = []

        phases = sorted(
            graph.nodes_by_category(NodeCategory.PHASE),
            key=lambda n: n.params.get("order", 0),
        )
        _ = phases  # reserved for ordered multi-phase composition

        asset = str(params.get("asset_type", "BCH")).lower()
        intent_lower = graph.intent.lower()

        if pattern_set & {"treasury", "vault", "weighted_multisig"} or "treasury" in pattern_set:
            if asset in ("nft", "token") or "nft" in intent_lower:
                mod = GenerationModule(name="EscrowModule", capability="treasury", params={"variant": "escrow"})
                mod_name = "EscrowModule"
            else:
                mod = GenerationModule(name="VaultModule", capability="treasury", params={"variant": "vault"})
                mod_name = "VaultModule"
            decisions["treasury"] = mod_name
            modules.append(mod)

        if "weighted_multisig" in pattern_set:
            mod = GenerationModule(
                name="WeightedMultisigModule",
                capability="weighted_multisig",
                params={
                    "holders": params.get("holders"),
                    "weights": params.get("weights"),
                },
                depends_on=[modules[0].name] if modules else [],
            )
            decisions["weighted_multisig"] = "WeightedMultisigModule"
            modules.append(mod)
        elif "multisig" in pattern_set or "escrow" in pattern_set:
            mod = GenerationModule(
                name="MultisigModule",
                capability="multisig",
                params={
                    "signers": params.get("signers"),
                    "threshold": params.get("threshold"),
                },
                depends_on=[modules[0].name] if modules else [],
            )
            decisions["multisig"] = "MultisigModule"
            modules.append(mod)

        if "linear_decay" in pattern_set:
            lifecycle = str(params.get("lifecycle_mode", "")).lower()
            mod_name = "VestingScheduleModule" if lifecycle == "vesting" or "vest" in intent_lower else "LinearThresholdModule"
            mod = GenerationModule(
                name=mod_name,
                capability="linear_decay",
                params={
                    "initial_threshold": params.get("initial_threshold"),
                    "final_threshold": params.get("final_threshold"),
                    "duration_days": params.get("duration_days"),
                },
                depends_on=[modules[-1].name] if modules else [],
            )
            decisions["linear_decay"] = mod_name
            modules.append(mod)

        if "split" in pattern_set:
            mod = GenerationModule(
                name="SplitModule",
                capability="split",
                params={
                    "recipients": params.get("recipients"),
                    "shares": params.get("shares"),
                },
                depends_on=[modules[-1].name] if modules else [],
            )
            decisions["split"] = "SplitModule"
            modules.append(mod)

        if "hashlock" in pattern_set:
            mod = GenerationModule(
                name="HashlockModule",
                capability="hashlock",
                params={"hash_preimage": params.get("hash_preimage")},
                depends_on=[modules[-1].name] if modules else [],
            )
            decisions["hashlock"] = "HashlockModule"
            modules.append(mod)

        if "refundable" in pattern_set and not any(m.name == "RefundModule" for m in modules):
            mod = GenerationModule(
                name="RefundModule",
                capability="escrow",
                params={"timeout_days": params.get("timeout_days")},
                depends_on=[modules[-1].name] if modules else [],
            )
            decisions["refundable"] = "RefundModule"
            modules.append(mod)

        return _dedupe_modules(modules), decisions
