"""LLM Specification Extractor — emits ConstraintGraph + confidence."""

from __future__ import annotations

import json
import logging
import re
from typing import Any, Dict, Optional

from src.services.llm.factory import LLMFactory
from src.services.spec.constraint_graph import (
    ConfidenceLevel,
    ConstraintGraph,
    GraphNode,
    NodeCategory,
    Provenance,
)
from src.services.spec.discovery import lacks_contract_signal

logger = logging.getLogger("nexops.spec.graph_extractor")

_SPEC_EXTRACT_SYSTEM = """You are a Bitcoin Cash smart contract specification architect.
Extract a constraint graph from the user's natural language request.

Return ONLY valid JSON with this shape:
{
  "intent": "one-line summary",
  "nodes": [
    {"category": "Phase|Actor|Asset|Authorization|Time|Policy|Branch|Constraint|LifecycleState|SecurityInvariant",
     "label": "human label",
     "kind": "Threshold|Weighted|Decay|Distribution|Preimage|Predicate|Refund|Claim|...",
     "variant": "Linear|EqualSplit|...",
     "params": {},
     "pattern_tags": ["vault", "multisig", ...],
     "confidence": "high|medium|low"}
  ],
  "edges": [
    {"source_index": 0, "target_index": 1, "kind": "authorizes|gates|distributes|guarded_by|enters|invariant_applies", "params": {}}
  ]
}

Use LifecycleState for contract FSM states (Draft, Funded, Locked, Claimable).
Use Policy with kind Decay/Distribution/Recovery for vesting and splits.
Do not invent signers unless clearly stated; mark confidence low when uncertain.
If the message is a greeting, small talk, or has no contract intent, return empty nodes and edges arrays.
"""


def _parse_json_block(text: str) -> Optional[Dict[str, Any]]:
    text = text.strip()
    fence = re.search(r"```(?:json)?\s*([\s\S]*?)```", text)
    if fence:
        text = fence.group(1).strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        start = text.find("{")
        end = text.rfind("}")
        if start >= 0 and end > start:
            try:
                return json.loads(text[start : end + 1])
            except json.JSONDecodeError:
                return None
    return None


def _heuristic_graph(intent: str) -> ConstraintGraph:
    """Deterministic fallback when LLM unavailable."""
    if lacks_contract_signal(intent):
        return ConstraintGraph(intent=intent)

    from src.models import RawIntent
    from src.services.spec.detection import detect_capabilities, is_cliff_vesting_vault
    from src.services.spec.parameter_extraction import extract_parameters_from_message

    il = intent.lower()
    caps: list[str] = []
    if is_cliff_vesting_vault(il):
        caps.extend(["vault", "timelock", "split"])
    elif "escrow" in il:
        caps.extend(["escrow", "multisig"])
    if "vault" in il or "treasury" in il:
        if not is_cliff_vesting_vault(il):
            caps.extend(["vault", "treasury"])
    if not is_cliff_vesting_vault(il) and ("vest" in il or "decay" in il):
        caps.append("linear_decay")
    if "split" in il or "distribute" in il or is_cliff_vesting_vault(il):
        caps.append("split")
    if "multisig" in il and "escrow" in il:
        caps.append("multisig")
    raw = RawIntent(intent=intent, capabilities=list(dict.fromkeys(caps)), constraints={})
    spec = detect_capabilities(raw, original_intent=intent)
    params = extract_parameters_from_message(intent, spec)
    if params:
        spec.parameters.update(params)
    return ConstraintGraph.from_specification(spec)


class GraphExtractor:
    @staticmethod
    async def extract(
        intent: str,
        *,
        api_key: Optional[str] = None,
        provider: Optional[str] = None,
        openrouter_key: Optional[str] = None,
        user_message: Optional[str] = None,
    ) -> ConstraintGraph:
        if user_message and intent and user_message.strip() != intent.strip():
            prompt = f"Original request:\n{intent}\n\nLatest clarification:\n{user_message}"
        else:
            prompt = user_message or intent
        if lacks_contract_signal(prompt) and lacks_contract_signal(intent):
            return ConstraintGraph(intent=intent or prompt)

        try:
            llm = LLMFactory.get_provider(
                task_type="spec_extract",
                api_key=api_key,
                provider_type=provider,
                openrouter_key=openrouter_key,
            )
            raw = await llm.complete(
                f"{_SPEC_EXTRACT_SYSTEM}\n\nUser request:\n{prompt}",
            )
            data = _parse_json_block(raw)
            if data:
                return GraphExtractor._graph_from_llm(intent, data)
        except Exception as exc:
            logger.warning("spec_extract LLM failed, using heuristic: %s", exc)

        return _heuristic_graph(intent)

    @staticmethod
    def _graph_from_llm(intent: str, data: Dict[str, Any]) -> ConstraintGraph:
        graph = ConstraintGraph(intent=data.get("intent") or intent)
        index_to_id: Dict[int, str] = {}

        for i, raw_node in enumerate(data.get("nodes") or []):
            cat_str = str(raw_node.get("category", "Phase"))
            try:
                category = NodeCategory(cat_str)
            except ValueError:
                category = NodeCategory.PHASE
            conf_str = str(raw_node.get("confidence", "medium")).lower()
            conf = ConfidenceLevel.MEDIUM
            if conf_str in ("high", "medium", "low", "unknown"):
                conf = ConfidenceLevel(conf_str)
            node = GraphNode(
                id=GraphNode.new_id("n"),
                category=category,
                label=str(raw_node.get("label", "")),
                kind=str(raw_node.get("kind", "")),
                variant=str(raw_node.get("variant", "")),
                params=dict(raw_node.get("params") or {}),
                pattern_tags=list(raw_node.get("pattern_tags") or []),
                confidence=conf,
                provenance=Provenance(source="extractor", rationale="LLM spec_extract"),
            )
            graph.add_node(node)
            index_to_id[i] = node.id
            graph.set_confidence(node.id, conf)

        from src.services.spec.constraint_graph import EdgeKind

        for raw_edge in data.get("edges") or []:
            src_i = int(raw_edge.get("source_index", 0))
            tgt_i = int(raw_edge.get("target_index", 0))
            kind_str = str(raw_edge.get("kind", "guarded_by"))
            try:
                kind = EdgeKind(kind_str)
            except ValueError:
                kind = EdgeKind.GUARDED_BY
            src_id = index_to_id.get(src_i)
            tgt_id = index_to_id.get(tgt_i)
            if src_id and tgt_id:
                graph.add_edge(src_id, tgt_id, kind, **dict(raw_edge.get("params") or {}))

        if not graph.nodes:
            return _heuristic_graph(intent)
        return graph
