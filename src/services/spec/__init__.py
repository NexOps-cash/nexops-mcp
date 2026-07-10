"""Specification-first generation pipeline (v2)."""

from .capabilities import CAPABILITY_REGISTRY, Capability, FieldSpec, get_capability
from .extraction import extract_intent, parse_extraction
from .detection import detect_capabilities
from .validator import SpecValidator
from .clarification import build_clarification_plan
from .planner import ModulePlanner
from .composer import Composer
from .architecture import ArchitectureBuilder
from .phase2_adapter import resolve_effective_mode
from .review import render_specification, confirm_specification, modify_specification
from .orchestrator import run_spec_pipeline, derive_intent_model, apply_legacy_fallback, merge_answers
from .support_assessment import assess_composition_support, assess_from_capabilities
from .assistant import SpecificationAssistant
from .constraint_graph import ConstraintGraph, GraphNode, NodeCategory
from .graph_config import use_spec_graph_v2
from .graph_pipeline import bootstrap_graph, should_use_graph_pipeline
from .graph_generation_bridge import GraphGenerationBridge
from .validator_v2 import ValidatorV2, GraphValidationResult
from .clarification_engine import ClarificationEngine, ClarificationBatch

__all__ = [
    "CAPABILITY_REGISTRY",
    "Capability",
    "FieldSpec",
    "get_capability",
    "extract_intent",
    "parse_extraction",
    "detect_capabilities",
    "SpecValidator",
    "build_clarification_plan",
    "ModulePlanner",
    "Composer",
    "ArchitectureBuilder",
    "resolve_effective_mode",
    "render_specification",
    "confirm_specification",
    "modify_specification",
    "run_spec_pipeline",
    "derive_intent_model",
    "apply_legacy_fallback",
    "assess_composition_support",
    "assess_from_capabilities",
    "SpecificationAssistant",
    "ConstraintGraph",
    "GraphNode",
    "NodeCategory",
    "use_spec_graph_v2",
    "bootstrap_graph",
    "should_use_graph_pipeline",
    "GraphGenerationBridge",
    "ValidatorV2",
    "GraphValidationResult",
    "ClarificationEngine",
    "ClarificationBatch",
]
