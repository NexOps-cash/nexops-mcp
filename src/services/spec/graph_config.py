"""Feature flags for Constraint Graph v2 pipeline."""

from __future__ import annotations

import os


def use_spec_graph_v2() -> bool:
    """
    When true, interactive spec uses ConstraintGraph as SSOT.
    Phase 5: defaults to enabled unless NEXOPS_SPEC_GRAPH_V2=0.
    """
    raw = os.getenv("NEXOPS_SPEC_GRAPH_V2", "1").strip().lower()
    return raw not in ("0", "false", "no", "off")


def graph_benchmark_legacy_only() -> bool:
    """Force legacy keyword path for non-interactive benchmark runs."""
    raw = os.getenv("NEXOPS_SPEC_GRAPH_LEGACY_BENCHMARK", "1").strip().lower()
    return raw in ("1", "true", "yes", "on")
