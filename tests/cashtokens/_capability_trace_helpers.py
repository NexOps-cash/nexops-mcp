"""Assertions for SemanticCapabilities trace integrity (Wave 2A.5)."""

from __future__ import annotations

from src.services.semantic_capabilities import SemanticCapabilities


def assert_capability_trace(
    caps: SemanticCapabilities,
    key: str,
    expected: bool,
    *,
    required_anchor_substrings: list[str] | None = None,
) -> None:
    actual = caps.get(key)
    if expected:
        assert actual is True, f"{key}: expected true, got {actual!r}"
        trace = caps.to_trace_dict()
        derived = [d for d in trace.get("derived_from", []) if d.get("key") == key and d.get("value")]
        assert derived, f"{key}: missing derived_from entry when true"
        anchors = derived[0].get("anchors") or []
        assert anchors, f"{key}: true capability must have non-empty anchors"
        if required_anchor_substrings:
            joined = " ".join(anchors).lower()
            for sub in required_anchor_substrings:
                assert sub.lower() in joined, f"{key}: anchor missing substring {sub!r}"
    else:
        assert actual is not True, f"{key}: expected false/absent, got {actual!r}"
        trace = caps.to_trace_dict()
        derived_true = [
            d for d in trace.get("derived_from", []) if d.get("key") == key and d.get("value") is True
        ]
        assert not derived_true, f"{key}: must not appear as true in derived_from"
