"""
Declarative requirement satisfaction over SemanticCapabilities.

`satisfies()` is a thin dispatcher — policy lives in semantic_requirement_map.yaml.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set

import yaml

from src.services.semantic_capabilities import SemanticCapabilities

_MAP_PATH = Path(__file__).resolve().parent / "config" / "semantic_requirement_map.yaml"
_CACHE: Optional[Dict[str, Dict[str, Any]]] = None


def load_requirement_map() -> Dict[str, Dict[str, Any]]:
    global _CACHE
    if _CACHE is None:
        with open(_MAP_PATH, encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
        _CACHE = data.get("mappings", {})
    return _CACHE


def _cap_value(caps: SemanticCapabilities, key: str) -> Optional[bool]:
    return caps.get(key)


def satisfies_requirement(
    req: str,
    caps: SemanticCapabilities,
    *,
    legacy_alias_checks: Optional[Dict[str, bool]] = None,
    detected_features: Optional[Set[str]] = None,
    legacy_capabilities: Optional[Dict[str, bool]] = None,
) -> tuple[bool, Dict[str, Any]]:
    """
    Returns (satisfied, trace_entry) for one requirement key.
    trace_entry records path: capability | fallback | unknown
    """
    mapping = load_requirement_map().get(req)
    trace: Dict[str, Any] = {"requirement": req, "path": "unknown", "details": {}}

    if not mapping:
        # Direct legacy capability / detected feature
        if legacy_capabilities and legacy_capabilities.get(req):
            trace["path"] = "legacy_capability"
            return True, trace
        if detected_features and req in detected_features:
            trace["path"] = "detected_feature"
            return True, trace
        if legacy_alias_checks and legacy_alias_checks.get(req):
            trace["path"] = "regex_alias_unmapped"
            return True, trace
        return False, trace

    def eval_capability(key: str, negate: bool = False) -> Optional[bool]:
        val = _cap_value(caps, key)
        if val is None:
            return None
        return (not val) if negate else val

    # all_capabilities
    if "all_capabilities" in mapping:
        keys = mapping["all_capabilities"]
        vals = [eval_capability(k) for k in keys]
        if all(v is True for v in vals):
            trace["path"] = "capability_all"
            trace["details"] = {"keys": keys}
            return True, trace
        trace["details"] = {"keys": keys, "vals": vals}

    # any_capabilities
    if "any_capabilities" in mapping:
        keys = mapping["any_capabilities"]
        if any(eval_capability(k) is True for k in keys):
            trace["path"] = "capability_any"
            trace["details"] = {"keys": keys}
            return True, trace

    # single capability
    cap_key = mapping.get("capability")
    if cap_key:
        negate = bool(mapping.get("negate"))
        val = eval_capability(cap_key, negate=negate)
        if val is True:
            trace["path"] = "capability"
            trace["details"] = {"capability": cap_key, "negate": negate}
            return True, trace
        neg_cap = mapping.get("negate_capability")
        if neg_cap and eval_capability(neg_cap, negate=True) is True:
            trace["path"] = "capability_negate_pair"
            trace["details"] = {"capability": cap_key, "negate_capability": neg_cap}
            return True, trace

    # Fallback chain
    fallback = mapping.get("fallback", "regex_alias")
    alias_key = mapping.get("alias_pool_key", req)
    if fallback == "regex_alias" and legacy_alias_checks and legacy_alias_checks.get(alias_key):
        trace["path"] = "fallback_regex_alias"
        trace["details"] = {"alias_pool_key": alias_key}
        return True, trace
    if fallback == "detected_feature":
        det = mapping.get("detected", req)
        if detected_features and det in detected_features:
            trace["path"] = "fallback_detected"
            trace["details"] = {"detected": det}
            return True, trace
    if legacy_capabilities and legacy_capabilities.get(req):
        trace["path"] = "fallback_legacy_capability"
        return True, trace

    trace["path"] = "unsatisfied"
    return False, trace


def satisfy_all_requirements(
    requirements: List[str],
    caps: SemanticCapabilities,
    **kwargs: Any,
) -> tuple[List[str], List[str], Dict[str, Dict[str, Any]]]:
    """Returns (matched, missing, trace_by_req)."""
    matched: List[str] = []
    missing: List[str] = []
    traces: Dict[str, Dict[str, Any]] = {}
    for req in requirements:
        ok, tr = satisfies_requirement(req, caps, **kwargs)
        traces[req] = tr
        if ok:
            matched.append(req)
        else:
            missing.append(req)
    return matched, missing, traces
