"""Unified invariant engine profile tests."""

from src.services.anti_pattern_detectors import DETECTOR_REGISTRY
from src.services.audit_engine.audit_detectors import AUDIT_DETECTOR_REGISTRY
from src.services.invariant_engine_core import (
    build_audit_profile,
    build_generation_profile,
    validate_with_profile,
)

MINIMAL = """
pragma cashscript ^0.10.0;
contract Ok() {
    function go(sig s, pubkey p) {
        require(checkSig(s, p));
        require(tx.outputs.length >= 1);
        require(tx.outputs[0].value == 1000);
    }
}
"""


def test_generation_profile_includes_capability_detectors():
    profile = build_generation_profile(DETECTOR_REGISTRY)
    assert len(profile.capability_detectors) >= 7
    result = validate_with_profile(MINIMAL, profile, contract_mode="escrow")
    assert "valid" in result
    assert "stage" in result


def test_audit_profile_metadata_routing():
    profile = build_audit_profile(AUDIT_DETECTOR_REGISTRY)
    result = validate_with_profile(MINIMAL, profile, contract_mode="escrow", trace_case_id="t1")
    assert "capabilities" in result
    assert "valid" in result
