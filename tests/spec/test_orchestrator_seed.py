"""Tests for seeding spec parameters from the initial user intent."""

import pytest

from src.services.spec.orchestrator import run_spec_pipeline


@pytest.mark.asyncio
async def test_pipeline_seeds_founder_vesting_from_intent():
    intent = (
        "Create a founder vesting vault. Requirements: "
        "- Funds remain locked for 180 days. "
        "- 60% to Founder A, 40% to Founder B. "
        "- Preserve BCH value."
    )
    spec, _, _, _, _, _ = await run_spec_pipeline(
        intent,
        resolution_mode="non_interactive",
    )
    names = {c.name for c in spec.capabilities}
    assert names == {"split", "timelock", "vault"}
    assert spec.parameters.get("timeout_days") == 180
    assert spec.parameters.get("shares") == [60, 40]
    assert spec.parameters.get("recipients") == ["Founder A", "Founder B"]
    assert spec.parameters.get("asset_type") == "bch"
