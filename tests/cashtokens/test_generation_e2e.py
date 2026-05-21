"""E2E generation smoke tests (require LLM API keys)."""
import os
import pytest

pytestmark = pytest.mark.skipif(
    not os.getenv("OPENROUTER_API_KEY") and not os.getenv("GROQ_API_KEY"),
    reason="OPENROUTER_API_KEY or GROQ_API_KEY required for E2E generation",
)


@pytest.mark.asyncio
async def test_ft_transfer_compiles():
    from src.services.pipeline_engine import get_guarded_pipeline_engine

    engine = get_guarded_pipeline_engine()
    intent = (
        "Create a loyalty points transfer contract. Users hold pre-minted points "
        "and can send a chosen amount to a recipient with their signature."
    )
    result = await engine.generate_guarded(
        intent,
        security_level="high",
        disable_golden=True,
        disable_fallbacks=True,
    )
    assert result.get("type") == "success", result
    code = result["data"]["code"]
    assert "tokenCategory" in code
    assert "checkSig" in code


@pytest.mark.asyncio
async def test_minting_failure_case_rejected_or_no_custody():
    from src.services.pipeline_engine import get_guarded_pipeline_engine

    engine = get_guarded_pipeline_engine()
    intent = (
        "FAILURE CASE: NFT mint contract that releases the 0x02 minting NFT "
        "to the buyer (capability leak)."
    )
    result = await engine.generate_guarded(
        intent,
        security_level="high",
        disable_golden=True,
        disable_fallbacks=True,
    )
    if result.get("type") == "success":
        code = result["data"]["code"]
        has_custody = "this.activeBytecode" in code and "0x02" in code
        assert has_custody, "Leaky mint must not pass without custody on 0x02 output"
