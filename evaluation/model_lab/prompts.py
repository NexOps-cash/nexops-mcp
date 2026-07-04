from __future__ import annotations

from src.models import ContractIR
from src.services.pipeline import Phase1, build_phase2_prompt_bundle


async def run_phase1(
    prompt_text: str,
    *,
    phase1_model: str | None = None,
    security_level: str = "high",
) -> ContractIR:
    return await Phase1.run(
        prompt_text,
        security_level=security_level,
        disable_golden=True,
        disable_fallbacks=True,
        phase1_model=phase1_model,
    )


def build_phase2_prompts(ir: ContractIR) -> tuple[str, str]:
    return build_phase2_prompt_bundle(ir)
