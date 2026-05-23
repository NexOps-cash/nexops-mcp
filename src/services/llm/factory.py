from .base import LLMProvider, LLMConfig, ResilientProvider
from .openrouter import OpenRouterProvider
from .openai import OpenAIProvider
from dotenv import load_dotenv
import logging
import os
from typing import Optional

load_dotenv()

logger = logging.getLogger("nexops.llm_factory")

OR_KEY = os.getenv("OPENROUTER_API_KEY")
if OR_KEY:
    logger.debug(f"[LLM] Context check: OPENROUTER_API_KEY length={len(OR_KEY)}")
else:
    logger.warning("[LLM] Context check: OPENROUTER_API_KEY is MISSING in environment.")

# Phase 1: intent + semantic tag classification — slightly stronger than raw 70B Llama.
# Haiku 4.5: better JSON/schema adherence for ownership/lifecycle/supply fields.
OPENROUTER_PHASE1_MODEL = os.getenv(
    "OPENROUTER_PHASE1_MODEL",
    "anthropic/claude-haiku-4.5",
)
# Cheaper fallback when primary is rate-limited or out of credits.
OPENROUTER_PHASE1_FALLBACK_MODEL = os.getenv(
    "OPENROUTER_PHASE1_FALLBACK_MODEL",
    "meta-llama/llama-3.3-70b-instruct",
)
OPENROUTER_FAST_FALLBACK_MODEL = os.getenv(
    "OPENROUTER_FAST_FALLBACK_MODEL",
    "openai/gpt-4o-mini",
)

_MAX_TOKENS = {
    "phase1": 512,
    "phase2": 1000,
    "phase2_retry": 600,
    "golden": 800,
    "fix": 400,
    "repair": 1500,
    "edit": 2000,
    "audit": 1500,
    "general": 1000,
}


def _or(model: str, **kwargs) -> LLMConfig:
    return LLMConfig(OpenRouterProvider(model=model), **kwargs)


def _llama_fallback(task_type: str, temperature: float, label: str) -> LLMConfig:
    return _or(
        OPENROUTER_FAST_FALLBACK_MODEL,
        temperature=temperature,
        label=label,
        max_tokens=_MAX_TOKENS.get(task_type, 1000),
    )


class LLMFactory:
    @classmethod
    def get_provider(
        cls,
        task_type: str = "general",
        api_key: Optional[str] = None,
        provider_type: Optional[str] = None,
        openrouter_key: Optional[str] = None,
        # Deprecated: ignored if passed by older clients
        groq_key: Optional[str] = None,
    ) -> LLMProvider:
        """
        Returns a ResilientProvider configured with OpenRouter specialists and fallbacks.
        """
        if groq_key:
            logger.warning("[LLM] groq_key is deprecated and ignored; use OPENROUTER_API_KEY only.")

        target_key = openrouter_key or api_key
        target_provider = (provider_type or "openrouter").lower()

        if target_key:
            model = OPENROUTER_PHASE1_MODEL
            if task_type == "phase2" or task_type in ("repair", "edit"):
                model = "anthropic/claude-sonnet-4.6"
            elif task_type == "fix" or task_type == "audit":
                model = "anthropic/claude-haiku-4.5"
            elif task_type == "golden":
                model = "anthropic/claude-sonnet-4.6"
            elif task_type == "phase1":
                model = OPENROUTER_PHASE1_MODEL

            if "openai" in target_provider and "openrouter" not in target_provider:
                provider = OpenAIProvider(model="gpt-4o", api_key=target_key)
            else:
                provider = OpenRouterProvider(model=model, api_key=target_key)

            config = LLMConfig(
                provider,
                temperature=0.2,
                label=f"BYOK-{target_provider}-{task_type}",
                max_tokens=_MAX_TOKENS.get(task_type, 1000),
            )
            return ResilientProvider(config)

        if not os.getenv("OPENROUTER_API_KEY"):
            raise RuntimeError("No LLM API key found (OPENROUTER_API_KEY required).")

        configs: list[LLMConfig] = []

        if task_type == "phase1":
            configs.append(_or(
                OPENROUTER_PHASE1_MODEL,
                temperature=0.1,
                label="OpenRouter-Phase1-Primary",
                max_tokens=_MAX_TOKENS["phase1"],
            ))
            configs.append(_or(
                OPENROUTER_PHASE1_FALLBACK_MODEL,
                temperature=0.1,
                label="OpenRouter-Phase1-Fallback",
                max_tokens=_MAX_TOKENS["phase1"],
            ))

        elif task_type == "phase2":
            configs.append(_or(
                "anthropic/claude-sonnet-4.6",
                temperature=0.2,
                label="Claude-4.6-Sonnet-Primary",
                max_tokens=_MAX_TOKENS["phase2"],
            ))
            configs.append(_or(
                OPENROUTER_PHASE1_MODEL,
                temperature=0.2,
                label="OpenRouter-Llama-Phase2-Fallback",
                max_tokens=_MAX_TOKENS["phase2"],
            ))

        elif task_type == "golden":
            configs.append(_or(
                "anthropic/claude-sonnet-4.6",
                temperature=0.1,
                label="Claude-4.6-Sonnet-Golden-Primary",
                max_tokens=_MAX_TOKENS["golden"],
            ))
            configs.append(_or(
                OPENROUTER_PHASE1_MODEL,
                temperature=0.1,
                label="OpenRouter-Llama-Golden-Fallback",
                max_tokens=_MAX_TOKENS["golden"],
            ))

        elif task_type == "fix":
            configs.append(_or(
                "anthropic/claude-haiku-4.5",
                temperature=0.0,
                label="Claude-4.5-Haiku-Fix-Primary",
                max_tokens=_MAX_TOKENS["fix"],
            ))
            configs.append(_or(
                "openai/gpt-4o-mini",
                temperature=0.0,
                label="GPT-4o-mini-Fix-Secondary",
                max_tokens=_MAX_TOKENS["fix"],
            ))
            configs.append(_or(
                "anthropic/claude-sonnet-4.6",
                temperature=0.0,
                label="Claude-4.6-Sonnet-Fix-Fallback",
                max_tokens=_MAX_TOKENS["fix"],
            ))

        elif task_type == "repair":
            configs.append(_or(
                "anthropic/claude-haiku-4.5",
                temperature=0.1,
                label="Claude-4.5-Haiku-Repair-Primary",
                max_tokens=_MAX_TOKENS["repair"],
            ))
            configs.append(_or(
                "anthropic/claude-sonnet-4.6",
                temperature=0.1,
                label="Claude-4.6-Sonnet-Repair-Escalation",
                max_tokens=_MAX_TOKENS["repair"],
            ))

        elif task_type == "edit":
            configs.append(_or(
                "anthropic/claude-sonnet-4.6",
                temperature=0.2,
                label="Claude-4.6-Sonnet-Edit-Primary",
                max_tokens=_MAX_TOKENS["edit"],
            ))
            configs.append(_or(
                "anthropic/claude-haiku-4.5",
                temperature=0.2,
                label="Claude-4.5-Haiku-Edit-Fallback",
                max_tokens=_MAX_TOKENS["edit"],
            ))

        elif task_type == "audit":
            configs.append(_or(
                "anthropic/claude-haiku-4.5",
                temperature=0.1,
                label="Claude-4.5-Haiku-Audit",
                max_tokens=_MAX_TOKENS["audit"],
            ))
            configs.append(_or(
                "anthropic/claude-sonnet-4.6",
                temperature=0.1,
                label="Claude-4.6-Sonnet-Audit-Fallback",
                max_tokens=_MAX_TOKENS["audit"],
            ))

        else:
            configs.append(_or(
                OPENROUTER_PHASE1_MODEL,
                temperature=0.2,
                label="OpenRouter-Llama-Default",
                max_tokens=_MAX_TOKENS["general"],
            ))
            configs.append(_or(
                "deepseek/deepseek-r1",
                temperature=0.2,
                label="DeepSeek-R1-Fallback",
                max_tokens=_MAX_TOKENS["general"],
            ))

        logger.info(
            f"[LLM] Factory return ResilientProvider for '{task_type}' "
            f"with {len(configs)} configs (phase1_model={OPENROUTER_PHASE1_MODEL})."
        )
        return ResilientProvider(configs[0], configs[1:])
