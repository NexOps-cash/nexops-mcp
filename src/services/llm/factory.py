from .base import LLMProvider, LLMConfig, ResilientProvider
from .openrouter import OpenRouterProvider
from .groq import GroqProvider
from .openai import OpenAIProvider
from dotenv import load_dotenv
import logging
import os

# Load environment variables explicitly
load_dotenv()

logger = logging.getLogger("nexops.llm_factory")

OR_KEY = os.getenv("OPENROUTER_API_KEY")
if OR_KEY:
    logger.debug(f"[LLM] Context check: OPENROUTER_API_KEY length={len(OR_KEY)}")
else:
    logger.warning("[LLM] Context check: OPENROUTER_API_KEY is MISSING in environment.")

# ─── Task-Specific Max Token Caps ────────────────────────────────────────────
# CashScript contracts are small. We do NOT need 4096 tokens.
# These caps prevent runaway billing and reduce cost per call.
_MAX_TOKENS = {
    "phase1": 512,    # JSON intent model — tiny
    "phase2": 1000,   # Full contract synthesis — Sonnet quality in ~800 tokens
    "phase2_retry": 600,  # Haiku retry — compact fix
    "fix": 400,       # Syntax fix — minimal change
    "repair": 1500,   # Security fix — complex surgical edit
    "edit": 2000,     # User-directed code edit — needs room for full contract rewrite
    "general": 1000,
}


class LLMFactory:
    @classmethod
    def get_provider(cls, task_type: str = "general") -> LLMProvider:
        """
        Returns a ResilientProvider configured with specialists and fallbacks.
        max_tokens is set per task type to control cost.
        """
        # Fail-fast check
        if not os.getenv("OPENROUTER_API_KEY") and not os.getenv("GROQ_API_KEY"):
            raise RuntimeError("No LLM API keys found (OPENROUTER_API_KEY or GROQ_API_KEY).")

        configs = []
        has_openrouter = bool(os.getenv("OPENROUTER_API_KEY"))

        # 1. Specialist Chains
        if task_type == "phase1":
            # Groq Llama 3.3 is reliable enough for JSON intent parsing
            configs.append(LLMConfig(
                GroqProvider(model="llama-3.3-70b-versatile"),
                temperature=0.1,
                label="Groq-Llama-3.3-Phase1-Primary",
                max_tokens=_MAX_TOKENS["phase1"],
            ))

        elif task_type == "phase2":
            # Claude 4.6 Sonnet via OpenRouter — The latest SOTA (Released Feb 2026)
            # Exceptional at CashScript structure and covenant logic
            if has_openrouter:
                configs.append(LLMConfig(
                    OpenRouterProvider(model="anthropic/claude-sonnet-4.6"),
                    temperature=0.2, 
                    label="Claude-4.6-Sonnet-Primary",
                    max_tokens=_MAX_TOKENS["phase2"],
                ))
            # Groq as fallback — Llama 3.3
            configs.append(LLMConfig(
                GroqProvider(model="llama-3.3-70b-versatile"),
                temperature=0.2,
                label="Groq-Llama-3.3-Fallback",
                max_tokens=_MAX_TOKENS["phase2"],
            ))

        elif task_type == "fix":
            # Claude 4.5 Haiku via OpenRouter — Extremely fast, smarter than 3.5 Sonnet
            if has_openrouter:
                configs.append(LLMConfig(
                    OpenRouterProvider(model="anthropic/claude-haiku-4.5"),
                    temperature=0.0,
                    label="Claude-4.5-Haiku-Fix-Primary",
                    max_tokens=_MAX_TOKENS["fix"],
                ))
                configs.append(LLMConfig(
                    OpenRouterProvider(model="anthropic/claude-sonnet-4.6"),
                    temperature=0.0,
                    label="Claude-4.6-Sonnet-Fix-Fallback",
                    max_tokens=_MAX_TOKENS["fix"],
                ))
            # Groq fallback for fix loop
            configs.append(LLMConfig(
                GroqProvider(model="llama-3.3-70b-versatile"),
                temperature=0.0,
                max_tokens=_MAX_TOKENS["fix"],
            ))

        elif task_type == "repair":
            # Tiered Security Repair Models
            if has_openrouter:
                # Primary: Haiku 4.5 (Disciplined, fast)
                configs.append(LLMConfig(
                    OpenRouterProvider(model="anthropic/claude-haiku-4.5"),
                    temperature=0.1,
                    label="Claude-4.5-Haiku-Repair-Primary",
                    max_tokens=_MAX_TOKENS["repair"],
                ))
                # Escalation: Sonnet 4.6 (Intelligence for complex invariants)
                configs.append(LLMConfig(
                    OpenRouterProvider(model="anthropic/claude-sonnet-4.6"),
                    temperature=0.1,
                    label="Claude-4.6-Sonnet-Repair-Escalation",
                    max_tokens=_MAX_TOKENS["repair"],
                ))
            else:
                configs.append(LLMConfig(
                    GroqProvider(model="llama-3.3-70b-versatile"),
                    temperature=0.1,
                    label="Groq-Repair-Fallback",
                    max_tokens=_MAX_TOKENS["repair"],
                ))

        elif task_type == "edit":
            # User-directed code editing — Sonnet 4.6 primary, Haiku 4.5 fallback
            if has_openrouter:
                configs.append(LLMConfig(
                    OpenRouterProvider(model="anthropic/claude-sonnet-4.6"),
                    temperature=0.2,
                    label="Claude-4.6-Sonnet-Edit-Primary",
                    max_tokens=_MAX_TOKENS["edit"],
                ))
                configs.append(LLMConfig(
                    OpenRouterProvider(model="anthropic/claude-haiku-4.5"),
                    temperature=0.2,
                    label="Claude-4.5-Haiku-Edit-Fallback",
                    max_tokens=_MAX_TOKENS["edit"],
                ))
            else:
                configs.append(LLMConfig(
                    GroqProvider(model="llama-3.3-70b-versatile"),
                    temperature=0.2,
                    label="Groq-Edit-Fallback",
                    max_tokens=_MAX_TOKENS["edit"],
                ))

        else:
            # Default general chain
            configs.append(LLMConfig(
                GroqProvider(model="llama-3.3-70b-versatile"),
                temperature=0.2,
                label="Groq-Llama-3.3-Default",
                max_tokens=_MAX_TOKENS["general"],
            ))
            if has_openrouter:
                configs.append(LLMConfig(
                    OpenRouterProvider(model="deepseek/deepseek-r1"),
                    temperature=0.2,
                    label="DeepSeek-R1-Fallback",
                    max_tokens=_MAX_TOKENS["general"],
                ))

        logger.info(f"[LLM] Factory return ResilientProvider for '{task_type}' with {len(configs)} configs.")
        return ResilientProvider(configs[0], configs[1:])
