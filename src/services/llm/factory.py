from .base import LLMProvider, LLMConfig, ResilientProvider
from .openrouter import OpenRouterProvider
from .groq import GroqProvider
from .openai import OpenAIProvider
from dotenv import load_dotenv
import logging
import os
from typing import Optional

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
    "golden": 800,    # Golden adaptation — constrained JSON only (constructor + business logic)
    "fix": 400,       # Syntax fix — minimal change
    "repair": 1500,   # Security fix — complex surgical edit
    "edit": 2000,     # User-directed code edit — needs room for full contract rewrite
    "audit": 1500,    # Semantic logic review — returns JSON (needs room for detailed descriptions)
    "general": 1000,
}


class LLMFactory:
    @classmethod
    def get_provider(
        cls, 
        task_type: str = "general", 
        api_key: Optional[str] = None, 
        provider_type: Optional[str] = None,
        groq_key: Optional[str] = None,
        openrouter_key: Optional[str] = None
    ) -> LLMProvider:
        """
        Returns a ResilientProvider configured with specialists and fallbacks.
        Supports dual-key BYOK (groq_key for Phase 1, openrouter_key for others).
        """
        # 1. Prioritize Multi-Key BYOK
        target_key = None
        target_provider = None

        if task_type == "phase1" and groq_key:
            target_key = groq_key
            target_provider = "groq"
        elif task_type != "phase1" and openrouter_key:
            target_key = openrouter_key
            target_provider = "openrouter"
        
        # 2. Fallback to Legacy Single-Key BYOK
        if not target_key and api_key:
            target_key = api_key
            target_provider = provider_type or "openrouter"

        if target_key:
            ptype = target_provider.lower()
            provider = None
            model = None
            
            # Select model based on task_type and provider
            if "openrouter" in ptype:
                if task_type == "phase2" or task_type == "repair" or task_type == "edit":
                    model = "anthropic/claude-sonnet-4.6"
                elif task_type == "fix" or task_type == "audit":
                    model = "anthropic/claude-haiku-4.5"
                else:
                    model = "openai/gpt-oss-120b" # Default
                provider = OpenRouterProvider(model=model, api_key=target_key)
                
            elif "groq" in ptype:
                model = "llama-3.3-70b-versatile"
                provider = GroqProvider(model=model, api_key=target_key)
                
            elif "openai" in ptype:
                model = "gpt-4o"
                provider = OpenAIProvider(model=model, api_key=target_key)
            else:
                provider = OpenRouterProvider(api_key=target_key)

            config = LLMConfig(
                provider,
                temperature=0.2,
                label=f"BYOK-{ptype}-{task_type}",
                max_tokens=_MAX_TOKENS.get(task_type, 1000)
            )
            return ResilientProvider(config)

        # Fail-fast check
        if not os.getenv("OPENROUTER_API_KEY") and not os.getenv("GROQ_API_KEY"):
            raise RuntimeError("No LLM API keys found (OPENROUTER_API_KEY or GROQ_API_KEY).")

        configs = []
        has_openrouter = bool(os.getenv("OPENROUTER_API_KEY"))

        # 1. Specialist Chains
        if task_type == "phase1":
            # OpenRouter Llama 3.3 is cheap and reliable enough for JSON intent parsing
            if has_openrouter:
                configs.append(LLMConfig(
                    OpenRouterProvider(model="meta-llama/llama-3.3-70b-instruct"),
                    temperature=0.1,
                    label="OpenRouter-Llama-3.3-Phase1-Primary",
                    max_tokens=_MAX_TOKENS["phase1"],
                ))
            else:
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

        elif task_type == "golden":
            # Golden Adaptation: Claude 4.6 Sonnet — constrained JSON output, ultra-low temp
            # Must return strict {constructor_block, business_logic_block} JSON only
            # 800 token cap prevents runaway output and prompt injection
            if has_openrouter:
                configs.append(LLMConfig(
                    OpenRouterProvider(model="anthropic/claude-sonnet-4.6"),
                    temperature=0.1,
                    label="Claude-4.6-Sonnet-Golden-Primary",
                    max_tokens=_MAX_TOKENS["golden"],
                ))
            # Groq Llama 3.3 as fallback — disciplined enough for constrained JSON
            configs.append(LLMConfig(
                GroqProvider(model="llama-3.3-70b-versatile"),
                temperature=0.1,
                label="Groq-Llama-3.3-Golden-Fallback",
                max_tokens=_MAX_TOKENS["golden"],
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
                    OpenRouterProvider(model="openai/gpt-4o-mini"),
                    temperature=0.0,
                    label="GPT-4o-mini-Fix-Secondary",
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

        elif task_type == "audit":
            # Semantic Audit - Haiku 4.5 is fast/cheap enough to read Logic, Sonnet as escalation
            # JSON enforcement is done via system prompt (no response_format kwarg needed)
            if has_openrouter:
                configs.append(LLMConfig(
                    OpenRouterProvider(model="anthropic/claude-haiku-4.5"),
                    temperature=0.1,
                    label="Claude-4.5-Haiku-Audit",
                    max_tokens=_MAX_TOKENS["audit"],
                ))
                configs.append(LLMConfig(
                    OpenRouterProvider(model="anthropic/claude-sonnet-4.6"),
                    temperature=0.1,
                    label="Claude-4.6-Sonnet-Audit-Fallback",
                    max_tokens=_MAX_TOKENS["audit"],
                ))
            else:
                configs.append(LLMConfig(
                    GroqProvider(model="llama-3.3-70b-versatile"),
                    temperature=0.1,
                    label="Groq-Audit-Fallback",
                    max_tokens=_MAX_TOKENS["audit"],
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
