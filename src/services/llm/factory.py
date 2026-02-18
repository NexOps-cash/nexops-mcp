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

class LLMFactory:
    @classmethod
    def get_provider(cls, task_type: str = "general") -> LLMProvider:
        """
        Returns a ResilientProvider configured with specialists and fallbacks.
        """
        # Fail-fast check
        if not os.getenv("OPENROUTER_API_KEY") and not os.getenv("GROQ_API_KEY"):
            raise RuntimeError("No LLM API keys found (OPENROUTER_API_KEY or GROQ_API_KEY).")

        configs = []

        # 1. Specialist Chains
        if task_type == "phase1":
            # Groq is primary for Phase 1 now (Llama 3.3 70B is reliable enough)
            configs.append(LLMConfig(GroqProvider(model="llama-3.3-70b-versatile"), temperature=0.1, label="Groq-Llama-3.3-Phase1-Primary"))
            # Gemini Flash as fallback if Groq fails
            configs.append(LLMConfig(OpenRouterProvider(model="google/gemini-2.0-flash-exp"), temperature=0.1, label="Gemini-Flash-Exp-Fallback"))
        
        elif task_type == "phase2":
            # Groq is primary for synthesis
            configs.append(LLMConfig(GroqProvider(model="llama-3.3-70b-versatile"), temperature=0.2, label="Groq-Llama-3.3-Primary"))
            
            # Fallbacks (keeping them for resilience, but Groq is first)
            if os.getenv("OPENAI_API_KEY"):
                configs.append(LLMConfig(OpenAIProvider(model="gpt-4o"), temperature=0.2, label="OpenAI-GPT4o-Secondary"))
            configs.append(LLMConfig(OpenRouterProvider(model="deepseek/deepseek-r1"), temperature=0.2, label="DeepSeek-R1-Fallback"))
        
        elif task_type == "fix":
            # Groq is primary for fixes
            configs.append(LLMConfig(GroqProvider(model="llama-3.3-70b-versatile"), temperature=0.0, label="Groq-Llama-3.3-Fix-Primary"))
            
            # Fallbacks
            configs.append(LLMConfig(OpenRouterProvider(model="deepseek/deepseek-chat"), temperature=0.0, label="DeepSeek-V3-Fix-Fallback"))
            if os.getenv("OPENAI_API_KEY"):
                configs.append(LLMConfig(OpenAIProvider(model="gpt-4o"), temperature=0.0, label="OpenAI-GPT4o-Fix-Fallback"))
        
        else:
            # Default general chain
            configs.append(LLMConfig(GroqProvider(model="llama-3.3-70b-versatile"), temperature=0.2, label="Groq-Llama-3.3-Default"))
            configs.append(LLMConfig(OpenRouterProvider(model="deepseek/deepseek-r1"), temperature=0.2, label="DeepSeek-R1-Fallback"))

        logger.info(f"[LLM] Factory return ResilientProvider for '{task_type}' with {len(configs)} configs.")
        return ResilientProvider(configs[0], configs[1:])
