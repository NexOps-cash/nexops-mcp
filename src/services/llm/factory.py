from .base import LLMProvider
from .openrouter import OpenRouterProvider
from .groq import GroqProvider
import os

class LLMFactory:
    _primary: LLMProvider = None
    _fallback: LLMProvider = None

    @classmethod
    def get_provider(cls, task_type: str = "general") -> LLMProvider:
        """
        Returns the appropriate provider based on task availability.
        Strategies:
        - Phase 1 & 2 (Reasoning): Prefer OpenRouter -> Fallback Groq
        - Chat/Fast: Prefer Groq -> Fallback OpenRouter
        """
        
        # Initialize providers lazily
        if not cls._primary:
            try:
                cls._primary = OpenRouterProvider()
            except:
                pass # Primary might not be configured
        
        if not cls._fallback:
            try:
                cls._fallback = GroqProvider()
            except:
                pass

        # Strategy: Strict preference for OpenRouter for now as per "Anti-Gravity" rules
        # unless it's missing, then fallback.
        
        if cls._primary:
            return cls._primary
        elif cls._fallback:
            return cls._fallback
        else:
            raise RuntimeError("No LLM providers configured. Check .env for OPENROUTER_API_KEY or GROQ_API_KEY.")
