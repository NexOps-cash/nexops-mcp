from abc import ABC, abstractmethod
from typing import List

class LLMProvider(ABC):
    @abstractmethod
    async def complete(self, prompt: str, **kwargs) -> str:
        """
        Complete the prompt and return the full text response.
        """
        pass

class LLMConfig:
    def __init__(self, provider: LLMProvider, temperature: float, label: str = "primary"):
        self.provider = provider
        self.temperature = temperature
        self.label = label

class ResilientProvider(LLMProvider):
    """
    A provider that wraps multiple configurations and handles fallbacks at runtime.
    """
    def __init__(self, primary_config: LLMConfig, fallback_configs: List[LLMConfig] = None):
        self.configs = [primary_config] + (fallback_configs or [])
        import logging
        self.logger = logging.getLogger("nexops.resilient_llm")

    async def complete(self, prompt: str, **kwargs) -> str:
        last_error = None
        for i, config in enumerate(self.configs):
            try:
                self.logger.info(f"[LLM] Attempt {i+1}/{len(self.configs)}: Using {config.label} ({config.provider.__class__.__name__})")
                temp = kwargs.get("temperature", config.temperature)
                return await config.provider.complete(prompt, temperature=temp)
            except Exception as e:
                last_error = e
                self.logger.warning(f"[LLM] {config.label} failed (Attempt {i+1}): {e}")
        
        err_msg = f"All {len(self.configs)} LLM fallbacks exhausted. Final error: {last_error}"
        self.logger.error(f"[LLM] CRITICAL: {err_msg}")
        raise RuntimeError(err_msg)
    
    # Streaming support deferred to next iteration
    # @abstractmethod
    # async def stream(self, prompt: str):
    #     pass
