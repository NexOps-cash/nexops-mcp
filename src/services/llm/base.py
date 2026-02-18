from abc import ABC, abstractmethod
from typing import List, Optional


class LLMProvider(ABC):
    @abstractmethod
    async def complete(
        self,
        prompt: str,
        system: Optional[str] = None,
        max_tokens: Optional[int] = None,
        **kwargs,
    ) -> str:
        """
        Complete the prompt and return the full text response.
        If `system` is provided, it is sent as a system-role message.
        If `max_tokens` is provided, it caps the output length.
        """
        pass


class LLMConfig:
    def __init__(
        self,
        provider: "LLMProvider",
        temperature: float,
        label: str = "primary",
        max_tokens: Optional[int] = None,
    ):
        self.provider = provider
        self.temperature = temperature
        self.label = label
        self.max_tokens = max_tokens  # Task-specific cap


class ResilientProvider(LLMProvider):
    """
    A provider that wraps multiple configurations and handles fallbacks at runtime.
    """
    def __init__(self, primary_config: LLMConfig, fallback_configs: List[LLMConfig] = None):
        self.configs = [primary_config] + (fallback_configs or [])
        import logging
        self.logger = logging.getLogger("nexops.resilient_llm")

    async def complete(
        self,
        prompt: str,
        system: Optional[str] = None,
        max_tokens: Optional[int] = None,
        **kwargs,
    ) -> str:
        last_error = None
        for i, config in enumerate(self.configs):
            try:
                self.logger.info(f"[LLM] Attempt {i+1}/{len(self.configs)}: Using {config.label} ({config.provider.__class__.__name__})")
                temp = kwargs.pop("temperature", config.temperature)
                # Task-level cap takes precedence over call-level cap
                effective_max_tokens = config.max_tokens or max_tokens
                return await config.provider.complete(
                    prompt,
                    system=system,
                    max_tokens=effective_max_tokens,
                    temperature=temp,
                    **kwargs,
                )
            except Exception as e:
                last_error = e
                self.logger.warning(f"[LLM] {config.label} failed (Attempt {i+1}): {e}")

        err_msg = f"All {len(self.configs)} LLM fallbacks exhausted. Final error: {last_error}"
        self.logger.error(f"[LLM] CRITICAL: {err_msg}")
        raise RuntimeError(err_msg)
