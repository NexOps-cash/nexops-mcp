from .base import LLMProvider
import os
from typing import Optional
from groq import AsyncGroq


class GroqProvider(LLMProvider):

    def __init__(self, model: Optional[str] = None, api_key: Optional[str] = None):
        if not api_key:
            api_key = os.getenv("GROQ_API_KEY")
        
        if not api_key:
            raise ValueError("GROQ_API_KEY is not set")

        self.client = AsyncGroq(api_key=api_key)
        self.model = model or "llama-3.3-70b-versatile"

    async def complete(
        self,
        prompt: str,
        system: Optional[str] = None,
        max_tokens: Optional[int] = None,
        **kwargs,
    ) -> str:
        try:
            messages = []
            if system:
                messages.append({"role": "system", "content": system})
            messages.append({"role": "user", "content": prompt})

            create_kwargs = {"model": self.model, "messages": messages, **kwargs}
            if max_tokens:
                create_kwargs["max_tokens"] = max_tokens

            response = await self.client.chat.completions.create(**create_kwargs)
            actual_model = response.model
            content = response.choices[0].message.content
            import logging
            logging.getLogger("nexops.llm.groq").info(f"[Groq] Response from {actual_model} ({len(content)} chars)")
            return content
        except Exception as e:
            raise RuntimeError(f"Groq completion failed: {e}")
