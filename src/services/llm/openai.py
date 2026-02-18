from .base import LLMProvider
import os
from typing import Optional
from openai import AsyncOpenAI

class OpenAIProvider(LLMProvider):
    def __init__(self, model: Optional[str] = None):
        api_key = os.getenv("OPENAI_API_KEY")
        if not api_key:
            raise ValueError("OPENAI_API_KEY is not set")
            
        self.client = AsyncOpenAI(
            api_key=api_key,
        )
        self.model = model or "gpt-4o"

    async def complete(self, prompt: str, **kwargs) -> str:
        try:
            response = await self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "user", "content": prompt}
                ],
                **kwargs
            )
            return response.choices[0].message.content
        except Exception as e:
            raise RuntimeError(f"OpenAI completion failed: {e}")
