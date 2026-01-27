from .base import LLMProvider
import os
from groq import AsyncGroq

class GroqProvider(LLMProvider):
    def __init__(self):
        api_key = os.getenv("GROQ_API_KEY")
        if not api_key:
            raise ValueError("GROQ_API_KEY is not set")
            
        self.client = AsyncGroq(api_key=api_key)
        self.model = "mixtral-8x7b-32768"

    async def complete(self, prompt: str) -> str:
        try:
            response = await self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "user", "content": prompt}
                ],
            )
            return response.choices[0].message.content
        except Exception as e:
            raise RuntimeError(f"Groq completion failed: {e}")
