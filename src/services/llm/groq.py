from .base import LLMProvider
import os
from typing import Optional
from groq import AsyncGroq



class GroqProvider(LLMProvider):

    def __init__(self, model: Optional[str] = None):
        api_key = os.getenv("GROQ_API_KEY")
        if not api_key:
            raise ValueError("GROQ_API_KEY is not set")
            
        self.client = AsyncGroq(api_key=api_key)
        self.model = model or "llama-3.3-70b-versatile" # Updated from decommissioned mixtral-8x7b-32768



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

            raise RuntimeError(f"Groq completion failed: {e}")

