import os
import asyncio
from dotenv import load_dotenv
from openai import AsyncOpenAI

async def test_openrouter():
    load_dotenv()
    api_key = os.getenv("OPENROUTER_API_KEY")
    if not api_key:
        print("OPENROUTER_API_KEY not found")
        return

    client = AsyncOpenAI(
        base_url="https://openrouter.ai/api/v1",
        api_key=api_key,
    )

    print(f"Testing with key: {api_key[:10]}...")
    try:
        response = await client.chat.completions.create(
            model="google/gemini-2.0-flash-exp:free",
            messages=[{"role": "user", "content": "hi"}],
            extra_headers={
                "HTTP-Referer": "https://github.com/nexops/nexops-mcp", # OpenRouter best practice
                "X-Title": "NexOps MCP",
            }
        )
        print("Success!")
        print(response.choices[0].message.content)
    except Exception as e:
        print(f"Failed: {e}")

if __name__ == "__main__":
    asyncio.run(test_openrouter())
