import os
import asyncio
from dotenv import load_dotenv
from openai import AsyncOpenAI

async def test_openai():
    load_dotenv()
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        print("OPENAI_API_KEY not found")
        return

    client = AsyncOpenAI(
        api_key=api_key,
    )

    print(f"Testing with key: {api_key[:10]}...")
    try:
        response = await client.chat.completions.create(
            model="gpt-4o",
            messages=[{"role": "user", "content": "hi"}],
        )
        print("Success!")
        print(response.choices[0].message.content)
    except Exception as e:
        print(f"Failed: {e}")

if __name__ == "__main__":
    asyncio.run(test_openai())
