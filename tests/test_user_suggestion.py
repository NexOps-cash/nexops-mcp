from openai import OpenAI
import os
from dotenv import load_dotenv

load_dotenv()

client = OpenAI(
    api_key=os.getenv("OPENROUTER_API_KEY"),  # IMPORTANT
    base_url="https://openrouter.ai/api/v1",
    default_headers={
        "HTTP-Referer": "http://localhost",
        "X-Title": "NexOps"
    }
)

response = client.chat.completions.create(
    model="deepseek/deepseek-coder:free",
    messages=[{"role": "user", "content": "how are u"}],
)

print(response.choices[0].message.content)