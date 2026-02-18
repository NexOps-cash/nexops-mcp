import os
from dotenv import load_dotenv

load_dotenv()
key = os.getenv("OPENROUTER_API_KEY")
if key:
    print(f"Key loaded: {key[:10]}...{key[-5:]}")
    print(f"Key length: {len(key)}")
else:
    print("Key NOT found in environment.")
