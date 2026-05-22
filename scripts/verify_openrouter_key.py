"""Quick check that OPENROUTER_API_KEY and optional OPENROUTER_PHASE1_MODEL are set."""
import os
from dotenv import load_dotenv

load_dotenv()
key = os.getenv("OPENROUTER_API_KEY")
phase1 = os.getenv("OPENROUTER_PHASE1_MODEL", "anthropic/claude-haiku-4.5")
phase1_fb = os.getenv("OPENROUTER_PHASE1_FALLBACK_MODEL", "meta-llama/llama-3.3-70b-instruct")
if key:
    print(f"OPENROUTER_API_KEY: {key[:12]}...{key[-4:]}")
    print(f"OPENROUTER_PHASE1_MODEL: {phase1}")
    print(f"OPENROUTER_PHASE1_FALLBACK_MODEL: {phase1_fb}")
else:
    print("OPENROUTER_API_KEY not set")
