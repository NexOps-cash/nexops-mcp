"""
Sample Generation Script — Demonstrates the 3-Phase Pipeline.

Usage: python scripts/sample_generate.py "Your intent here"
Example: python scripts/sample_generate.py "Create a 2-of-2 escrow with timeout"
"""

import asyncio
import sys
import os
import json
import logging
from typing import Dict, Any
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Ensure project root is in path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.models import MCPRequest
from src.controllers.generator import GenerationController

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("nexops.sample")

async def main():
    # 1. Get user intent from arg or default
    intent = sys.argv[1] if len(sys.argv) > 1 else "Create a 2-of-2 escrow with timeout"
    
    # 2. Check for API keys
    if not os.getenv("OPENROUTER_API_KEY") and not os.getenv("GROQ_API_KEY"):
        print("[FAIL] ERROR: No API keys found.")
        print("Please set OPENROUTER_API_KEY or GROQ_API_KEY in your environment.")
        return

    print(f"\n[START] Starting Generation Pipeline for:")
    print(f"   Intent: \"{intent}\"")
    print("-" * 60)

    # 3. Create Request
    req = MCPRequest(
        request_id="test-req-123",
        action="generate",
        payload={
            "user_request": intent,
            "session_id": "demo-session"
        },
        context={
            "security_level": "high"
        }
    )

    # 4. Instantiate Controller
    controller = GenerationController()

    # 5. Run Pipeline
    try:
        response = await controller.generate(req)
        
        if response["type"] == "success":
            data = response["data"]
            print(f"\n✅ SUCCESS!")
            print(f"   Contract Name: {data['contract_name']}")
            print(f"   Structural Score: {data['toll_gate']['structural_score']:.2f}")
            print(f"   Session ID: {data['session_id']}")
            print("\n📜 Generated Code:")
            print("-" * 60)
            print(data["code"])
            print("-" * 60)
        else:
            error = response.get("error", {})
            print(f"\n❌ FAILED!")
            print(f"   Error Code: {error.get('code')}")
            print(f"   Message: {error.get('message')}")
            
            violations = error.get("violations")
            if violations:
                print("\n🚫 Toll Gate Violations:")
                for i, v in enumerate(violations, 1):
                    print(f"   {i}. [{v.get('severity', '').upper()}] {v.get('rule')}: {v.get('reason')}")
                    if v.get("fix_hint"):
                        print(f"      HINT: {v.get('fix_hint')}")

    except Exception as e:
        logger.exception("Fatal error during sample generation")
        print(f"\n[CRASH] CRASH: {e}")

if __name__ == "__main__":
    asyncio.run(main())
