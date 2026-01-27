from src.models import MCPRequest
from src.services.llm.factory import LLMFactory
from typing import Dict, Any, Optional
import os
import json
import logging

logger = logging.getLogger("nexops.generator")

def load_phase1_prompt(user_request: str, security_level: str = "high", project_context: str = "") -> str:
    try:
        # Load prompt template from spec file
        spec_path = os.path.join(os.getcwd(), "specs", "phase1_spec.md")
        with open(spec_path, "r", encoding="utf-8") as f:
            content = f.read()
            
        # Extract the system prompt block (between ```text and ```)
        # Simple extraction strategy: find first code block
        start_marker = "```text"
        end_marker = "```"
        start = content.find(start_marker)
        if start != -1:
            start += len(start_marker)
            end = content.find(end_marker, start)
            if end != -1:
                template = content[start:end].strip()
                # Inject variables
                return template.format(
                    user_request=user_request,
                    security_level=security_level,
                    project_context=project_context
                )
        
        logger.warning("Could not parse phase1_spec.md, falling back to simple prompt")
    except Exception as e:
        logger.warning(f"Error loading phase1 spec: {e}")
        
    return f"Generate CashScript skeleton for: {user_request}. Output JSON only."

async def generate_skeleton(req: MCPRequest) -> Dict[str, Any]:
    user_request = req.payload.get("user_request", "No request provided")
    security_level = req.context.get("security_level", "high") if req.context else "high"
    
    # Construct Prompt
    prompt = load_phase1_prompt(user_request, security_level)
    
    try:
        # Get LLM Provider
        llm = LLMFactory.get_provider("phase1")
        
        # Call LLM
        response_text = await llm.complete(prompt)
        
        # Clean response (remove markdown fences if present)
        clean_json = response_text.replace("```json", "").replace("```", "").strip()
        
        # Parse JSON
        data = json.loads(clean_json)
        
        # Enforce structural contract
        return {
            "request_id": req.request_id,
            "type": "skeleton",
            "data": data
        }
        
    except Exception as e:
        logger.error(f"Generation failed: {e}")
        return {
            "request_id": req.request_id,
            "type": "error",
            "error": {"code": "GENERATION_FAILED", "message": str(e)}
        }
