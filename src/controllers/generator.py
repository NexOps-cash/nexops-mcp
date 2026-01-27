from ..models import MCPRequest
import asyncio
from typing import Dict, Any

async def generate_skeleton(req: MCPRequest) -> Dict[str, Any]:
    user_request = req.payload.get("user_request", "No request provided")
    
    # Simulate processing time
    # await asyncio.sleep(0.1) 

    skeleton_code = f"""
contract ExampleSkeleton(pubkey admin) {{
    /**
     * {user_request}
     * TODO: Implement logic
     */
    function action() {{
        // TODO
    }}
}}
""".strip()

    return {
        "request_id": req.request_id,
        "type": "skeleton",
        "data": {
            "stage": "skeleton",
            "code": skeleton_code,
            "notes": "Structure only. Logic intentionally omitted."
        }
    }
