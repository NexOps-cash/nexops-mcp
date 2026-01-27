from .models import MCPRequest
from .controllers.generator import generate_skeleton
from .utils.errors import error_response
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("nexops.router")

async def route_request(raw_msg: dict) -> dict:
    try:
        # Validate request structure
        req = MCPRequest(**raw_msg)
        
        logger.info(f"Routing request: {req.request_id} Action: {req.action}")

        if req.action == "generate":
            return await generate_skeleton(req)
        
        # Default fallback for unknown actions
        return error_response(
            req.request_id,
            "UNKNOWN_ACTION",
            f"Unsupported action: {req.action}"
        )

    except Exception as e:
        logger.error(f"Routing error: {str(e)}")
        # If we can't parse the request_id, use "unknown" or try to retrieve it safely
        req_id = raw_msg.get("request_id", "unknown") if isinstance(raw_msg, dict) else "unknown"
        return error_response(
            req_id,
            "INTERNAL_ERROR",
            str(e)
        )
