from typing import Any, Dict

def error_response(request_id: str, code: str, message: str) -> Dict[str, Any]:
    return {
        "request_id": request_id,
        "type": "error",
        "data": None, # Explicitly null for error responses
        "error": {
            "code": code,
            "message": message
        }
    }
