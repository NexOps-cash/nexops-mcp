from pydantic import BaseModel
from typing import Any, Optional, Dict, Literal

class MCPRequest(BaseModel):
    request_id: str
    action: str
    payload: Dict[str, Any]
    context: Optional[Dict[str, Any]] = None

class MCPResponse(BaseModel):
    request_id: str
    type: str # "success" | "error" | "skeleton" | "update" etc.
    data: Any
    error: Optional[Dict[str, Any]] = None
