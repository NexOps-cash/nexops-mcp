"""
Generation Controller — Orchestrates the 3-phase pipeline.

Handles: generate (P1 → P2 → P3 → retry loop)
Does NOT handle: modify, audit (not yet implemented)
"""

import logging
from typing import Dict, Any, Optional

from src.models import MCPRequest, ContractIR, TollGateResult
from src.services.pipeline import Phase1, Phase2, Phase3, MAX_RETRIES
from src.services.session import get_session_manager

logger = logging.getLogger("nexops.generator")


class GenerationController:
    """Orchestrates the full generation pipeline with retry loop."""

    def __init__(self) -> None:
        self.session_mgr = get_session_manager()

    async def generate(self, req: MCPRequest, on_update: Optional[Any] = None) -> Dict[str, Any]:
        """
        Guarded Synthesis Pipeline Orchestration.
        Delegates to GuardedPipelineEngine for the 4-stage loop.
        """
        intent = req.payload.get("user_request", "")
        if not intent:
            return _error(req.request_id, "MISSING_INTENT", "payload.user_request is required")

        session_id = req.payload.get("session_id")
        security_level = req.context.get("security_level", "high") if req.context else "high"
        
        # BYOK Extraction
        api_key = req.context.get("api_key") if req.context else None
        provider = req.context.get("provider") if req.context else None

        session = self.session_mgr.get_or_create(session_id)
        
        # Instantiate the Guarded Engine
        from src.services.pipeline_engine import get_guarded_pipeline_engine
        engine = get_guarded_pipeline_engine()

        # Run the Guarded Loop
        result = await engine.generate_guarded(
            intent, 
            security_level, 
            on_update=on_update,
            api_key=api_key,
            provider=provider
        )

        if result["type"] == "error":
            return {
                "request_id": req.request_id,
                "type": "error",
                "error": result["error"]
            }

        data = result["data"]
        
        # Store in session (reconstruct dummy IR for backward compatibility if needed)
        # In a real system, we'd refactor session storage to be more flexible
        self.session_mgr.store_turn(
            session_id=session.session_id,
            intent=intent,
            contract_ir=ContractIR(), # Simplified for now
            final_code=data["code"],
            toll_gate_result=TollGateResult(**data["toll_gate"]),
        )

        return {
            "request_id": req.request_id,
            "type": "success",
            "data": {
                "stage": "complete",
                "code": data["code"],
                "contract_name": data["contract_name"],
                "session_id": session.session_id,
                "toll_gate": data["toll_gate"],
                "sanity_check": data.get("sanity_check"),
                "intent_model": data.get("intent_model")
            },
        }


# ─── Legacy wrapper for backward compatibility with router ────────────

_controller_instance: GenerationController | None = None


def _get_controller() -> GenerationController:
    global _controller_instance
    if _controller_instance is None:
        _controller_instance = GenerationController()
    return _controller_instance


async def generate_skeleton(req: MCPRequest, on_update: Optional[Any] = None) -> Dict[str, Any]:
    """Entry point called by router. Delegates to GenerationController."""
    controller = _get_controller()
    return await controller.generate(req, on_update=on_update)


# ─── Helpers ──────────────────────────────────────────────────────────

def _error(
    request_id: str,
    code: str,
    message: str,
    violations: list | None = None,
) -> Dict[str, Any]:
    """Build a standardized error response."""
    err: Dict[str, Any] = {"code": code, "message": message}
    if violations:
        err["violations"] = violations
    return {
        "request_id": request_id,
        "type": "error",
        "error": err,
    }
