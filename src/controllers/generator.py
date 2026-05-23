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


def _synthesis_flags(context: Optional[dict]) -> tuple[bool, bool]:
    """
    Align prod API with benchmark evaluator by default:
    free synthesis (no golden) and no secure fallback substitution.
    Opt out via context.benchmark_synthesis=false, or allow_fallback / use_golden.
    """
    ctx = context or {}
    if ctx.get("benchmark_synthesis") is False:
        return (
            bool(ctx.get("use_golden", False)),
            not bool(ctx.get("allow_fallback", True)),
        )
    disable_golden = not bool(ctx.get("use_golden", False))
    disable_fallbacks = not bool(ctx.get("allow_fallback", False))
    return disable_golden, disable_fallbacks


def _benchmark_stats_from_success(data: dict) -> dict:
    fallback_used = bool(data.get("fallback_used", False))
    return {
        "compile_pass": True,
        "converged": not fallback_used,
        "fallback_used": fallback_used,
        "attempt_number": data.get("attempt_number"),
        "generation_seconds": data.get("generation_seconds"),
        "compile_fix_count": data.get("compile_fix_count"),
        "disable_golden": True,
        "disable_fallbacks": True,
        "is_perfect_match": data.get("is_perfect_match"),
    }


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
        openrouter_key = req.context.get("openrouter_key") if req.context else None
        disable_golden, disable_fallbacks = _synthesis_flags(req.context)

        session = self.session_mgr.get_or_create(session_id)
        
        # Instantiate the Guarded Engine
        from src.services.pipeline_engine import get_guarded_pipeline_engine
        engine = get_guarded_pipeline_engine()

        # Run the Guarded Loop (benchmark parity: free synthesis, no fallback)
        result = await engine.generate_guarded(
            intent, 
            security_level, 
            on_update=on_update,
            api_key=api_key,
            provider=provider,
            openrouter_key=openrouter_key,
            disable_golden=disable_golden,
            disable_fallbacks=disable_fallbacks,
        )

        if result["type"] == "error":
            err = result.get("error") or {}
            return {
                "request_id": req.request_id,
                "type": "error",
                "error": err,
                "synthesis": {
                    "compile_pass": False,
                    "converged": False,
                    "fallback_used": False,
                    "disable_golden": disable_golden,
                    "disable_fallbacks": disable_fallbacks,
                    "failure_code": err.get("code"),
                },
            }

        data = result["data"]
        stats = _benchmark_stats_from_success(data)
        stats["disable_golden"] = disable_golden
        stats["disable_fallbacks"] = disable_fallbacks

        if stats["fallback_used"]:
            return {
                "request_id": req.request_id,
                "type": "error",
                "error": {
                    "code": "synthesis_fallback",
                    "message": "Pipeline returned fallback contract; benchmark mode treats this as failure.",
                },
                "synthesis": stats,
            }
        
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
                "intent_model": data.get("intent_model"),
                "fallback_used": stats["fallback_used"],
                "attempt_number": stats.get("attempt_number"),
                "generation_seconds": stats.get("generation_seconds"),
                "synthesis": stats,
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
