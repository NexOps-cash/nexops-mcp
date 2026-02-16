"""
Generation Controller — Orchestrates the 3-phase pipeline.

Handles: generate (P1 → P2 → P3 → retry loop)
Does NOT handle: modify, audit (not yet implemented)
"""

import logging
from typing import Dict, Any

from src.models import MCPRequest, ContractIR, TollGateResult
from src.services.pipeline import Phase1, Phase2, Phase3, MAX_RETRIES
from src.services.session import get_session_manager

logger = logging.getLogger("nexops.generator")


class GenerationController:
    """Orchestrates the full generation pipeline with retry loop."""

    def __init__(self) -> None:
        self.session_mgr = get_session_manager()

    async def generate(self, req: MCPRequest) -> Dict[str, Any]:
        """
        Full 3-phase generation pipeline.

        1. Phase 1 — LLM produces ContractIR skeleton
        2. Phase 2 — LLM fills business logic → .cash code
        3. Phase 3 — Deterministic toll gate validates code
        4. Retry loop — If P3 fails, re-run P2 with violation context (max 3)
        5. Store valid result in session

        The user NEVER sees rejected intermediate outputs.
        """
        intent = req.payload.get("user_request", "")
        if not intent:
            return _error(req.request_id, "MISSING_INTENT", "payload.user_request is required")

        session_id = req.payload.get("session_id")
        security_level = "high"
        if req.context:
            security_level = req.context.get("security_level", "high")

        session = self.session_mgr.get_or_create(session_id)

        # ── Phase 1: Skeleton ──────────────────────────────────────
        try:
            ir = await Phase1.run(intent, security_level)
        except Exception as e:
            logger.error(f"Phase 1 failed: {e}")
            return _error(req.request_id, "PHASE1_FAILED", str(e))

        # ── Phase 2 + Phase 3 with retry loop ─────────────────────
        code = ""
        toll_gate: TollGateResult = TollGateResult(passed=False)
        violations = None

        for attempt in range(MAX_RETRIES):
            # Phase 2: Logic Fill
            try:
                code = await Phase2.run(
                    ir=ir,
                    violations=violations,
                    retry_count=attempt,
                )
            except Exception as e:
                logger.error(f"Phase 2 failed (attempt {attempt + 1}): {e}")
                if attempt == MAX_RETRIES - 1:
                    return _error(req.request_id, "PHASE2_FAILED", str(e))
                continue

            # Phase 3: Toll Gate
            toll_gate = Phase3.validate(code)

            if toll_gate.passed:
                logger.info(f"Toll gate PASSED on attempt {attempt + 1}")
                break

            # Toll gate failed — prepare for retry
            logger.warning(
                f"Toll gate FAILED (attempt {attempt + 1}/{MAX_RETRIES}): "
                f"{len(toll_gate.violations)} violations"
            )
            violations = toll_gate.violations

        # ── Final result ──────────────────────────────────────────
        if not toll_gate.passed:
            # All retries exhausted — return structured error
            return _error(
                req.request_id,
                "TOLL_GATE_FAILED",
                f"Contract failed validation after {MAX_RETRIES} attempts",
                violations=[v.model_dump() for v in toll_gate.violations],
            )

        # Store in session
        self.session_mgr.store_turn(
            session_id=session.session_id,
            intent=intent,
            contract_ir=ir,
            final_code=code,
            toll_gate_result=toll_gate,
        )

        return {
            "request_id": req.request_id,
            "type": "success",
            "data": {
                "stage": "complete",
                "code": code,
                "contract_name": ir.contract_name,
                "session_id": session.session_id,
                "toll_gate": {
                    "passed": True,
                    "structural_score": toll_gate.structural_score,
                },
            },
        }


# ─── Legacy wrapper for backward compatibility with router ────────────

_controller_instance: GenerationController | None = None


def _get_controller() -> GenerationController:
    global _controller_instance
    if _controller_instance is None:
        _controller_instance = GenerationController()
    return _controller_instance


async def generate_skeleton(req: MCPRequest) -> Dict[str, Any]:
    """Entry point called by router. Delegates to GenerationController."""
    controller = _get_controller()
    return await controller.generate(req)


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
