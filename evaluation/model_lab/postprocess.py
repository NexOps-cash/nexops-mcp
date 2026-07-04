from __future__ import annotations

import json
from typing import Any, Optional

from src.services.audit_agent import AuditAgent
from src.services.compiler import CompilerService

from .schemas import CompileResult


def run_compile(extracted_code: str) -> CompileResult:
    if not extracted_code.strip():
        return CompileResult(
            compile_success=False,
            compile_error={"type": "EmptyCode", "raw": "extracted contract is empty"},
            toolchain_error=False,
        )
    result = CompilerService.compile(extracted_code)
    err = result.get("error")
    compile_error: Optional[Any] = err
    if isinstance(err, dict) and err.get("raw"):
        compile_error = err
    elif err and not isinstance(err, dict):
        compile_error = {"raw": str(err)}
    return CompileResult(
        compile_success=bool(result.get("success")),
        compile_error=compile_error if not result.get("success") else None,
        toolchain_error=bool(result.get("toolchain_error", False)),
    )


async def run_audit(
    extracted_code: str,
    *,
    intent: str,
    effective_mode: str = "",
) -> dict[str, Any]:
    report = await AuditAgent.audit(
        extracted_code,
        intent=intent,
        effective_mode=effective_mode,
    )
    return report.model_dump()
