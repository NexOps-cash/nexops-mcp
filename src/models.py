from pydantic import BaseModel, Field
from typing import Any, Optional, Dict, List
from datetime import datetime


# ─── MCP Protocol Models ─────────────────────────────────────────────

class MCPRequest(BaseModel):
    request_id: str
    action: str
    payload: Dict[str, Any]
    context: Optional[Dict[str, Any]] = None


class MCPResponse(BaseModel):
    request_id: str
    type: str  # "success" | "error" | "skeleton" | "update"
    data: Any
    error: Optional[Dict[str, Any]] = None


# ─── Contract IR (Intermediate Representation) ───────────────────────

class ParamIR(BaseModel):
    name: str
    type: str
    purpose: str = ""


class FunctionIR(BaseModel):
    name: str
    params: List[ParamIR] = Field(default_factory=list)
    visibility: str = "public"
    structural_guards: List[str] = Field(default_factory=list)
    business_logic: List[str] = Field(default_factory=list)
    primitives_used: List[str] = Field(default_factory=list)
    requires: List[str] = Field(default_factory=list)


class StateIR(BaseModel):
    is_stateful: bool = False
    state_fields: List[ParamIR] = Field(default_factory=list)
    continuation_required: bool = False


class ContractMetadata(BaseModel):
    intent: str = ""
    security_level: str = "high"
    generation_phase: int = 0
    retry_count: int = 0
    kb_categories_used: List[str] = Field(default_factory=list)
    timestamp: str = Field(default_factory=lambda: datetime.utcnow().isoformat())


class ContractIR(BaseModel):
    contract_name: str = ""
    pragma: str = "cashscript ^0.10.0"
    constructor_params: List[ParamIR] = Field(default_factory=list)
    functions: List[FunctionIR] = Field(default_factory=list)
    state: StateIR = Field(default_factory=StateIR)
    metadata: ContractMetadata = Field(default_factory=ContractMetadata)


# ─── Toll Gate Result ─────────────────────────────────────────────────

class ViolationDetail(BaseModel):
    rule: str
    reason: str
    exploit: str = ""
    location: Dict[str, Any] = Field(default_factory=dict)
    severity: str = "critical"
    fix_hint: str = ""


class TollGateResult(BaseModel):
    passed: bool
    violations: List[ViolationDetail] = Field(default_factory=list)
    hallucination_flags: List[str] = Field(default_factory=list)
    structural_score: float = 1.0


# ─── Session State ────────────────────────────────────────────────────

class TurnRecord(BaseModel):
    turn: int
    intent: str
    contract_ir: ContractIR
    final_code: str = ""
    toll_gate_result: Optional[TollGateResult] = None
    timestamp: str = Field(default_factory=lambda: datetime.utcnow().isoformat())


class SessionState(BaseModel):
    session_id: str
    created_at: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
    history: List[TurnRecord] = Field(default_factory=list)
    current_contract: Optional[ContractIR] = None
    current_code: str = ""
