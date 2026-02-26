from pydantic import BaseModel, Field
from typing import Any, Optional, Dict, List
from datetime import datetime
from enum import Enum


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


# ─── Intent Model (Phase 1 Output) ──────────────────────────────────

class IntentModel(BaseModel):
    contract_type: str = "generic"
    features: List[str] = Field(default_factory=list)
    signers: List[str] = Field(default_factory=list)
    threshold: Optional[int] = None
    timeout_days: Optional[int] = None
    token_id: Optional[str] = None
    purpose: str = ""

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
    intent_model: Optional[IntentModel] = None
    security_level: str = "high"
    generation_phase: int = 0
    effective_mode: str = ""
    retry_count: int = 0
    compile_fix_count: int = 0
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

# ─── Phase AR (Audit & Repair) Models ────────────────────────────────

class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

class AuditIssue(BaseModel):
    title: str
    severity: Severity
    line: int
    description: str
    recommendation: str
    rule_id: str
    can_fix: bool = True

class AuditMetadata(BaseModel):
    compile_success: bool
    dsl_passed: bool
    structural_score: float
    semantic_score: Optional[int] = None
    contract_hash: str

class SemanticAuditResult(BaseModel):
    category: str
    explanation: str
    confidence: float

class AuditReport(BaseModel):
    deterministic_score: int
    semantic_score: int
    total_score: int
    risk_level: str  # CRITICAL, HIGH, MEDIUM, LOW, SAFE
    semantic_category: str
    deployment_allowed: bool
    issues: List[AuditIssue] = Field(default_factory=list)
    total_high: int = 0
    total_medium: int = 0
    total_low: int = 0
    metadata: AuditMetadata

class AuditRequest(BaseModel):
    code: str
    effective_mode: str = ""
    intent: str = ""  # Optional: declared intent for semantic logic audit
    context: Optional[Dict[str, Any]] = Field(default_factory=dict)

class RepairRequest(BaseModel):
    original_code: str
    issue: AuditIssue
    context: Optional[Dict[str, Any]] = Field(default_factory=dict)

class RepairResponse(BaseModel):
    corrected_code: str
    new_report: Optional[AuditReport] = None  # Not populated during repair; user audits after
    success: bool

class EditRequest(BaseModel):
    original_code: str
    instruction: str
    effective_mode: str = ""
    context: Optional[Dict[str, Any]] = Field(default_factory=dict)

class EditResponse(BaseModel):
    edited_code: str
    success: bool
    new_report: AuditReport
