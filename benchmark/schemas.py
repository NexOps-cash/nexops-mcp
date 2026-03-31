from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from datetime import datetime

class BenchmarkCase(BaseModel):
    id: str
    pattern: str
    difficulty: str
    intent: str
    max_retries: int = 3
    required_features: List[str] = []
    critical_features: List[str] = []
    expected_structure: Dict[str, Any] = {}
    behavior_tests: Dict[str, str] = {}
    tags: List[str] = []
    suite_version: Optional[str] = "1.0"
    created_by: Optional[str] = "unknown"
    date: Optional[str] = None

class CaseResult(BaseModel):
    id: str
    pattern: str
    difficulty: str
    compile_pass: bool
    lint_errors: int
    lint_warnings: int
    lint_factor: float
    structure_score: float
    adj_structure_score: float
    required_features: List[str]
    detected_features: List[str]
    missing_features: List[str]
    extraneous_features: List[str] = []
    hallucinated_features: List[str]
    intent_coverage: float
    final_score: float
    
    # Latency & Cost
    latency_seconds: float
    tokens_prompt: int = 0
    tokens_completion: int = 0
    cost_usd: float = 0.0
    
    # Trace
    first_pass_attempt: Optional[int] = None
    retries_used: int
    max_retries: int
    converged: bool
    fallback_used: bool = False
    failure_layer: Optional[str] = None
    elapsed_seconds: float
    code: Optional[str] = None
    timestamp: str = Field(default_factory=lambda: datetime.now().isoformat())

class PatternSummary(BaseModel):
    pattern: str
    count: int
    compile_rate: float
    convergence_rate: float
    avg_intent_coverage: float
    avg_final_score: float
    avg_retries: float

class DifficultySummary(BaseModel):
    difficulty: str
    count: int
    compile_rate: float
    avg_intent_coverage: float
    avg_final_score: float

class BenchmarkReport(BaseModel):
    run_id: str
    dataset_hash: str
    suite_version: str
    total_cases: int
    start_time: str
    end_time: str
    elapsed_total_seconds: float
    
    # Results
    results: List[CaseResult]
    
    # Aggregates
    pattern_summaries: List[PatternSummary]
    difficulty_summaries: List[DifficultySummary]
    
    # Global Metrics
    avg_latency: float
    total_tokens_prompt: int
    total_tokens_completion: int
    total_cost_usd: float
    avg_final_score: float = 0.0
    
    # Configuration Used
    model_name: Optional[str] = None
    model_version: Optional[str] = None
