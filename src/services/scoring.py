import hashlib
from typing import List, Optional
from src.models import (
    AuditIssue,
    AuditReport,
    AuditMetadata,
    Severity
)

# ── Deterministic Bucket (0-70) ─────────────────────────────────────────────
# Penalty deductions applied to the deterministic 70-point bucket.
DET_PENALTIES: dict = {
    Severity.CRITICAL: 20,
    Severity.HIGH: 10,
    Severity.MEDIUM: 5,
    Severity.LOW: 2,
    Severity.INFO: 0,
}

# Maximum score for the deterministic bucket.
DET_MAX = 70

# ── Semantic Bucket (0-30) ──────────────────────────────────────────────────
# Maps the 5 allowed LLM classification categories to a point value.
SEMANTIC_CATEGORY_MAP: dict = {
    "none": 30,
    "minor_design_risk": 25,
    "moderate_logic_risk": 20,
    "major_protocol_flaw": 10,
    "funds_unspendable": 0,
}

ALLOWED_CATEGORIES = set(SEMANTIC_CATEGORY_MAP.keys())

# ── Minimum display floor ───────────────────────────────────────────────────
DISPLAY_FLOOR = 20


def calculate_audit_report(
    issues: List[AuditIssue],
    compile_success: bool,
    dsl_passed: bool,
    structural_score: float,
    semantic_category: str,
    original_code: str,
) -> AuditReport:
    """
    Hybrid Scoring v2: 70/30 structured bucket system.

    Deterministic (0-70):
        • Driven ONLY by: compile errors, DSL lint, anti-patterns, structural invariants.
        • Deductions per severity: CRITICAL→-20, HIGH→-10, MEDIUM→-5, LOW→-2, INFO→0.
        • If compile fails → det_score = 0 immediately.

    Semantic (0-30):
        • Driven ONLY by the LLM classification category.
        • Allowed categories: none, minor_design_risk, moderate_logic_risk,
          major_protocol_flaw, funds_unspendable.
        • Unknown or missing categories → treated as "none" (30 pts).

    Final:
        total_score   = det_score + semantic_score
        display_score = max(20, total_score)

    Deployment gate:
        det_score >= 50 AND semantic_score > 0 AND display_score >= 75
    """

    # ── Generate contract fingerprint ─────────────────────────────────────
    contract_hash = hashlib.sha256(original_code.encode("utf-8")).hexdigest()

    # ── Deduplicate issues by rule_id (keep highest-severity instance) ────
    unique_issues_map: dict = {}
    for issue in issues:
        if issue.rule_id not in unique_issues_map:
            unique_issues_map[issue.rule_id] = issue
        else:
            existing_penalty = DET_PENALTIES.get(unique_issues_map[issue.rule_id].severity, 0)
            new_penalty = DET_PENALTIES.get(issue.severity, 0)
            if new_penalty > existing_penalty:
                unique_issues_map[issue.rule_id] = issue

    deduped_issues = list(unique_issues_map.values())

    # ── Count by severity band ─────────────────────────────────────────────
    total_high = sum(
        1 for i in deduped_issues if i.severity in (Severity.HIGH, Severity.CRITICAL)
    )
    total_medium = sum(1 for i in deduped_issues if i.severity == Severity.MEDIUM)
    total_low = sum(1 for i in deduped_issues if i.severity == Severity.LOW)

    # ── Deterministic score ────────────────────────────────────────────────
    if not compile_success:
        # Hard failure: deterministic bucket collapses to 0.
        det_score = 0
    else:
        total_deductions = sum(DET_PENALTIES.get(i.severity, 0) for i in deduped_issues)
        det_score = max(0, DET_MAX - total_deductions)

    # ── Semantic score ─────────────────────────────────────────────────────
    # Normalise the category; fall back to "none" for unknown values.
    normalised_category = semantic_category.strip().lower() if semantic_category else "none"
    if normalised_category not in ALLOWED_CATEGORIES:
        normalised_category = "none"

    semantic_score = SEMANTIC_CATEGORY_MAP[normalised_category]

    # ── Final / display score ──────────────────────────────────────────────
    total_score = det_score + semantic_score
    display_score = max(DISPLAY_FLOOR, total_score)

    # ── Deployment gate ────────────────────────────────────────────────────
    # semantic_score == 0 means "funds_unspendable" → always blocks deployment.
    deployment_allowed = bool(
        det_score >= 50
        and semantic_score > 0
        and display_score >= 75
    )

    # ── Risk level (based on display_score) ───────────────────────────────
    if display_score >= 90:
        risk_level = "SAFE"
    elif display_score >= 75:
        risk_level = "LOW"
    elif display_score >= 60:
        risk_level = "MEDIUM"
    elif display_score >= 40:
        risk_level = "HIGH"
    else:
        risk_level = "CRITICAL"

    # ── Build metadata ─────────────────────────────────────────────────────
    metadata = AuditMetadata(
        compile_success=compile_success,
        dsl_passed=dsl_passed,
        structural_score=structural_score,
        semantic_score=semantic_score,   # stores the 0/10/20/25/30 int value
        contract_hash=contract_hash,
    )

    return AuditReport(
        deterministic_score=det_score,
        semantic_score=semantic_score,
        total_score=display_score,          # display_score is what the UI shows
        risk_level=risk_level,
        semantic_category=normalised_category,
        deployment_allowed=deployment_allowed,
        issues=deduped_issues,
        total_high=total_high,
        total_medium=total_medium,
        total_low=total_low,
        metadata=metadata,
    )
