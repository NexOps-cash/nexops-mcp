import hashlib
from typing import List, Optional
from src.models import (
    AuditIssue,
    AuditReport,
    AuditMetadata,
    Severity,
    IssueClass,
    ExploitSeverity,
)

# ── Deterministic Bucket (0-70) ─────────────────────────────────────────────
DET_PENALTIES: dict = {
    Severity.CRITICAL: 20,
    Severity.HIGH: 10,
    Severity.MEDIUM: 5,
    Severity.LOW: 2,
    Severity.INFO: 0,
}
DET_MAX = 70

# When cashc crashes with a known toolchain error (not a contract defect), do not
# zero the deterministic bucket — avoids misleading CRITICAL scores.
TOOLCHAIN_NEUTRAL_DET_SCORE = 40

# ── Semantic Bucket (0-30) — split into two sub-components ─────────────────
#
#   Structured category  (0-20 pts): machine-determined from 5 enum values.
#   Business logic score (0-10 pts): free-form AI assessment (race conditions,
#       multi-party fairness gaps, edge-case handling, etc.).
#
#   semantic_score = min(30, category_pts + business_logic_score)
#   Exception: "funds_unspendable" forces semantic_score = 0 unconditionally.
#
SEMANTIC_CATEGORY_MAP: dict = {
    "none":                20,
    "minor_design_risk":   15,
    "moderate_logic_risk": 10,
    "major_protocol_flaw":  5,
    "funds_unspendable":    0,
}

ALLOWED_CATEGORIES = set(SEMANTIC_CATEGORY_MAP.keys())

# ── Display floor ────────────────────────────────────────────────────────────
DISPLAY_FLOOR = 20


def calculate_audit_report(
    issues: List[AuditIssue],
    compile_success: bool,
    dsl_passed: bool,
    structural_score: float,
    semantic_category: str,
    business_logic_score: int,        # 0-10, free-form AI assessment
    semantic_confidence: Optional[float],
    original_code: str,
    compile_toolchain_error: bool = False,
) -> AuditReport:
    """
    Hybrid Scoring v2 (revised semantic split):

    Deterministic (0-70):
        Deductions per severity: CRITICAL→-20, HIGH→-10, MEDIUM→-5, LOW→-2, INFO→0.
        If compile fails → det_score = 0, except compile_toolchain_error (cashc crash) →
        det_score = TOOLCHAIN_NEUTRAL_DET_SCORE (not a contract syntax failure).

    Semantic (0-30):
        Structured category (0-20):
            none→20, minor_design_risk→15, moderate_logic_risk→10,
            major_protocol_flaw→5, funds_unspendable→0.
        Free-form AI business logic (0-10):
            Race conditions, multi-party fairness, edge cases, etc.
        Combined: min(30, category_pts + business_logic_score)
        If category == "funds_unspendable" → semantic_score = 0 (unconditional).

    Final:
        total_score   = det_score + semantic_score
        display_score = max(20, total_score)

    Deployment gate:
        det_score >= 50 AND semantic_score > 0 AND display_score >= 75
    """

    contract_hash = hashlib.sha256(original_code.encode("utf-8")).hexdigest()

    # ── Deduplicate by rule_id (keep highest-penalty instance) ───────────
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

    # ── Severity counts ──────────────────────────────────────────────────
    total_high = sum(
        1 for i in deduped_issues if i.severity in (Severity.HIGH, Severity.CRITICAL)
    )
    total_medium = sum(1 for i in deduped_issues if i.severity == Severity.MEDIUM)
    total_low = sum(1 for i in deduped_issues if i.severity == Severity.LOW)

    def _class_multiplier(issue: AuditIssue) -> float:
        if issue.issue_class == IssueClass.REAL_ISSUE:
            return 1.0
        if issue.issue_class == IssueClass.CONTEXTUAL:
            return 0.5
        return 0.0

    def _severity_multiplier(issue: AuditIssue) -> float:
        if issue.issue_class != IssueClass.REAL_ISSUE:
            return 1.0
        if issue.exploit_severity == ExploitSeverity.DIRECT_FUND_LOSS:
            return 1.0
        if issue.exploit_severity == ExploitSeverity.PARTIAL_VIOLATION:
            return 0.7
        if issue.exploit_severity == ExploitSeverity.GRIEFING:
            return 0.3
        return 1.0

    def _effective_penalty(issue: AuditIssue) -> int:
        if issue.rule_id.startswith("semantic_"):
            # Semantic findings are accounted for in the semantic bucket, not deterministic.
            return 0
        if issue.deferred_validation:
            return 0
        base = DET_PENALTIES.get(issue.severity, 0)
        penalty = base * _class_multiplier(issue) * _severity_multiplier(issue)
        return int(round(penalty))

    # ── Deterministic score ──────────────────────────────────────────────
    if not compile_success:
        if compile_toolchain_error:
            # cashc/Node internal failure — not treated as a blank compile failure
            det_score = TOOLCHAIN_NEUTRAL_DET_SCORE
        else:
            det_score = 0
    else:
        total_deductions = sum(_effective_penalty(i) for i in deduped_issues)
        det_score = max(0, DET_MAX - total_deductions)

    # ── Semantic score ───────────────────────────────────────────────────
    normalised_category = semantic_category.strip().lower() if semantic_category else "none"
    if normalised_category not in ALLOWED_CATEGORIES:
        normalised_category = "none"

    if normalised_category == "funds_unspendable":
        # Hard override — permanent deadlock forces semantic to zero.
        semantic_score = 0
    else:
        category_pts = SEMANTIC_CATEGORY_MAP[normalised_category]
        biz_pts = max(0, min(10, int(business_logic_score)))  # clamp to [0, 10]
        semantic_score = min(30, category_pts + biz_pts)

    # ── Final / display score ────────────────────────────────────────────
    total_score = det_score + semantic_score
    display_score = max(DISPLAY_FLOOR, total_score)

    # ── Deployment gate ──────────────────────────────────────────────────
    deployment_allowed = bool(
        det_score >= 50
        and semantic_score > 0
        and display_score >= 75
    )

    # ── Risk level (from display_score) ─────────────────────────────────
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

    metadata = AuditMetadata(
        compile_success=compile_success,
        dsl_passed=dsl_passed,
        structural_score=structural_score,
        semantic_score=semantic_score,
        semantic_confidence=semantic_confidence,
        contract_hash=contract_hash,
    )

    return AuditReport(
        deterministic_score=det_score,
        semantic_score=semantic_score,
        total_score=display_score,
        risk_level=risk_level,
        semantic_category=normalised_category,
        deployment_allowed=deployment_allowed,
        issues=deduped_issues,
        total_high=total_high,
        total_medium=total_medium,
        total_low=total_low,
        metadata=metadata,
    )
