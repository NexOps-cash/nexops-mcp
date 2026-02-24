import hashlib
from typing import List, Dict, Any
from src.models import (
    AuditIssue, 
    AuditReport, 
    AuditMetadata, 
    Severity
)

# Penalty weights
PENALTIES = {
    Severity.CRITICAL: 20, # Treat critical syntax errors effectively as HIGH
    Severity.HIGH: 20,
    Severity.MEDIUM: 10,
    Severity.LOW: 5,
    Severity.INFO: 0
}

def calculate_audit_report(
    issues: List[AuditIssue],
    compile_success: bool,
    dsl_passed: bool,
    structural_score: float,
    original_code: str
) -> AuditReport:
    """
    Simulates the full validation stack scoring logic.
    1. Deduplicates issues by rule_id.
    2. Calculates penalties.
    3. Determines risk level.
    """
    
    # Generate contract hash for state snapshot/tracking
    contract_hash = hashlib.sha256(original_code.encode("utf-8")).hexdigest()
    
    # Deduplicate issues by rule_id (keep the first occurrence/highest severity ideally, 
    # but since rule_id maps to a specific concept, any instance suffices to flag the conceptual flaw)
    unique_issues_map = {}
    for issue in issues:
        if issue.rule_id not in unique_issues_map:
            unique_issues_map[issue.rule_id] = issue
        else:
            # If we see the same rule_id, prioritize the higher severity if they differ
            existing_severity = PENALTIES.get(unique_issues_map[issue.rule_id].severity, 0)
            new_severity = PENALTIES.get(issue.severity, 0)
            if new_severity > existing_severity:
                unique_issues_map[issue.rule_id] = issue
                
    deduped_issues = list(unique_issues_map.values())
    
    # Calculate counts
    total_high = sum(1 for i in deduped_issues if i.severity in [Severity.HIGH, Severity.CRITICAL])
    total_medium = sum(1 for i in deduped_issues if i.severity == Severity.MEDIUM)
    total_low = sum(1 for i in deduped_issues if i.severity == Severity.LOW)
    
    # Calculate score
    total_penalty = sum(PENALTIES.get(i.severity, 0) for i in deduped_issues)
    score = max(0, 100 - total_penalty)
    
    # Determine risk level
    if total_high >= 2:
        risk_level = "CRITICAL"
    elif total_high == 1 or score < 60:
        risk_level = "HIGH"
    elif score < 80:
        risk_level = "MEDIUM"
    elif score < 100:
        risk_level = "LOW"
    else:
        risk_level = "SAFE"
        
    metadata = AuditMetadata(
        compile_success=compile_success,
        dsl_passed=dsl_passed,
        structural_score=structural_score,
        contract_hash=contract_hash
    )
    
    return AuditReport(
        score=score,
        risk_level=risk_level,
        issues=deduped_issues,
        total_high=total_high,
        total_medium=total_medium,
        total_low=total_low,
        metadata=metadata
    )
