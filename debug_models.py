from pydantic import ValidationError
from src.models import RepairRequest, AuditIssue, Severity

sample_issue_json = {
    "title": "DSL Structure Warning (LNC-014)",
    "severity": "HIGH",
    "line": 5,
    "description": "Function 'increment' validates tokenCategory but not tokenAmount.",
    "recommendation": "Adhere to NexOps CashScript DSL conventions.",
    "rule_id": "LNC-014",
    "can_fix": True
}

sample_request_json = {
    "original_code": "pragma cashscript ^0.10.0; contract Test() { ... }",
    "issue": sample_issue_json,
    "context": {}
}

try:
    req = RepairRequest(**sample_request_json)
    print("RepairRequest validation SUCCESSFUL")
    print(f"Severity type: {type(req.issue.severity)}")
    print(f"Severity value: {req.issue.severity}")
except ValidationError as e:
    print("RepairRequest validation FAILED")
    print(e.json())

# Test with invalid severity case
sample_issue_json["severity"] = "high" # lowercase
try:
    req = RepairRequest(**sample_request_json)
    print("RepairRequest (lowercase severity) SUCCESSFUL")
except ValidationError as e:
    print("RepairRequest (lowercase severity) FAILED (as expected)")
    # print(e.json())
