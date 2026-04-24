import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.models import AuditIssue, ExploitSeverity, IssueClass, Severity
from src.services.anti_pattern_detectors import AuthorizationModelClassifierDetector, IndexUnderflowDetector
from src.services.audit_agent import AuditAgent
from src.services.scoring import calculate_audit_report
from src.utils.cashscript_ast import CashScriptAST


@pytest.fixture
def anyio_backend():
    return "asyncio"


def _mock_provider(payload: dict):
    provider = MagicMock()
    provider.complete = AsyncMock(return_value=json.dumps(payload))
    return provider


def _compile_ok(_code):
    return {"success": True}


def _compile_unknown_error(_code):
    return {"success": False, "error": {"type": "UnknownError", "raw": "sourceTags is not iterable"}}


def _lint_ok(_code, contract_mode=""):
    return {"passed": True, "violations": []}


def _toll_gate_ok(_code):
    r = MagicMock()
    r.passed = True
    r.violations = []
    r.structural_score = 1.0
    return r


@pytest.mark.anyio
async def test_semantic_exploit_low_confidence_downgrades_issue_class():
    payload = {
        "category": "EXPLOIT",
        "exploit_severity": "direct_fund_loss",
        "explanation": "Critical invariant can be bypassed.",
        "confidence": 0.40,
        "business_logic_score": 3,
        "business_logic_notes": "Review authorization gates.",
    }

    with patch("src.services.llm.factory.LLMFactory.get_provider", return_value=_mock_provider(payload)), \
         patch("src.services.audit_agent.get_compiler_service", return_value=MagicMock(compile=_compile_ok)), \
         patch("src.services.audit_agent.get_dsl_linter", return_value=MagicMock(lint=_lint_ok)), \
         patch("src.services.audit_agent.Phase3.validate", side_effect=_toll_gate_ok):
        report = await AuditAgent.audit("pragma cashscript ^0.13.0; contract T(){}")

    semantic_issue = next(i for i in report.issues if i.rule_id.startswith("semantic_"))
    assert report.semantic_category == "major_protocol_flaw"
    assert semantic_issue.issue_class == IssueClass.CONTEXTUAL
    assert semantic_issue.exploit_severity == ExploitSeverity.DIRECT_FUND_LOSS
    assert report.metadata.semantic_confidence == pytest.approx(0.40, abs=1e-9)


@pytest.mark.anyio
async def test_semantic_assumption_sets_deferred_validation():
    payload = {
        "category": "ASSUMPTION",
        "exploit_severity": "n/a",
        "explanation": "Validation deferred to peer manager contract.",
        "confidence": 0.92,
        "business_logic_score": 6,
        "business_logic_notes": "Cross-contract dependency required.",
    }

    with patch("src.services.llm.factory.LLMFactory.get_provider", return_value=_mock_provider(payload)), \
         patch("src.services.audit_agent.get_compiler_service", return_value=MagicMock(compile=_compile_ok)), \
         patch("src.services.audit_agent.get_dsl_linter", return_value=MagicMock(lint=_lint_ok)), \
         patch("src.services.audit_agent.Phase3.validate", side_effect=_toll_gate_ok):
        report = await AuditAgent.audit("pragma cashscript ^0.13.0; contract T(){}")

    semantic_issue = next(i for i in report.issues if i.rule_id.startswith("semantic_"))
    assert report.semantic_category == "minor_design_risk"
    assert semantic_issue.issue_class == IssueClass.CONTEXTUAL
    assert semantic_issue.deferred_validation is True
    assert semantic_issue.exploit_severity == ExploitSeverity.NOT_APPLICABLE


def test_authorization_classifier_contextual_when_value_controlled():
    code = """
    contract A() {
        function spend() {
            require(tx.outputs[0].tokenCategory == tx.inputs[this.activeInputIndex].tokenCategory);
            require(tx.outputs[0].tokenAmount > 0);
        }
    }
    """
    ast = CashScriptAST(code)
    violation = AuthorizationModelClassifierDetector().detect(ast)
    assert violation is not None
    assert violation.rule == "authorization_model_classifier"
    assert violation.severity == "medium"
    assert violation.issue_class == "contextual"
    assert violation.exploit_severity == "griefing"


def test_index_underflow_detector_marks_griefing():
    code = """
    contract V() {
        function spend() {
            int prev = this.activeInputIndex - 1;
            require(tx.inputs[prev].value > 0);
        }
    }
    """
    ast = CashScriptAST(code)
    violation = IndexUnderflowDetector().detect(ast)
    assert violation is not None
    assert violation.rule == "index_underflow"
    assert violation.exploit_severity == "griefing"
    assert violation.severity == "medium"


def test_scoring_skips_deferred_validation_penalties():
    deferred_issue = AuditIssue(
        title="Deferred check",
        severity=Severity.HIGH,
        line=1,
        description="Handled by peer contract.",
        recommendation="Document dependency.",
        rule_id="missing_output_limit",
        can_fix=False,
        issue_class=IssueClass.REAL_ISSUE,
        exploit_severity=ExploitSeverity.DIRECT_FUND_LOSS,
        deferred_validation=True,
    )

    report = calculate_audit_report(
        issues=[deferred_issue],
        compile_success=True,
        dsl_passed=True,
        structural_score=1.0,
        semantic_category="none",
        business_logic_score=10,
        semantic_confidence=None,
        original_code="contract T(){}",
    )

    assert report.deterministic_score == 70
    assert report.total_score == 100


@pytest.mark.anyio
async def test_compile_unknown_error_is_tagged_toolchain():
    with patch("src.services.audit_agent.get_compiler_service", return_value=MagicMock(compile=_compile_unknown_error)), \
         patch("src.services.audit_agent.get_dsl_linter", return_value=MagicMock(lint=_lint_ok)), \
         patch("src.services.audit_agent.Phase3.validate", side_effect=_toll_gate_ok):
        report = await AuditAgent.audit("pragma cashscript ^0.13.0; contract T(){}")

    compile_issue = next(i for i in report.issues if i.rule_id == "compile_unknown_error")
    assert compile_issue.source == "toolchain"
    assert compile_issue.severity == Severity.HIGH
    assert compile_issue.issue_class == IssueClass.CONTEXTUAL
