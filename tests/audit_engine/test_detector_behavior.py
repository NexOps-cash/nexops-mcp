from src.services.audit_engine.audit_detectors import (
    AuthorizationModelClassifierDetector,
    CommitmentLengthSafetyDetector,
    IndexUnderflowDetector,
)
from src.services.audit_engine.invariant_engine import should_skip_commitment_rule_for_body
from src.utils.cashscript_ast import CashScriptAST


def test_index_underflow_detected():
    code = """
    contract C() {
        function spend() {
            require(tx.inputs[this.activeInputIndex - 1].value > 0);
        }
    }
    """
    assert IndexUnderflowDetector().detect(CashScriptAST(code), None) is not None


def test_index_underflow_greater_zero_safe_for_minus_one():
    code = """
    contract C() {
        function spend() {
            require(this.activeInputIndex > 0);
            require(tx.inputs[this.activeInputIndex - 1].value > 0);
        }
    }
    """
    assert IndexUnderflowDetector().detect(CashScriptAST(code), None) is None


def test_index_underflow_skips_intentional_zero_path():
    code = """
    contract C() {
        function onlyAtZero() {
            require(this.activeInputIndex == 0);
            require(tx.inputs[this.activeInputIndex - 1].value > 0);
        }
    }
    """
    assert IndexUnderflowDetector().detect(CashScriptAST(code), None) is None


def test_commitment_length_skip_requires_buffer_or_tuple_length():
    assert should_skip_commitment_rule_for_body(
        "bytes a, bytes b = c.split(32); require(a == 0x00);"
    ) is False
    assert should_skip_commitment_rule_for_body(
        "bytes a, bytes b = c.split(32); require(c.length >= 32);"
    ) is True


def test_index_underflow_guarded():
    code = """
    contract C() {
        function spend() {
            require(this.activeInputIndex >= 1);
            require(tx.inputs[this.activeInputIndex - 1].value > 0);
        }
    }
    """
    assert IndexUnderflowDetector().detect(CashScriptAST(code), None) is None


def test_commitment_requires_length():
    code = """
    contract C() {
        function spend() {
            bytes commitment = tx.outputs[0].nftCommitment;
            require(tx.outputs.length == 1);
            bytes left, bytes right = commitment.split(32);
        }
    }
    """
    assert CommitmentLengthSafetyDetector().detect(CashScriptAST(code), None) is not None


def test_commitment_with_length_guard_is_safe():
    code = """
    contract C() {
        function spend() {
            bytes commitment = tx.outputs[0].nftCommitment;
            require(commitment.length >= 32);
            bytes left, bytes right = commitment.split(32);
            require(left != 0x);
        }
    }
    """
    assert CommitmentLengthSafetyDetector().detect(CashScriptAST(code), None) is None


def test_authorization_classifier_never_escalates():
    code = """
    contract C(bytes32 authorization) {
        function spend() {
            require(tx.inputs[this.activeInputIndex].tokenCategory == authorization);
        }
    }
    """
    violation = AuthorizationModelClassifierDetector().detect(CashScriptAST(code), None)
    assert violation is not None
    assert violation.severity == "info"
    assert violation.issue_class == "noise"
    assert violation.exploit_severity == "n/a"
