from src.services.audit_engine.audit_detectors import (
    AuthorizationModelClassifierDetector,
    CommitmentLengthSafetyDetector,
    IndexUnderflowDetector,
)
from src.utils.cashscript_ast import CashScriptAST


def test_index_underflow_detected():
    code = """
    contract C() {
        function spend() {
            require(tx.inputs[this.activeInputIndex - 1].value > 0);
        }
    }
    """
    assert IndexUnderflowDetector().detect(CashScriptAST(code)) is not None


def test_index_underflow_guarded():
    code = """
    contract C() {
        function spend() {
            require(this.activeInputIndex >= 1);
            require(tx.inputs[this.activeInputIndex - 1].value > 0);
        }
    }
    """
    assert IndexUnderflowDetector().detect(CashScriptAST(code)) is None


def test_commitment_requires_length():
    code = """
    contract C() {
        function spend() {
            bytes commitment = tx.outputs[0].nftCommitment;
            bytes left, bytes right = commitment.split(32);
            require(left != 0x);
        }
    }
    """
    assert CommitmentLengthSafetyDetector().detect(CashScriptAST(code)) is not None


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
    assert CommitmentLengthSafetyDetector().detect(CashScriptAST(code)) is None


def test_authorization_classifier_never_escalates():
    code = """
    contract C(bytes32 authorization) {
        function spend() {
            require(tx.inputs[this.activeInputIndex].tokenCategory == authorization);
        }
    }
    """
    violation = AuthorizationModelClassifierDetector().detect(CashScriptAST(code))
    assert violation is not None
    assert violation.severity == "info"
    assert violation.issue_class == "noise"
    assert violation.exploit_severity == "n/a"
