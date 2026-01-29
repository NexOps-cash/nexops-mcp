"""
Tests for Semantic Anti-Pattern Detection System
"""

import pytest
from src.services.anti_pattern_enforcer import AntiPatternEnforcer, get_anti_pattern_enforcer
from src.utils.cashscript_ast import CashScriptAST
from src.services.anti_pattern_detectors import (
    ImplicitOutputOrderingDetector,
    MissingOutputLimitDetector,
    UnvalidatedPositionDetector,
    FeeAssumptionViolationDetector
)


def test_anti_pattern_docs_loaded():
    """Test that anti-pattern documentation files are loaded"""
    enforcer = AntiPatternEnforcer()
    
    assert len(enforcer.anti_patterns) > 0, "No anti-pattern docs loaded"
    assert len(enforcer.detectors) > 0, "No detectors registered"


def test_implicit_output_ordering_detector():
    """Test semantic detection of implicit output ordering"""
    detector = ImplicitOutputOrderingDetector()
    
    # VULNERABLE: Uses output index without lockingBytecode validation
    vulnerable_code = """
    contract VulnerableContract() {
        function withdraw() {
            require(tx.outputs[0].value >= 1000);
            require(tx.outputs[1].value == 500);
        }
    }
    """
    
    ast = CashScriptAST(vulnerable_code)
    violation = detector.detect(ast)
    
    assert violation is not None, "Should detect implicit output ordering"
    assert violation.rule == "implicit_output_ordering.cash"
    assert "reorder" in violation.exploit.lower()


def test_implicit_output_ordering_secure_code():
    """Test that secure code with lockingBytecode validation passes"""
    detector = ImplicitOutputOrderingDetector()
    
    # SECURE: Validates lockingBytecode before using output
    secure_code = """
    contract SecureContract() {
        function withdraw() {
            bytes inputBytecode = tx.inputs[this.activeInputIndex].lockingBytecode;
            require(tx.outputs[0].lockingBytecode == inputBytecode);
            require(tx.outputs[0].value >= 1000);
        }
    }
    """
    
    ast = CashScriptAST(secure_code)
    violation = detector.detect(ast)
    
    assert violation is None, "Secure code should not be flagged"


def test_missing_output_limit_detector():
    """Test detection of missing output count validation"""
    detector = MissingOutputLimitDetector()
    
    # VULNERABLE: No output count validation
    vulnerable_code = """
    contract VulnerableContract() {
        function spend() {
            require(tx.outputs[0].value >= 1000);
        }
    }
    """
    
    ast = CashScriptAST(vulnerable_code)
    violation = detector.detect(ast)
    
    assert violation is not None, "Should detect missing output limit"
    assert violation.rule == "missing_output_limit.cash"
    assert "mint" in violation.exploit.lower()


def test_missing_output_limit_secure_code():
    """Test that code with output count validation passes"""
    detector = MissingOutputLimitDetector()
    
    # SECURE: Validates output count
    secure_code = """
    contract SecureContract() {
        function spend() {
            require(tx.outputs.length <= 2);
            require(tx.outputs[0].value >= 1000);
        }
    }
    """
    
    ast = CashScriptAST(secure_code)
    violation = detector.detect(ast)
    
    assert violation is None, "Secure code should not be flagged"


def test_unvalidated_position_detector():
    """Test detection of missing input position validation"""
    detector = UnvalidatedPositionDetector()
    
    # VULNERABLE: No position validation
    vulnerable_code = """
    contract VulnerableContract() {
        function spend() {
            require(tx.outputs[0].value >= 1000);
        }
    }
    """
    
    ast = CashScriptAST(vulnerable_code)
    violation = detector.detect(ast)
    
    assert violation is not None, "Should detect unvalidated position"
    assert violation.rule == "unvalidated_position.cash"


def test_unvalidated_position_secure_code():
    """Test that code with position validation passes"""
    detector = UnvalidatedPositionDetector()
    
    # SECURE: Validates input position
    secure_code = """
    contract SecureContract() {
        function spend() {
            require(this.activeInputIndex == 0);
            require(tx.outputs[0].value >= 1000);
        }
    }
    """
    
    ast = CashScriptAST(secure_code)
    violation = detector.detect(ast)
    
    assert violation is None, "Secure code should not be flagged"


def test_fee_assumption_detector():
    """Test detection of fee assumption anti-pattern"""
    detector = FeeAssumptionViolationDetector()
    
    # VULNERABLE: Calculates fee
    vulnerable_code = """
    contract VulnerableContract() {
        function spend() {
            int inputValue = tx.inputs[this.activeInputIndex].value;
            int outputValue = tx.outputs[0].value;
            int fee = inputValue - outputValue;
            require(fee <= 1000);
        }
    }
    """
    
    ast = CashScriptAST(vulnerable_code)
    violation = detector.detect(ast)
    
    assert violation is not None, "Should detect fee assumption"
    assert violation.rule == "fee_assumption_violation.cash"


def test_enforcer_validate_code():
    """Test end-to-end validation through enforcer"""
    enforcer = AntiPatternEnforcer()
    
    # Vulnerable code with multiple violations
    vulnerable_code = """
    contract MultipleViolations() {
        function bad() {
            int fee = tx.inputs[this.activeInputIndex].value - tx.outputs[0].value;
            require(fee <= 1000);
            require(tx.outputs[0].value >= 100);
        }
    }
    """
    
    result = enforcer.validate_code(vulnerable_code, stage="audit")
    
    assert not result["valid"], "Should detect violations"
    assert len(result["violated_rules"]) >= 2, "Should detect multiple violations"
    assert result["stage"] == "audit"


def test_enforcer_secure_code():
    """Test that fully secure code passes all checks"""
    enforcer = AntiPatternEnforcer()
    
    # Secure code with all validations
    secure_code = """
    contract SecureContract() {
        function spend() {
            require(this.activeInputIndex == 0);
            require(tx.outputs.length == 1);
            bytes inputBytecode = tx.inputs[this.activeInputIndex].lockingBytecode;
            require(tx.outputs[0].lockingBytecode == inputBytecode);
            require(tx.outputs[0].value >= 1000);
        }
    }
    """
    
    result = enforcer.validate_code(secure_code)
    
    assert result["valid"], f"Secure code should pass: {result['violated_rules']}"
    assert len(result["violated_rules"]) == 0


def test_violation_structure():
    """Test that violations have correct structure"""
    detector = ImplicitOutputOrderingDetector()
    
    vulnerable_code = """
    contract Test() {
        function f() {
            require(tx.outputs[0].value >= 100);
        }
    }
    """
    
    ast = CashScriptAST(vulnerable_code)
    violation = detector.detect(ast)
    
    assert violation is not None
    violation_dict = violation.to_dict()
    
    assert "rule" in violation_dict
    assert "reason" in violation_dict
    assert "exploit" in violation_dict
    assert "location" in violation_dict
    assert "severity" in violation_dict
    
    assert violation_dict["severity"] == "critical"
    assert len(violation_dict["reason"]) > 0
    assert len(violation_dict["exploit"]) > 0


def test_singleton_pattern():
    """Test that get_anti_pattern_enforcer returns singleton"""
    enforcer1 = get_anti_pattern_enforcer()
    enforcer2 = get_anti_pattern_enforcer()
    
    assert enforcer1 is enforcer2, "Should return same instance"
