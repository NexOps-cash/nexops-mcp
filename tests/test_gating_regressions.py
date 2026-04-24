from src.services.anti_pattern_detectors import EmptyFunctionDetector
from src.services.anti_pattern_enforcer import AntiPatternEnforcer
from src.services.dsl_lint import DSLLinter
from src.utils.cashscript_ast import CashScriptAST


def test_empty_function_nested_blocks_with_require_is_not_flagged():
    code = """
    contract T() {
        function release() {
            int i = 0;
            do {
                if (tx.inputs[i].value >= 0) {
                    require(tx.inputs[i].value >= 0);
                }
                i = i + 1;
            } while (i < tx.inputs.length);
        }
    }
    """
    violation = EmptyFunctionDetector().detect(CashScriptAST(code, contract_mode="manager"))
    assert violation is None


def test_empty_function_truly_empty_is_flagged():
    code = """
    contract T() {
        function release() {
        }
    }
    """
    violation = EmptyFunctionDetector().detect(CashScriptAST(code, contract_mode="manager"))
    assert violation is not None
    assert violation.rule == "empty_function_body"


def test_lnc005_comment_only_does_not_trigger():
    code = """
    contract T() {
        function spend() {
            // fee subtraction logic moved off-chain
            int amount = tx.inputs[this.activeInputIndex].value;
            require(amount > 0);
        }
    }
    """
    result = DSLLinter().lint(code, contract_mode="manager")
    assert all(v.get("rule_id") != "LNC-005" for v in result["violations"])


def test_lnc005_real_subtraction_triggers():
    code = """
    contract T(int fee) {
        function spend() {
            int out = tx.inputs[this.activeInputIndex].value - fee;
            require(out > 0);
        }
    }
    """
    result = DSLLinter().lint(code, contract_mode="manager")
    assert any(v.get("rule_id") == "LNC-005" for v in result["violations"])


def test_lnc014_mode_gating_vault_suppressed_manager_active():
    code = """
    contract T(bytes32 authToken) {
        function release() {
            require(tx.inputs[this.activeInputIndex].tokenCategory == authToken);
        }
    }
    """
    lint_vault = DSLLinter().lint(code, contract_mode="vault")
    lint_manager = DSLLinter().lint(code, contract_mode="manager")

    assert all(v.get("rule_id") != "LNC-014" for v in lint_vault["violations"])
    assert any(v.get("rule_id") == "LNC-014" for v in lint_manager["violations"])


def test_profile_disables_empty_function_for_vault_not_manager():
    code = """
    contract T() {
        function release() {
        }
    }
    """
    enforcer = AntiPatternEnforcer()
    vault_result = enforcer.validate_code(code, stage="audit", contract_mode="vault")
    manager_result = enforcer.validate_code(code, stage="audit", contract_mode="manager")

    assert "empty_function_body" not in vault_result["violated_rules"]
    assert "empty_function_body" in manager_result["violated_rules"]
