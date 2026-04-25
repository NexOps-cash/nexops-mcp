"""
Index underflow: per-function body scoping (balanced braces) + guard in same function.
"""

from src.services.anti_pattern_detectors import IndexUnderflowDetector
from src.utils.cashscript_ast import CashScriptAST

# Case 1 — SimpleVault-style: nested do/while, no this.activeInputIndex subtraction
SIMPLE_VAULT = """
pragma cashscript ~0.13.0;
contract SimpleVault(bytes32 authToken) {
    function release() {
        bool authorized = false;
        int inputIndex = 0;
        do {
            if(tx.inputs[inputIndex].tokenCategory == authToken) {
                authorized = true;
            }
            inputIndex = inputIndex + 1;
        } while(inputIndex < tx.inputs.length && !authorized);
        require(authorized, "unauthorized user");
    }
}
"""


def test_simple_vault_no_subtraction_no_finding():
    ast = CashScriptAST(SIMPLE_VAULT, contract_mode="vault")
    assert ast.has_index_underflow_risk() == []
    assert IndexUnderflowDetector().detect(ast) is None


# Case 2 — subtract index without guard
UNSAFE_SUB = """
contract U() {
    function data() {
        require(tx.inputs[this.activeInputIndex].tokenCategory == 0x00);
        require(tx.inputs[this.activeInputIndex - 1].value == 0);
    }
}
"""


def test_unsafe_subtract_one_in_inputs_without_guard():
    ast = CashScriptAST(UNSAFE_SUB)
    v = IndexUnderflowDetector().detect(ast)
    assert v is not None
    assert v.rule == "index_underflow"
    assert "data" in (v.location or {}).get("function", "")


# Case 3 — strict guard before use (for -1 need > 1, not > 0)
SAFE_STRICT = """
contract U() {
    function data() {
        require(this.activeInputIndex > 1);
        require(tx.inputs[this.activeInputIndex - 1].value == 0);
    }
}
"""


def test_safe_with_strict_guard_no_finding():
    ast = CashScriptAST(SAFE_STRICT)
    assert IndexUnderflowDetector().detect(ast) is None


# Case 3b — weak guard: > 0 is insufficient for - 1, still report
WEAK_GUARD = """
contract U() {
    function data() {
        require(this.activeInputIndex > 0);
        require(tx.inputs[this.activeInputIndex - 1].value == 0);
    }
}
"""


def test_weak_guard_still_risky_for_minus_one():
    ast = CashScriptAST(WEAK_GUARD)
    v = IndexUnderflowDetector().detect(ast)
    assert v is not None
    assert v.rule == "index_underflow"


# Multi-function: only the function with unguarded -1 is flagged
TWO_FN = """
contract M(bytes32 t) {
    function close() {
        int i = 0;
        do {
            require(tx.inputs[i].tokenCategory == t);
            i = i + 1;
        } while (i < tx.inputs.length);
    }
    function data() {
        require(tx.inputs[this.activeInputIndex].tokenCategory == t);
        require(tx.inputs[this.activeInputIndex - 1].value == 0);
    }
}
"""


def test_only_function_with_unguarded_subtraction_is_flagged():
    ast = CashScriptAST(TWO_FN)
    risky = ast.has_index_underflow_risk()
    assert risky == ["data"]
    v = IndexUnderflowDetector().detect(ast)
    assert v is not None
    assert (v.location or {}).get("function") == "data"
