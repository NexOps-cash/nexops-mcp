"""Wave 2D — token validation hardening (AST + capabilities)."""

from src.services.dsl_lint import DSLLinter, _split_token_conservation_in_body
from src.services.semantic_capabilities import extract_semantic_capabilities
from src.utils.cashscript_ast import CashScriptAST

SPLIT_OK = """
pragma cashscript ^0.13.0;
contract C(pubkey o) {
    function split(sig s) {
        require(checkSig(s, o));
        require(tx.outputs[0].tokenCategory == tx.inputs[this.activeInputIndex].tokenCategory);
        require(tx.outputs[1].tokenCategory == tx.inputs[this.activeInputIndex].tokenCategory);
        require(tx.outputs[0].tokenAmount + tx.outputs[1].tokenAmount == tx.inputs[this.activeInputIndex].tokenAmount);
    }
}
"""

SPLIT_BAD = """
pragma cashscript ^0.13.0;
contract C(pubkey o) {
    function split(sig s) {
        require(checkSig(s, o));
        require(tx.outputs[0].tokenAmount == 100);
        require(tx.outputs[1].tokenAmount == 200);
    }
}
"""


def test_ast_split_conservation():
    ast = CashScriptAST(SPLIT_OK)
    assert ast.has_split_token_supply_conservation()
    assert ast.has_same_index_category_preservation()


def test_capability_split_supply():
    caps = extract_semantic_capabilities(SPLIT_OK, contract_mode="token_ft")
    assert caps.get("preserves_split_token_supply") is True
    assert caps.get("preserves_token_amount") is True


def test_lint_split_without_sum_fails():
    linter = DSLLinter()
    result = linter.lint(SPLIT_BAD, contract_mode="token_ft")
    assert result["passed"] is False


def test_split_helper():
    assert _split_token_conservation_in_body(SPLIT_OK) is True
    assert _split_token_conservation_in_body(SPLIT_BAD) is False
