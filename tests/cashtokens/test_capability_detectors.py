"""Capability-backed detector smoke tests."""

from src.services.capability_detectors import (
    TokenContinuityBreakDetector,
    UnintendedBurnPathDetector,
)
from src.utils.cashscript_ast import CashScriptAST


def test_token_continuity_break_fires():
    code = """
    contract Bad() {
        function spend() {
            require(tx.outputs[0].value > 0);
            require(tx.outputs[0].tokenAmount == 100);
        }
    }
    """
    ast = CashScriptAST(code)
    v = TokenContinuityBreakDetector().detect(ast)
    assert v is not None
    assert v.rule == "capability_token_continuity_break"


def test_unintended_burn_without_input_constraint():
    code = """
    contract Bad() {
        function burn() {
            require(tx.outputs[0].tokenCategory == 0x);
        }
    }
    """
    ast = CashScriptAST(code)
    v = UnintendedBurnPathDetector().detect(ast)
    assert v is not None
    assert v.rule == "capability_unintended_burn"
