"""Tests for InvariantEngine integration with audit detectors and lint."""

from src.services.audit_engine.audit_detectors import (
    FixedIndexOOBDetector,
    InputOutputCouplingDetector,
)
from src.services.audit_engine.invariant_engine import (
    InvariantEngine,
    fixed_indices_covered_by_guards,
    should_skip_input_output_coupling,
)
from src.services.audit_engine.audit_lint import get_audit_linter, _check_hardcoded_input_index
from src.utils.cashscript_ast import CashScriptAST


def _inv(code: str) -> dict:
    return InvariantEngine(CashScriptAST(code, contract_mode="token")).analyze()


def test_fixed_index_oob_when_unsafe():
    code = """
    contract T() {
        function spend() {
            require(tx.outputs[2].value == 0);
        }
    }
    """
    ast = CashScriptAST(code, contract_mode="")
    invariants = _inv(code)
    v = FixedIndexOOBDetector().detect(ast, invariants)
    assert v is not None
    assert v.rule == "fixed_index_oob"


def test_fixed_index_oob_skipped_with_guard():
    code = """
    contract T() {
        function spend() {
            require(tx.outputs.length == 3);
            require(tx.outputs[2].value == 0);
        }
    }
    """
    ast = CashScriptAST(code, contract_mode="")
    invariants = _inv(code)
    v = FixedIndexOOBDetector().detect(ast, invariants)
    assert v is None


def test_input_output_coupling_skipped_by_invariant_signal():
    code = """
    contract T(bytes32 a) {
        function spend() {
            require(tx.inputs[this.activeInputIndex].lockingBytecode
                == tx.outputs[0].lockingBytecode);
            require(tx.inputs[this.activeInputIndex].tokenCategory
                == tx.outputs[0].tokenCategory);
            require(tx.inputs[this.activeInputIndex].value == tx.outputs[0].value);
        }
    }
    """
    ast = CashScriptAST(code, contract_mode="")
    invariants = _inv(code)
    c = invariants.get("coupling") or {}
    assert c.get("has_same_index_locking_and_token")
    assert c.get("positional_validation")
    v = InputOutputCouplingDetector().detect(ast, invariants)
    assert v is None


def test_lnc_001a_suppressed_with_requires_index_zero():
    code = """
    contract T() {
        function spend() {
            require(this.activeInputIndex == 0);
            require(tx.inputs[0].value > 0);
        }
    }
    """
    inv = _inv(code)
    assert (inv.get("input_constraints") or {}).get("requires_index_zero") is True
    viols = _check_hardcoded_input_index(code, invariants=inv)
    assert "LNC-001a" not in {v["rule_id"] for v in viols}


def test_linter_returns_invariant_keys_in_practice():
    code = "contract T() { function s() { require(this.activeInputIndex==0); require(tx.inputs[0].value>0);} }"
    r = get_audit_linter().lint(code, contract_mode="token")
    assert r["passed"] is True


def test_enforcer_includes_invariants_key():
    from src.services.audit_engine.audit_enforcer import get_audit_enforcer

    code = "contract T() { function s() { require(true); } }"
    r = get_audit_enforcer().validate_code(code, contract_mode="")
    assert "invariants" in r
    assert "output_constraints" in (r.get("invariants") or {})


def test_output_constraints_includes_min_required_outputs():
    code = """
    contract T() { function s() { require(tx.outputs[2].value==0); } }
    """
    oc = _inv(code).get("output_constraints") or {}
    assert oc.get("min_required_outputs") == 3
    assert oc.get("required_max_index") == 2


def test_length_guard_ops_cover_fixed_index():
    assert fixed_indices_covered_by_guards(4, [{"op": "==", "value": 5}])
    assert fixed_indices_covered_by_guards(4, [{"op": ">=", "value": 5}])
    assert fixed_indices_covered_by_guards(3, [{"op": ">", "value": 3}])
    assert not fixed_indices_covered_by_guards(4, [{"op": "==", "value": 4}])


def test_skip_coupling_false_when_locking_and_token_different_indices():
    code = """
    contract T() {
        function spend() {
            require(tx.outputs[0].lockingBytecode == 0x);
            require(tx.outputs[1].tokenCategory == 0x);
            require(tx.outputs[0].value == 0);
            require(tx.outputs[1].value == 0);
            require(tx.outputs[2].value == 0);
        }
    }
    """
    inv = _inv(code)
    assert not should_skip_input_output_coupling(inv)

