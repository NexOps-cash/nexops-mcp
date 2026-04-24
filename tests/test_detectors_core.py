"""
Phase-3 detector lock-in: InputOutputCoupling, PartialAggregation, OutputBinding
(mode gating), CommitmentLength, IndexUnderflow.
"""
import pytest

from src.services.anti_pattern_detectors import (
    InputOutputCouplingDetector,
    PartialAggregationDetector,
    OutputBindingDetector,
    CommitmentLengthSafetyDetector,
    IndexUnderflowDetector,
)
from src.utils.cashscript_ast import CashScriptAST

# ---------------------------------------------------------------------------
# 1) InputOutputCouplingDetector — aggregation must NOT false-positive;
#    broken forwarding (input indices not covered by output indices) must fire.
# ---------------------------------------------------------------------------


def test_io_coupling_aggregation_single_output_does_not_trigger():
    """
    multi-input read → single output read is "aggregation" (not forwarding),
    so the coupling check is skipped.
    """
    code = """
    contract Agg() {
        function close() {
            require(tx.inputs[0].value > 0);
            require(tx.inputs[1].value > 0);
            require(tx.outputs[0].value == 1);
        }
    }
    """
    d = InputOutputCouplingDetector()
    assert d.detect(CashScriptAST(code)) is None


def test_io_coupling_broken_forwarding_triggers():
    """
    Classified as forwarding (overlapping index sets) but input indices
    are not a subset of output indices → broken coupling.
    """
    code = """
    contract Bad() {
        function pay() {
            require(tx.inputs[0].value > 0);
            require(tx.inputs[1].value > 0);
            require(tx.outputs[0].value > 0);
            require(tx.outputs[2].value > 0);
        }
    }
    """
    d = InputOutputCouplingDetector()
    v = d.detect(CashScriptAST(code))
    assert v is not None
    assert v.rule == "input_output_coupling"
    assert "pay" in v.location.get("function", "")


# ---------------------------------------------------------------------------
# 2) PartialAggregationDetector — boundary vs subset processing
# ---------------------------------------------------------------------------


def test_partial_aggregation_unsafe_no_boundary():
    """
    Same input index tokenCategory check twice + no tx.inputs.length guard → flag.
    """
    code = """
    contract P() {
        function sweep() {
            require(tx.inputs[0].tokenCategory == 0x00);
            require(tx.inputs[0].tokenCategory == 0x00);
        }
    }
    """
    d = PartialAggregationDetector()
    v = d.detect(CashScriptAST(code, contract_mode=""))
    assert v is not None
    assert v.rule == "partial_aggregation_risk"


def test_partial_aggregation_safe_full_length_guard():
    code = """
    contract P() {
        function sweep() {
            require(tx.inputs.length == 2);
            require(tx.inputs[0].tokenCategory == 0x00);
            require(tx.inputs[0].tokenCategory == 0x00);
        }
    }
    """
    d = PartialAggregationDetector()
    assert d.detect(CashScriptAST(code, contract_mode="")) is None


def test_partial_aggregation_safe_fundindex_boundary():
    code = """
    contract P() {
        function scan() {
            require(tx.inputs[0].tokenCategory == 0x00);
            require(tx.inputs[0].tokenCategory == 0x00);
            require(fundIndex == tx.inputs.length);
        }
    }
    """
    d = PartialAggregationDetector()
    assert d.detect(CashScriptAST(code, contract_mode="")) is None


def test_partial_aggregation_skipped_for_parser_mode():
    code = """
    contract P() {
        function sweep() {
            require(tx.inputs[0].tokenCategory == 0x00);
            require(tx.inputs[0].tokenCategory == 0x00);
        }
    }
    """
    d = PartialAggregationDetector()
    assert d.detect(CashScriptAST(code, contract_mode="parser")) is None


# ---------------------------------------------------------------------------
# 3) OutputBindingDetector — only manager|stateful|covenant; not vault|minter|parser
# ---------------------------------------------------------------------------


def _code_unbound_value_no_locking():
    return """
    contract M(pubkey a) {
        function spend(sig s) {
            require(checkSig(s, a));
            require(tx.outputs[0].value == 1000);
        }
    }
    """


def test_output_binding_triggers_in_manager_mode():
    d = OutputBindingDetector()
    v = d.detect(CashScriptAST(_code_unbound_value_no_locking(), contract_mode="manager"))
    assert v is not None
    assert v.rule == "output_binding_missing"
    assert v.location.get("property") == "value"


@pytest.mark.parametrize("mode", ["vault", "minter", "parser"])
def test_output_binding_does_not_trigger_in_non_bound_modes(mode):
    d = OutputBindingDetector()
    assert d.detect(CashScriptAST(_code_unbound_value_no_locking(), contract_mode=mode)) is None


# ---------------------------------------------------------------------------
# 4) CommitmentLengthSafetyDetector
# ---------------------------------------------------------------------------


def test_commitment_split_unsafe_without_length_guard():
    code = """
    contract C() {
        function parse(bytes data) {
            require(true);
            bytes a = data.split(32);
        }
    }
    """
    d = CommitmentLengthSafetyDetector()
    v = d.detect(CashScriptAST(code))
    assert v is not None
    assert v.rule == "commitment_length_missing"


def test_commitment_split_safe_with_length_require():
    code = """
    contract C() {
        function parse(bytes data) {
            require(data.length >= 32);
            bytes a = data.split(32);
        }
    }
    """
    d = CommitmentLengthSafetyDetector()
    assert d.detect(CashScriptAST(code)) is None


# ---------------------------------------------------------------------------
# 5) IndexUnderflowDetector — operand-specific guard: for `- 1` need `> 1`
# ---------------------------------------------------------------------------


def test_index_underflow_unsafe_subtract_one_without_guard():
    code = """
    contract U() {
        function f() {
            int p = this.activeInputIndex - 1;
            require(p >= 0);
        }
    }
    """
    d = IndexUnderflowDetector()
    v = d.detect(CashScriptAST(code))
    assert v is not None
    assert v.rule == "index_underflow"


def test_index_underflow_safe_with_strict_guard_for_minus_one():
    code = """
    contract U() {
        function f() {
            require(this.activeInputIndex > 1);
            int p = this.activeInputIndex - 1;
            require(tx.inputs[p].value == 0);
        }
    }
    """
    d = IndexUnderflowDetector()
    assert d.detect(CashScriptAST(code)) is None


def test_index_underflow_weak_guard_greater_zero_still_unsafe_for_minus_one():
    """
    Guard must dominate the subtracted literal: for `- 1` the implementation
    requires `require(this.activeInputIndex > 1)`, not merely `> 0`.
    """
    code = """
    contract U() {
        function f() {
            require(this.activeInputIndex > 0);
            int p = this.activeInputIndex - 1;
        }
    }
    """
    d = IndexUnderflowDetector()
    v = d.detect(CashScriptAST(code))
    assert v is not None
    assert v.rule == "index_underflow"
