"""Unit tests for N-output split conservation helpers."""

from src.utils.split_conservation import (
    has_bch_value_conservation,
    has_chained_field_sum,
    has_token_amount_conservation,
)


def test_two_output_bch_sum():
    body = """
        require(tx.outputs.length == 2);
        require(tx.outputs[0].value + tx.outputs[1].value == tx.inputs[this.activeInputIndex].value);
    """
    assert has_bch_value_conservation(body)


def test_three_output_bch_sum():
    body = """
        require(tx.outputs.length == 3);
        require(
            tx.outputs[0].value + tx.outputs[1].value + tx.outputs[2].value ==
            tx.inputs[this.activeInputIndex].value
        );
    """
    assert has_bch_value_conservation(body)


def test_three_output_token_sum():
    body = """
        require(
            tx.outputs[0].tokenAmount + tx.outputs[1].tokenAmount + tx.outputs[2].tokenAmount ==
            tx.inputs[this.activeInputIndex].tokenAmount
        );
    """
    assert has_token_amount_conservation(body)


def test_invalid_single_output_not_conservation():
    body = "require(tx.outputs[0].value == tx.inputs[this.activeInputIndex].value);"
    assert not has_chained_field_sum(body, "value", r"tx\.inputs\[this\.activeInputIndex\]\.value")
