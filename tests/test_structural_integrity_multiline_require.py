"""Unit tests for multiline require() detection in structural integrity."""

from src.services.structural_integrity import (
    _dangling_require,
    diagnose_structure,
    is_structurally_valid,
)


def test_valid_single_line_require():
    code = """
    function spend() {
        require(checkSig(sig, pk));
        require(tx.outputs.length == 2);
    }
    """
    assert not _dangling_require(code)
    assert is_structurally_valid(
        "pragma cashscript ^0.13.0;\ncontract C() {\n" + code + "\n}"
    )


def test_valid_multiline_require():
    code = """pragma cashscript ^0.13.0;
contract Split() {
    function distribute() {
        require(tx.outputs.length == 3);
        require(
            tx.outputs[0].value + tx.outputs[1].value + tx.outputs[2].value ==
            tx.inputs[this.activeInputIndex].value
        );
    }
}"""
    assert not _dangling_require(code)
    diag = diagnose_structure(code)
    assert diag.valid
    assert "dangling_require" not in diag.issues


def test_truly_dangling_require():
    code = """pragma cashscript ^0.13.0;
contract Bad() {
    function purchase() {
        require(checkSig(sig, pk));
        require(
"""
    assert _dangling_require(code)
    diag = diagnose_structure(code)
    assert not diag.valid
    assert "dangling_require" in diag.issues


def test_nested_expression_require():
    code = """pragma cashscript ^0.13.0;
contract Nested() {
    function go() {
        require(checkMultiSig([sig1, sig2], [pk1, pk2, pk3]));
        require((tx.outputs[0].value + tx.outputs[1].value) == inputVal);
    }
}"""
    assert not _dangling_require(code)
    assert diagnose_structure(code).valid
