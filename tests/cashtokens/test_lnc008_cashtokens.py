"""CashTokens LNC-008 mode exclusions."""
from src.services.dsl_lint import _check_covenant_self_anchor

FT_TRANSFER = """
pragma cashscript ^0.13.0;
contract FT(bytes32 tokenCategory, pubkey owner, bytes dest) {
    function transfer(sig ownerSig) {
        require(checkSig(ownerSig, owner));
        require(tx.outputs[0].tokenCategory == tx.inputs[this.activeInputIndex].tokenCategory);
        require(tx.outputs[0].lockingBytecode == dest);
    }
}
"""

MINTING_AUTHORITY = """
pragma cashscript ^0.13.0;
contract Mint(bytes32 baseCategory, pubkey m) {
    function mint(sig mintSig) {
        require(checkSig(mintSig, m));
        require(tx.outputs[0].tokenCategory == baseCategory + 0x02);
    }
}
"""


def test_lnc008_skips_ft_transfer_mode():
    violations = _check_covenant_self_anchor(FT_TRANSFER, "ft_transfer")
    assert not [v for v in violations if v["rule_id"] == "LNC-008"]


def test_lnc008_requires_minting_self_anchor():
    violations = _check_covenant_self_anchor(MINTING_AUTHORITY, "nft_minting")
    assert any(v["rule_id"] == "LNC-008" for v in violations)


def test_ast_nft_commitment_flag():
    from src.utils.cashscript_ast import CashScriptAST

    code = """
    function f() {
        require(tx.outputs[0].nftCommitment == tx.inputs[this.activeInputIndex].nftCommitment);
    }
    """
    ast = CashScriptAST(code, "nft_immutable")
    assert ast.has_validates_nft_commitment


def test_ast_capability_match_flag():
    from src.utils.cashscript_ast import CashScriptAST

    code = """
pragma cashscript ^0.13.0;
contract C(bytes32 baseCategory) {
    function f() {
        require(tx.outputs[0].tokenCategory == baseCategory + 0x02);
    }
}
"""
    ast = CashScriptAST(code, "nft_minting")
    assert ast.has_validates_capability_match
