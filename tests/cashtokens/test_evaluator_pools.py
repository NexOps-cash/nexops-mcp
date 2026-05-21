"""Per-pattern evaluator alias pools for CashTokens."""
from benchmark.evaluator import _cashtoken_alias_pool


def test_token_ft_pool_requires_category():
    code = """
    function transfer(sig s) {
        require(checkSig(s, owner));
        require(tx.inputs[this.activeInputIndex].tokenCategory == tokenCategory);
        require(tx.outputs[0].tokenCategory == tx.inputs[this.activeInputIndex].tokenCategory);
        require(tx.outputs[0].tokenAmount == tx.inputs[this.activeInputIndex].tokenAmount);
    }
    """
    pool = _cashtoken_alias_pool(
        "token_ft",
        {"signature_verification": True},
        set(),
        code,
        [],
    )
    assert pool["token_category_check"]
    assert pool["token_amount_check"]
    assert pool["valid_signature_check"]


def test_minting_pfp_authority_echo_without_0x02_suffix():
    """PFP drop: authority category echoed on continuation output without +0x02 literal."""
    code = """
    function mint(sig mintSig) {
        require(checkSig(mintSig, mintAuthority));
        require(tx.inputs[this.activeInputIndex].tokenCategory == mintingAuthorityCategory);
        require(tx.outputs[0].tokenCategory == mintingAuthorityCategory);
        require(tx.outputs[0].lockingBytecode == this.activeBytecode);
    }
    """
    pool = _cashtoken_alias_pool(
        "nft_minting",
        {"signature_verification": True},
        set(),
        code,
        [],
    )
    assert pool["capability_minting"]
    assert pool["minting_authority_custody"]
