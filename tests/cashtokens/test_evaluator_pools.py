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
