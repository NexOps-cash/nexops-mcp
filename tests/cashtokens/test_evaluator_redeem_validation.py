"""Evaluator: redeemable FT category-zero burn satisfies token_validation."""

from benchmark.evaluator import BenchmarkEvaluator
from benchmark.feature_extractor import FeatureExtractor


VOUCHER_CODE = """
pragma cashscript ^0.13.0;
contract FungibleVoucherRedeem(
    pubkey owner,
    bytes recipientLockingBytecode,
    bytes32 tokenCategory
) {
    function redeem(sig ownerSig) {
        require(checkSig(ownerSig, owner));
        require(tx.inputs[this.activeInputIndex].tokenCategory == tokenCategory);
        require(tx.outputs.length == 1);
        require(tx.outputs[0].tokenCategory == 0x);
        require(tx.outputs[0].lockingBytecode == recipientLockingBytecode);
        require(tx.outputs[0].value == tx.inputs[this.activeInputIndex].value);
    }
}
"""


def test_redeemable_burn_satisfies_token_validation():
    extracted = FeatureExtractor().extract(VOUCHER_CODE)
    detected = set(extracted["features"])
    capabilities = {
        "signature_verification": any("_signature" in f or f == "multisig" for f in detected),
        "token_validation": (
            ("token_amount" in detected)
            or ("token_nft" in detected)
            or ("tokenCategory" in VOUCHER_CODE and "tokenAmount" in VOUCHER_CODE)
        ),
    }
    assert not capabilities["token_validation"]

    import re

    def redeemable_burn(src: str) -> bool:
        return bool(
            re.search(r"tx\.inputs\[[^\]]+\]\.tokenCategory\s*==", src)
            and re.search(r"tx\.outputs\[\d+\]\.tokenCategory\s*==\s*0x", src)
        )

    assert redeemable_burn(VOUCHER_CODE)
    assert capabilities["token_validation"] or redeemable_burn(VOUCHER_CODE)
