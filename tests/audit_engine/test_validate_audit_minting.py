"""validate_audit on CashTokens minting-shaped contracts (family parity)."""

from src.services.audit_engine.audit_phase import validate_audit

MINTING = """
pragma cashscript ^0.13.0;

contract OpenEditionNFT(
    bytes32 baseCategory,
    pubkey mintAuthority,
    int maxSupply,
    int totalMinted
) {
    function mint(sig mintSig, int mintAmount, bytes recipientLockingBytecode) {
        require(tx.outputs.length <= 3);
        require(checkSig(mintSig, mintAuthority));
        require(tx.inputs[this.activeInputIndex].tokenCategory == baseCategory + 0x02);
        require(totalMinted + mintAmount <= maxSupply);
        require(tx.outputs[0].tokenCategory == baseCategory + 0x02);
        require(tx.outputs[0].lockingBytecode == this.activeBytecode);
        require(tx.outputs[0].value == tx.inputs[this.activeInputIndex].value);
        require(tx.outputs[1].tokenCategory == baseCategory + 0x01);
        require(tx.outputs[1].lockingBytecode == recipientLockingBytecode);
    }
}
"""


def _rules(result) -> list[str]:
    return [v.rule for v in result.violations]


def test_minting_authority_passes_no_critical():
    r = validate_audit(MINTING, contract_mode="nft_minting_authority")
    assert r.passed is True
    assert not any(v.severity == "critical" for v in r.violations)
    assert "minting_authority_escape" not in _rules(r)
    assert "capability_escaped" not in _rules(r)


def test_minting_no_capability_false_positives():
    r = validate_audit(MINTING, contract_mode="nft_minting_authority")
    capability_rules = [x for x in _rules(r) if x.startswith("capability_")]
    assert capability_rules == []


def test_minting_fixed_index_oob_medium_only():
    """Known soft finding: <= 3 does not satisfy fixed_index_oob guard parser."""
    r = validate_audit(MINTING, contract_mode="nft_minting_authority")
    assert "fixed_index_oob" in _rules(r)
    oob = next(v for v in r.violations if v.rule == "fixed_index_oob")
    assert oob.severity == "medium"
