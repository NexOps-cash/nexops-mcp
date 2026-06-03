"""validate_audit for Wave 1 CashTokens families: immutable, mutable, hybrid."""

from src.services.audit_engine.audit_phase import validate_audit

IMMUTABLE = """
pragma cashscript ^0.13.0;

contract ArtNFT(pubkey owner, bytes32 tokenCategory) {
    function transfer(sig ownerSig, bytes recipientLock) {
        require(checkSig(ownerSig, owner));
        require(tx.outputs.length == 1);
        require(tx.inputs[this.activeInputIndex].tokenCategory == tokenCategory);
        require(tx.outputs[0].tokenCategory == tx.inputs[this.activeInputIndex].tokenCategory);
        require(tx.outputs[0].tokenAmount == tx.inputs[this.activeInputIndex].tokenAmount);
        require(tx.outputs[0].nftCommitment == tx.inputs[this.activeInputIndex].nftCommitment);
        require(tx.outputs[0].lockingBytecode == recipientLock);
    }
}
"""

IMMUTABLE_WITH_VALUE = """
pragma cashscript ^0.13.0;

contract ArtNFT(pubkey owner, bytes32 tokenCategory) {
    function transfer(sig ownerSig, bytes recipientLock) {
        require(checkSig(ownerSig, owner));
        require(tx.outputs.length == 1);
        require(tx.inputs[this.activeInputIndex].tokenCategory == tokenCategory);
        require(tx.outputs[0].tokenCategory == tx.inputs[this.activeInputIndex].tokenCategory);
        require(tx.outputs[0].tokenAmount == tx.inputs[this.activeInputIndex].tokenAmount);
        require(tx.outputs[0].nftCommitment == tx.inputs[this.activeInputIndex].nftCommitment);
        require(tx.outputs[0].value == tx.inputs[this.activeInputIndex].value);
        require(tx.outputs[0].lockingBytecode == recipientLock);
    }
}
"""

MUTABLE = """
pragma cashscript ^0.13.0;

contract EvolvingNFT(pubkey owner, bytes32 baseCategory, bytes newCommit) {
    function levelUp(sig ownerSig) {
        require(checkSig(ownerSig, owner));
        require(tx.outputs.length == 1);
        require(tx.inputs[this.activeInputIndex].tokenCategory == baseCategory + 0x01);
        require(tx.outputs[0].tokenCategory == baseCategory + 0x01);
        require(tx.outputs[0].lockingBytecode == this.activeBytecode);
        require(tx.outputs[0].nftCommitment == newCommit);
    }
}
"""

MUTABLE_WITH_VALUE = """
pragma cashscript ^0.13.0;

contract EvolvingNFT(pubkey owner, bytes32 baseCategory, bytes newCommit) {
    function levelUp(sig ownerSig) {
        require(checkSig(ownerSig, owner));
        require(tx.outputs.length == 1);
        require(tx.inputs[this.activeInputIndex].tokenCategory == baseCategory + 0x01);
        require(tx.outputs[0].tokenCategory == baseCategory + 0x01);
        require(tx.outputs[0].lockingBytecode == this.activeBytecode);
        require(tx.outputs[0].value == tx.inputs[this.activeInputIndex].value);
        require(tx.outputs[0].nftCommitment == newCommit);
    }
}
"""

HYBRID = """
pragma cashscript ^0.13.0;

contract StableVault(pubkey owner, bytes32 cat, bytes commit) {
    function transition(sig ownerSig) {
        require(checkSig(ownerSig, owner));
        require(tx.outputs.length == 1);
        require(tx.outputs[0].lockingBytecode == this.activeBytecode);
        require(tx.outputs[0].tokenCategory == tx.inputs[this.activeInputIndex].tokenCategory);
        require(tx.outputs[0].tokenAmount == tx.inputs[this.activeInputIndex].tokenAmount);
        require(tx.outputs[0].nftCommitment == tx.inputs[this.activeInputIndex].nftCommitment);
        require(tx.outputs[0].value == tx.inputs[this.activeInputIndex].value);
    }
}
"""


def _rules(result) -> list[str]:
    return [v.rule for v in result.violations]


def _capability_rules(result) -> list[str]:
    return [r for r in _rules(result) if r.startswith("capability_")]


def test_immutable_passes_no_critical():
    r = validate_audit(IMMUTABLE, contract_mode="nft_immutable")
    assert r.passed is True
    assert not any(v.severity == "critical" for v in r.violations)
    assert _capability_rules(r) == []


def test_immutable_clean_with_value_anchor():
    r = validate_audit(IMMUTABLE_WITH_VALUE, contract_mode="nft_immutable")
    assert r.passed is True
    assert "LNC-003" not in _rules(r)
    assert _capability_rules(r) == []


def test_mutable_passes_no_critical():
    r = validate_audit(MUTABLE, contract_mode="nft_mutable")
    assert r.passed is True
    assert not any(v.severity == "critical" for v in r.violations)
    assert "capability_mutable_nft_no_reanchor" not in _rules(r)


def test_mutable_clean_with_value_on_reanchor():
    r = validate_audit(MUTABLE_WITH_VALUE, contract_mode="nft_mutable")
    assert r.passed is True
    assert "LNC-016" not in _rules(r)
    assert "LNC-003" not in _rules(r)
    assert _capability_rules(r) == []


def test_hybrid_five_point_clean():
    r = validate_audit(HYBRID, contract_mode="hybrid_token")
    assert r.passed is True
    assert r.structural_score == 1.0
    assert _rules(r) == []
    assert _capability_rules(r) == []
