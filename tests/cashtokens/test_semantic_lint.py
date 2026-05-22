"""Semantic lifecycle and soulbound lint rules."""

from src.services.dsl_lint import DSLLinter

SOULBOUND_OK = """
contract S(pubkey owner, bytes expectedCategory, bytes newCommitment) {
    function update(bytes ownerSig) {
        require(checkSig(ownerSig, owner));
        require(tx.outputs.length == 1);
        require(tx.outputs[0].lockingBytecode == this.activeBytecode);
        require(tx.outputs[0].nftCommitment == newCommitment);
    }
}
"""

HYBRID_WITH_SIG = """
contract H(pubkey vaultOwner, bytes stateCategory, bytes newCommitment) {
    function updateState(bytes ownerSig) {
        require(checkSig(ownerSig, vaultOwner));
        require(tx.outputs[0].lockingBytecode == this.activeBytecode);
        require(tx.outputs[0].tokenCategory == stateCategory + 0x01);
        require(tx.outputs[0].nftCommitment == newCommitment);
    }
}
"""


def test_soulbound_lint_passes_self_anchor():
    sem = {"ownership_mode": "soulbound", "lifecycle_mode": "state_transition"}
    r = DSLLinter().lint(SOULBOUND_OK, contract_mode="nft_mutable", semantic=sem)
    lnc026 = [v for v in r["violations"] if v["rule_id"] == "LNC-026"]
    assert not lnc026 or r["passed"]


def test_hybrid_requires_checksig():
    sem = {"lifecycle_mode": "state_transition"}
    r = DSLLinter().lint(HYBRID_WITH_SIG, contract_mode="hybrid_token", semantic=sem)
    lnc027 = [v for v in r["violations"] if v["rule_id"] == "LNC-027"]
    assert len(lnc027) == 0
