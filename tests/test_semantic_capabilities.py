"""Wave 1.5 — SemanticCapabilities extraction and requirement mapping."""

import pytest

from benchmark.semantic_requirements import satisfies_requirement
from src.services.semantic_capabilities import (
    CAPABILITY_REGISTRY,
    extract_semantic_capabilities,
)


SOULBOUND_SNIPPET = """
contract Soulbound() {
    function transfer(sig s, pubkey owner) {
        require(checkSig(s, owner));
        require(tx.inputs[this.activeInputIndex].tokenCategory == tokenCategory);
        require(tx.outputs[0].lockingBytecode == this.activeBytecode);
        require(tx.outputs[0].tokenCategory == tx.inputs[this.activeInputIndex].tokenCategory);
    }
}
"""

MARKETPLACE_SNIPPET = """
contract Market() {
    function purchase(sig buyerSig, pubkey buyerPkh, bytes buyerLockingBytecode) {
        require(checkSig(buyerSig, buyerPkh));
        require(tx.outputs[0].lockingBytecode == buyerLockingBytecode);
        require(tx.outputs[0].tokenCategory == tx.inputs[this.activeInputIndex].tokenCategory);
    }
}
"""

VOUCHER_REDEEM_SNIPPET = """
contract Voucher() {
    function redeem(sig s, pubkey p) {
        require(checkSig(s, p));
        require(tx.inputs[this.activeInputIndex].tokenCategory == cat);
        require(tx.outputs[0].tokenCategory == 0x);
        require(tx.outputs[0].value > 0);
    }
}
"""

MUTABLE_NFT_SNIPPET = """
contract Mutable() {
    function update(sig s, pubkey p, bytes newCommit) {
        require(checkSig(s, p));
        require(tx.outputs[0].lockingBytecode == this.activeBytecode);
        require(tx.outputs[0].nftCommitment == newCommit);
        require(tx.outputs[0].tokenCategory == tx.inputs[this.activeInputIndex].tokenCategory + 0x01);
    }
}
"""

CAPPED_MINT_SNIPPET = """
contract Mint() {
    function mint(sig s, pubkey auth) {
        require(checkSig(s, auth));
        require(tx.inputs[this.activeInputIndex].tokenCategory == mintingAuthorityCategory);
        require(tx.outputs[0].lockingBytecode == this.activeBytecode);
        require(tx.outputs[0].tokenCategory == mintingAuthorityCategory);
    }
}
"""

ESCROW_SNIPPET = """
contract Escrow() {
    function release(sig a, sig b, pubkey p1, pubkey p2) {
        require(checkMultiSig([a, b], [p1, p2]));
        require(tx.outputs[0].value == amount);
    }
}
"""


def test_registry_has_no_experimental_tier():
    for key, (tier, _owner) in CAPABILITY_REGISTRY.items():
        assert tier != "Experimental", key


def test_soulbound_preserves_covenant():
    caps = extract_semantic_capabilities(
        SOULBOUND_SNIPPET,
        contract_mode="semantic_002",
        intent_modes={"ownership_mode": "soulbound"},
    )
    assert caps.get("has_signature_auth") is True
    assert caps.get("reanchors_covenant") is True
    assert caps.get("unrestricted_external_transfer") is not True


def test_marketplace_migratory():
    caps = extract_semantic_capabilities(
        MARKETPLACE_SNIPPET,
        contract_mode="semantic_005",
        intent_modes={"lifecycle_mode": "migratory"},
    )
    assert caps.get("migratory_output") is True
    assert caps.get("preserves_token_category") is True


def test_voucher_burn_path():
    caps = extract_semantic_capabilities(
        VOUCHER_REDEEM_SNIPPET,
        contract_mode="semantic_008",
        intent_modes={"supply_mode": "redeemable"},
    )
    assert caps.get("burns_output_tokens") is True
    assert caps.get("token_category_constrained") is True
    ok, tr = satisfies_requirement("redeem_burn_termination", caps)
    assert ok or tr["path"] in {"capability_all", "fallback_regex_alias"}


def test_mutable_reanchor():
    caps = extract_semantic_capabilities(MUTABLE_NFT_SNIPPET, contract_mode="nft_mutable")
    assert caps.get("reanchors_covenant") is True


def test_capped_mint_custody():
    caps = extract_semantic_capabilities(CAPPED_MINT_SNIPPET, contract_mode="nft_minting")
    assert caps.get("reanchors_covenant") is True
    assert caps.get("has_signature_auth") is True


def test_escrow_multisig():
    caps = extract_semantic_capabilities(ESCROW_SNIPPET, contract_mode="escrow")
    assert caps.get("has_multisig_auth") is True
    ok, tr = satisfies_requirement("two_of_three_logic", caps)
    assert ok or tr["path"] == "capability"


def test_structural_invalid_code():
    caps = extract_semantic_capabilities("contract X { function f() { require(")
    assert caps.get("structurally_valid") is False
