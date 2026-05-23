"""Keyword → semantic field normalization."""

import pytest
from src.models import IntentModel
from src.services.semantic_normalization import apply_semantic_normalization


def _model(**kwargs):
    base = dict(
        contract_type="generic",
        features=[],
        token_class=None,
    )
    base.update(kwargs)
    return IntentModel(**base)


def test_soulbound_keywords():
    m = _model()
    apply_semantic_normalization(
        m,
        "soulbound identity nft that can update metadata commitment but cannot transfer ownership",
    )
    assert m.ownership_mode == "soulbound"
    assert m.lifecycle_mode == "state_transition"
    assert m.token_class == "nft_mutable"


def test_marketplace_migratory():
    m = _model()
    apply_semantic_normalization(
        m,
        "marketplace covenant that locks immutable nft until buyer pays exact bch amount to seller",
    )
    assert m.lifecycle_mode == "migratory"
    assert m.ownership_mode == "transferable"
    assert "marketplace" in m.features


def test_burnable_ft():
    m = _model()
    apply_semantic_normalization(
        m,
        "burnable fungible token covenant where users can destroy tokens but never mint new supply",
    )
    assert m.supply_mode == "burnable"
    assert m.token_class == "ft"


def test_voucher_redeemable():
    m = _model()
    apply_semantic_normalization(
        m,
        "redeemable voucher token that burns itself when exchanged for bch payout",
    )
    assert m.supply_mode == "redeemable"
    assert m.lifecycle_mode == "terminating"


def test_streaming_expiry_schema():
    m = _model()
    apply_semantic_normalization(
        m,
        "subscription nft where nftcommitment stores expiry timestamp and renewals update state",
    )
    assert m.commitment_schema == "expiry"
    assert m.lifecycle_mode == "state_transition"
