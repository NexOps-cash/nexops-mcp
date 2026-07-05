"""Tests for composer and architecture."""

import pytest

from src.models import CapabilityInstance, ContractSpecification, SpecStatus
from src.services.spec.composer import Composer, SpecNotConfirmedError
from src.services.spec.architecture import ArchitectureBuilder
from src.services.spec.planner import ModulePlanner


def test_composer_rejects_unconfirmed():
    spec = ContractSpecification(
        intent="treasury",
        capabilities=[CapabilityInstance(name="treasury", parameters={})],
        status=SpecStatus.DRAFT,
    )
    with pytest.raises(SpecNotConfirmedError):
        Composer.compose(spec)


def test_composer_produces_utxo_architecture():
    spec = ContractSpecification(
        intent="treasury",
        capabilities=[
            CapabilityInstance(name="treasury", parameters={}),
            CapabilityInstance(name="weighted_multisig", parameters={}),
        ],
        parameters={
            "asset_type": "BCH",
            "holders": 3,
            "weights": [56, 30, 14],
        },
        status=SpecStatus.CONFIRMED,
    )
    plan, utxo = Composer.compose(spec)
    assert plan.modules
    assert utxo.contracts
    assert any(c.type == "Vault" for c in utxo.contracts)
    assert any(t.name == "withdraw" for t in utxo.transactions)
    assert any(s.storage == "Mutable NFT Commitment" for s in utxo.state_objects)


def test_modules_have_no_effective_mode():
    spec = ContractSpecification(
        intent="treasury",
        capabilities=[CapabilityInstance(name="vault", parameters={})],
        parameters={"asset_type": "BCH"},
        status=SpecStatus.CONFIRMED,
    )
    plan, _ = Composer.compose(spec)
    for mod in plan.modules:
        assert not hasattr(mod, "effective_mode") or "effective_mode" not in mod.model_fields
