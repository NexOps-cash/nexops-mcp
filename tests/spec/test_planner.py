"""Tests for module planner."""

from src.models import CapabilityInstance, ContractSpecification, SpecStatus
from src.services.spec.planner import ModulePlanner


def test_treasury_maps_to_vault_module():
    spec = ContractSpecification(
        intent="treasury",
        capabilities=[
            CapabilityInstance(name="treasury", parameters={}),
            CapabilityInstance(name="weighted_multisig", parameters={}),
        ],
        parameters={"asset_type": "BCH"},
        status=SpecStatus.CONFIRMED,
    )
    modules, decisions = ModulePlanner.select_modules(spec)
    assert any(m.name == "VaultModule" for m in modules)
    assert decisions.get("treasury") == "VaultModule"


def test_treasury_vault_linear_decay_dedupes_vault_module():
    spec = ContractSpecification(
        intent="treasury with decay",
        capabilities=[
            CapabilityInstance(name="treasury", parameters={}),
            CapabilityInstance(name="vault", parameters={}),
            CapabilityInstance(name="linear_decay", parameters={}),
        ],
        parameters={"asset_type": "ft", "duration_days": 30},
        status=SpecStatus.CONFIRMED,
    )
    modules, decisions = ModulePlanner.select_modules(spec)
    names = [m.name for m in modules]
    assert names.count("VaultModule") == 1
    assert names == ["VaultModule", "LinearThresholdModule"]
    assert decisions.get("treasury") == "VaultModule"
    assert decisions.get("vault") == "VaultModule"
    assert decisions.get("linear_decay") == "LinearThresholdModule"


def test_linear_decay_module_selection():
    spec = ContractSpecification(
        intent="vesting schedule",
        capabilities=[CapabilityInstance(name="linear_decay", parameters={})],
        parameters={"lifecycle_mode": "vesting"},
        status=SpecStatus.CONFIRMED,
    )
    modules, decisions = ModulePlanner.select_modules(spec)
    assert decisions.get("linear_decay") == "VestingScheduleModule"
