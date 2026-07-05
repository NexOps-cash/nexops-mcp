"""Tests for Phase2 adapter (temporary bridge)."""

from src.models import (
    CapabilityInstance,
    ContractNode,
    ContractSpecification,
    ExecutionPlan,
    GenerationModule,
    SpecStatus,
    TransactionSpec,
    UTXOArchitecture,
)
from src.services.spec.phase2_adapter import resolve_effective_mode


def test_vault_contract_type_maps_to_vault_mode():
    utxo = UTXOArchitecture(
        contracts=[ContractNode(id="treasury", type="Vault")],
        transactions=[TransactionSpec(name="withdraw", inputs=["A"], outputs=["B"])],
    )
    plan = ExecutionPlan(modules=[GenerationModule(name="VaultModule", capability="treasury")])
    assert resolve_effective_mode(utxo, plan) == "vault"


def test_escrow_contract_type():
    utxo = UTXOArchitecture(contracts=[ContractNode(id="e", type="Escrow")])
    plan = ExecutionPlan(modules=[GenerationModule(name="EscrowModule", capability="escrow")])
    assert resolve_effective_mode(utxo, plan) == "escrow_2of3_nft"
