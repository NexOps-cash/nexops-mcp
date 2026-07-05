"""Human-readable specification review and confirm/modify transitions."""

from __future__ import annotations

from typing import Optional

from src.models import (
    ContractSpecification,
    ExecutionPlan,
    SpecStatus,
    SpecificationReview,
    UTXOArchitecture,
)
from src.services.spec.architecture import ArchitectureBuilder
from src.services.spec.planner import ModulePlanner


def render_specification(
    spec: ContractSpecification,
    utxo_architecture: Optional[UTXOArchitecture] = None,
) -> SpecificationReview:
    sections: dict = {
        "Core Pattern": [spec.intent or "Unnamed contract"],
        "Access Control": [],
        "Time Rules": [],
        "Assets": [],
        "Operations": [],
        "Security": [],
    }

    for cap in spec.capabilities:
        if cap.name in ("weighted_multisig", "multisig", "escrow"):
            sections["Access Control"].append(cap.name.replace("_", " ").title())
        elif cap.name == "linear_decay":
            sections["Time Rules"].append("Linear threshold change")
        elif cap.name in ("treasury", "vault", "withdrawal_policy", "auction"):
            sections["Assets"].append(cap.name.replace("_", " ").title())

    if spec.parameters.get("holders"):
        sections["Access Control"].append(f"Key holders: {spec.parameters['holders']}")
    if spec.parameters.get("weights"):
        sections["Access Control"].append(f"Voting weights: {spec.parameters['weights']}")
    if spec.parameters.get("initial_threshold") is not None:
        sections["Time Rules"].append(f"Initial threshold: {spec.parameters['initial_threshold']}")
    if spec.parameters.get("final_threshold") is not None:
        sections["Time Rules"].append(f"Final threshold: {spec.parameters['final_threshold']}")
    if spec.parameters.get("duration_days"):
        sections["Time Rules"].append(f"Duration: {spec.parameters['duration_days']} days")
    if spec.parameters.get("asset_type"):
        sections["Assets"].append(f"Asset: {spec.parameters['asset_type']}")
    if spec.parameters.get("signers"):
        sections["Access Control"].append(f"Signers: {spec.parameters['signers']}")
    if spec.parameters.get("threshold"):
        sections["Access Control"].append(f"Threshold: {spec.parameters['threshold']}")
    if spec.parameters.get("start_price") is not None:
        sections["Assets"].append(f"Start price: {spec.parameters['start_price']} satoshis")
    if spec.parameters.get("min_price") is not None:
        sections["Assets"].append(f"Floor price: {spec.parameters['min_price']} satoshis")

    sections["Security"].extend([
        "Authorization required on spend paths",
        "Value preservation on covenant continuation",
    ])

    if utxo_architecture is None:
        modules, _ = ModulePlanner.select_modules(spec)
        plan = ExecutionPlan(modules=modules, order=[m.name for m in modules])
        utxo_architecture = ArchitectureBuilder.build(plan, spec)

    for tx in utxo_architecture.transactions:
        sections["Operations"].append(
            f"{tx.name}: [{', '.join(tx.inputs)}] -> [{', '.join(tx.outputs)}]"
        )
    for state in utxo_architecture.state_objects:
        sections["Security"].append(f"State {state.name}: {state.storage}")

    return SpecificationReview(
        sections=sections,
        utxo_architecture=utxo_architecture,
        spec_snapshot=spec.model_copy(deep=True),
    )


def confirm_specification(spec: ContractSpecification) -> ContractSpecification:
    spec.status = SpecStatus.CONFIRMED
    return spec


def modify_specification(spec: ContractSpecification) -> ContractSpecification:
    spec.status = SpecStatus.NEEDS_INPUT
    return spec
