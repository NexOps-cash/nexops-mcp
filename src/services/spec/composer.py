"""Composer — assembles ExecutionPlan + UTXOArchitecture (confirmed specs only)."""

from __future__ import annotations

from typing import Tuple

from src.models import ContractSpecification, ExecutionPlan, GenerationModule, SpecStatus, UTXOArchitecture
from src.services.spec.architecture import ArchitectureBuilder
from src.services.spec.planner import ModulePlanner


class SpecNotConfirmedError(ValueError):
    pass


class Composer:
    @staticmethod
    def compose(spec: ContractSpecification) -> Tuple[ExecutionPlan, UTXOArchitecture]:
        if spec.status != SpecStatus.CONFIRMED:
            raise SpecNotConfirmedError(
                f"Composer requires status=confirmed, got {spec.status}"
            )

        modules, _decisions = ModulePlanner.select_modules(spec)
        order = [m.name for m in modules]
        dependencies = {m.name: list(m.depends_on) for m in modules}
        shared = dict(spec.parameters)

        plan = ExecutionPlan(
            modules=modules,
            order=order,
            dependencies=dependencies,
            shared_parameters=shared,
        )
        utxo = ArchitectureBuilder.build(plan, spec)
        return plan, utxo
