"""Deterministic specification validator — no user-facing questions."""

from __future__ import annotations

from typing import Dict, List

from src.models import ContractSpecification, ValidationResult
from src.services.spec.capabilities import get_capability


class SpecValidator:
    @staticmethod
    def validate(spec: ContractSpecification) -> ValidationResult:
        missing: List[str] = []
        capability_context: Dict[str, dict] = {}
        recommendations: Dict[str, List[str]] = {}

        for cap_inst in spec.capabilities:
            cap = get_capability(cap_inst.name)
            if not cap:
                continue
            capability_context[cap.name] = {
                "documentation": cap.documentation,
                "examples": cap.examples,
            }
            if cap.recommendations:
                recommendations[cap.name] = list(cap.recommendations)
            for fs in cap.required_fields:
                val = spec.parameters.get(fs.name)
                if val is None or val == "" or val == []:
                    if fs.name not in missing:
                        missing.append(fs.name)

        return ValidationResult(
            missing_fields=missing,
            capability_context=capability_context,
            recommendations_available=recommendations,
            is_complete=len(missing) == 0,
        )
