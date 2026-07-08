"""Deterministic specification validator — no user-facing questions."""

from __future__ import annotations

from typing import Any, Dict, List

from src.models import ContractSpecification, ValidationResult
from src.services.spec.capabilities import get_capability
from src.services.spec.parameter_extraction import is_empty_value


class SpecValidator:
    @staticmethod
    def validate(spec: ContractSpecification) -> ValidationResult:
        missing: List[str] = []
        capability_context: Dict[str, dict] = {}
        recommendations: Dict[str, List[str]] = {}

        if not spec.capabilities:
            return ValidationResult(
                missing_fields=["contract_type"],
                capability_context=capability_context,
                recommendations_available=recommendations,
                is_complete=False,
            )

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
                if SpecValidator._field_is_satisfied(spec, fs.name):
                    continue
                if fs.name not in missing:
                    missing.append(fs.name)

        return ValidationResult(
            missing_fields=missing,
            capability_context=capability_context,
            recommendations_available=recommendations,
            is_complete=len(missing) == 0,
        )

    @staticmethod
    def _field_is_satisfied(spec: ContractSpecification, field_name: str) -> bool:
        val = spec.parameters.get(field_name)
        if not is_empty_value(val):
            return True
        # Confirmed fields with empty values still count as missing until filled.
        return False
