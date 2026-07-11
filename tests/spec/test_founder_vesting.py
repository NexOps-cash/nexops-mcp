"""Founder vesting must not route through treasury linear_decay."""

from __future__ import annotations

import pytest

from src.models import ContractSpecification
from src.services.spec.conversation import apply_conversation_turn, fields_to_ask
from src.services.spec.detection import (
    detect_capabilities,
    explicit_founder_vesting_choice,
    is_founder_vesting_spec,
    normalize_founder_vesting_spec,
)
from src.models import RawIntent
from src.services.spec.discovery import try_discover_specification
from src.services.spec.parameter_extraction import extract_parameters_from_message
from src.services.spec.validator import SpecValidator


def test_explicit_vesting_choice_detected():
    assert explicit_founder_vesting_choice("lets do vesting first") is True


def test_try_discover_promotes_founder_vesting():
    spec = ContractSpecification(intent="hello")
    discovered = try_discover_specification(spec, "lets do vesting first")
    assert discovered is not None
    names = {c.name for c in discovered.capabilities}
    assert names == {"split", "timelock", "vault"}
    assert discovered.parameters.get("lifecycle_mode") == "vesting"


def test_decay_percent_does_not_add_linear_decay_for_founder_vesting():
    spec = normalize_founder_vesting_spec(
        try_discover_specification(ContractSpecification(), "lets do vesting first")  # type: ignore[arg-type]
    )
    spec = apply_conversation_turn(spec, "decay 23% a year")
    spec = normalize_founder_vesting_spec(spec)
    cap_names = {c.name for c in spec.capabilities}
    assert "linear_decay" not in cap_names
    assert is_founder_vesting_spec(spec)


def test_extract_founder_vesting_timeline():
    spec = try_discover_specification(ContractSpecification(), "lets do vesting first")
    assert spec is not None
    params = extract_parameters_from_message(
        "2 founders 4 year vesting 1 year cliff",
        spec,
    )
    assert params.get("timeout_days") == 365
    assert params.get("vesting_years") == 4
    assert params.get("recipients") == ["Founder A", "Founder B"]


def test_fields_to_ask_skips_treasury_decay_fields():
    spec = try_discover_specification(ContractSpecification(), "lets do vesting first")
    assert spec is not None
    spec.parameters["initial_threshold"] = 50
    validation = SpecValidator.validate(spec)
    ask = fields_to_ask(spec, validation)
    assert "initial_threshold" not in ask
    assert "duration_days" not in ask


@pytest.mark.asyncio
async def test_pipeline_founder_vesting_not_linear_decay():
    from src.services.spec.orchestrator import run_spec_pipeline

    intent = (
        "Founder vesting for 2 founders. "
        "4 year vesting with 1 year cliff. 50/50 split. BCH."
    )
    spec, _, _, _, _, _ = await run_spec_pipeline(intent, resolution_mode="non_interactive")
    names = {c.name for c in spec.capabilities}
    assert "linear_decay" not in names
    assert {"vault", "timelock", "split"}.issubset(names)
