"""Conversation-level tests for incremental specification updates."""

from unittest.mock import AsyncMock, patch

import pytest

from src.models import CapabilityInstance, ContractSpecification, SpecStatus
from src.services.spec.assistant import SpecificationAssistant
from src.services.spec.conversation import apply_conversation_turn, build_opening_message, offer_default_for_uncertainty
from src.services.spec.field_guidance import suggest_field_default
from src.services.spec.validator import SpecValidator


def _treasury_decay_spec() -> ContractSpecification:
    return ContractSpecification(
        intent="build me a treasury with decay",
        capabilities=[
            CapabilityInstance(name="linear_decay", parameters={}),
            CapabilityInstance(name="treasury", parameters={}),
            CapabilityInstance(name="vault", parameters={}),
        ],
    )


def test_incremental_updates_converge_without_llm():
    spec = _treasury_decay_spec()

    spec = apply_conversation_turn(spec, "50 30 days")
    assert spec.parameters["initial_threshold"] == 50
    assert spec.parameters["duration_days"] == 30
    assert "initial_threshold" in spec.confirmed_fields
    assert "duration_days" in spec.confirmed_fields

    spec = apply_conversation_turn(spec, "asset ft")
    assert spec.parameters["asset_type"] == "ft"
    assert "asset_type" in spec.confirmed_fields

    spec = apply_conversation_turn(spec, "final 12")
    assert spec.parameters["final_threshold"] == 12
    assert "final_threshold" in spec.confirmed_fields

    validation = SpecValidator.validate(spec)
    assert validation.is_complete is True
    assert validation.missing_fields == []


def test_affirmation_applies_pending_parameters():
    spec = _treasury_decay_spec()
    spec.parameters = {"initial_threshold": 50, "duration_days": 30}
    spec.confirmed_fields = ["initial_threshold", "duration_days"]
    spec.pending_parameters = {"final_threshold": 12, "asset_type": "ft"}

    spec = apply_conversation_turn(spec, "yes")

    assert spec.parameters["final_threshold"] == 12
    assert spec.parameters["asset_type"] == "ft"
    assert "final_threshold" in spec.confirmed_fields
    assert "asset_type" in spec.confirmed_fields
    assert spec.pending_parameters == {}
    assert SpecValidator.validate(spec).is_complete is True


def test_confirmed_fields_are_not_re_reported_as_missing():
    spec = _treasury_decay_spec()
    spec.parameters = {
        "initial_threshold": 50,
        "final_threshold": 12,
        "duration_days": 30,
        "asset_type": "ft",
    }
    spec.confirmed_fields = [
        "initial_threshold",
        "final_threshold",
        "duration_days",
        "asset_type",
    ]

    validation = SpecValidator.validate(spec)
    assert validation.is_complete is True
    assert validation.missing_fields == []


def test_dense_first_message_parses_multiple_fields():
    spec = _treasury_decay_spec()
    spec = apply_conversation_turn(spec, "50 50 fina 1 30 days hold asset is ft")

    assert spec.parameters["initial_threshold"] == 50
    assert spec.parameters["duration_days"] == 30
    assert spec.parameters["asset_type"] == "ft"
    assert spec.parameters["final_threshold"] in (1, 50)


def test_use_standard_bro_applies_initial_threshold_immediately():
    spec = _treasury_decay_spec()
    msg, updated, suggested = offer_default_for_uncertainty(spec, "use standard bro")
    assert msg is not None
    assert updated.parameters.get("initial_threshold") == 50
    assert "initial_threshold" in updated.confirmed_fields
    assert updated.pending_parameters.get("initial_threshold") is None
    assert "50" in msg
    assert "Next:" in msg
    assert suggested == {"initial_threshold": 50}


def test_use_standard_offers_final_threshold_matching_initial():
    spec = _treasury_decay_spec()
    spec = apply_conversation_turn(spec, "50 30 days")
    assert spec.parameters["initial_threshold"] == 50

    msg, updated, suggested = offer_default_for_uncertainty(spec, "not sure")
    assert msg is not None
    assert updated.pending_parameters.get("final_threshold") == 50
    assert suggested == {"final_threshold": 50}

    spec = apply_conversation_turn(updated, "yes")
    assert spec.parameters["final_threshold"] == 50
    assert "asset_type" in SpecValidator.validate(spec).missing_fields


def test_suggest_final_matches_initial():
    spec = _treasury_decay_spec()
    spec.parameters = {"initial_threshold": 50, "duration_days": 30}
    value, explanation = suggest_field_default(spec, "final_threshold")
    assert value == 50
    assert "50" in explanation


def test_suggest_initial_threshold_for_treasury_decay():
    spec = _treasury_decay_spec()
    value, explanation = suggest_field_default(spec, "initial_threshold")
    assert value == 50
    assert "50" in explanation


def test_opening_message_is_single_question():
    spec = _treasury_decay_spec()
    opening = build_opening_message(spec)
    assert "step by step" in opening.lower()
    assert "Progress:" in opening
    assert opening.count("?") >= 1


@pytest.mark.asyncio
async def test_assistant_persists_deterministic_updates_when_llm_omits_parameters():
    spec = _treasury_decay_spec()
    validation = SpecValidator.validate(spec)

    llm_response = '{"message": "Thanks, tell me more.", "parameters": {}}'

    with patch("src.services.llm.factory.LLMFactory.get_provider") as mock_factory:
        provider = AsyncMock()
        provider.complete = AsyncMock(return_value=llm_response)
        mock_factory.return_value = provider

        turn = await SpecificationAssistant.respond(
            spec,
            validation,
            "50 30 days",
        )

    assert turn.updated_spec.parameters["initial_threshold"] == 50
    assert turn.updated_spec.parameters["duration_days"] == 30
    assert "initial_threshold" not in turn.still_missing
    assert "duration_days" not in turn.still_missing
    assert "initial_threshold" in turn.updated_spec.confirmed_fields


@pytest.mark.asyncio
async def test_assistant_full_conversation_converges_with_empty_llm_parameters():
    spec = _treasury_decay_spec()
    llm_empty = '{"message": "ok", "parameters": {}}'

    with patch("src.services.llm.factory.LLMFactory.get_provider") as mock_factory:
        provider = AsyncMock()
        provider.complete = AsyncMock(return_value=llm_empty)
        mock_factory.return_value = provider

        for message in ("50 30 days", "asset ft", "final 12"):
            validation = SpecValidator.validate(spec)
            turn = await SpecificationAssistant.respond(spec, validation, message)
            spec = turn.updated_spec

    validation = SpecValidator.validate(spec)
    assert validation.is_complete is True
    assert spec.parameters["initial_threshold"] == 50
    assert spec.parameters["duration_days"] == 30
    assert spec.parameters["asset_type"] == "ft"
    assert spec.parameters["final_threshold"] == 12
