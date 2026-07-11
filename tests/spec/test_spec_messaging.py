"""Tests for rival-style conversational messaging."""

from src.models import ContractSpecification
from src.services.spec.discovery import try_discover_specification
from src.services.spec.intent_pivot import try_pivot_specification
from src.services.spec.spec_messaging import (
    ambiguous_pattern_message,
    apply_parameterization_preferences,
    founder_vesting_ack_message,
    is_parameterization_request,
    maybe_completion_message,
    token_vesting_pivot_message,
)

_REQUIREMENTS = """lets do this Create a CashTokens vesting contract. Requirements:
- Lock 100,000 fungible tokens for 365 days.
- Tokens cannot move before expiry.
- After expiry, the beneficiary may claim all tokens."""


def test_ambiguous_pattern_explains_both_options():
    msg = ambiguous_pattern_message()
    assert "Founder vesting" in msg
    assert "Treasury governance" in msg


def test_founder_cliff_acknowledges_schedule():
    spec = try_discover_specification(
        ContractSpecification(),
        "lets do founder vesting 4 year 1 year cliff",
    )
    assert spec is not None
    assert spec.parameters.get("vesting_years") == 4
    assert spec.parameters.get("timeout_days") == 365
    msg = founder_vesting_ack_message(spec)
    assert "4-year" in msg or "4 year" in msg.lower()
    assert "linear" in msg.lower()


def test_token_vesting_pivot_asks_smart_questions():
    spec = try_discover_specification(ContractSpecification(), _REQUIREMENTS)
    assert spec is not None
    _, msg = try_pivot_specification(spec, _REQUIREMENTS)
    assert "Beneficiary" in msg
    assert "deploy" in msg.lower()


def test_parameterization_summary():
    spec = try_discover_specification(ContractSpecification(), _REQUIREMENTS)
    assert spec is not None
    updated = apply_parameterization_preferences(
        spec,
        "use parameters when possible and when contract deployed start",
    )
    assert is_parameterization_request("use parameters at deploy")
    assert updated.parameters.get("lock_start") == "deployment"
    assert updated.parameters.get("beneficiary_pubkey") == "PARAMETER"
    summary = maybe_completion_message(updated)
    assert summary is not None
    assert "365" in summary
    assert "deploy" in summary.lower()
