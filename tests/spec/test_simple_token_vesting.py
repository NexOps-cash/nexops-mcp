"""Simple CashTokens timelock vesting vs founder vesting."""

from src.models import ContractSpecification
from src.services.spec.detection import (
    is_founder_vesting_spec,
    is_simple_token_timelock_vesting,
)
from src.services.spec.discovery import try_discover_specification
from src.services.spec.intent_pivot import looks_like_spec_replacement, try_pivot_specification
from src.services.spec.parameter_extraction import extract_parameters_from_message


_REQUIREMENTS = """no lets do this Create a CashTokens vesting contract.Requirements:
- Lock 100,000 fungible tokens for 365 days.
- Tokens cannot move before expiry.
- After expiry, the beneficiary may claim all tokens.
- Token category must remain unchanged.
- Token amount must be preserved exactly.
- Preserve BCH dust outputs."""


def test_simple_token_vesting_detected():
    assert is_simple_token_timelock_vesting(_REQUIREMENTS)


def test_requirements_not_founder_vesting():
    spec = ContractSpecification()
    discovered = try_discover_specification(spec, _REQUIREMENTS)
    assert discovered is not None
    names = {c.name for c in discovered.capabilities}
    assert names == {"timelock", "vault"}
    assert "split" not in names
    assert not is_founder_vesting_spec(discovered)


def test_requirements_extract_lock_and_asset():
    spec = try_discover_specification(ContractSpecification(), _REQUIREMENTS)
    assert spec is not None
    params = extract_parameters_from_message(_REQUIREMENTS, spec)
    assert params.get("timeout_days") == 365
    assert params.get("asset_type") == "ft"
    assert params.get("token_amount") == 100_000


def test_pivot_from_founder_to_token_vesting():
    founder = try_discover_specification(ContractSpecification(), "lets do vesting first")
    assert founder is not None
    assert looks_like_spec_replacement(_REQUIREMENTS)
    pivoted, ack = try_pivot_specification(founder, _REQUIREMENTS)
    assert pivoted is not None
    assert "simpler" in ack.lower() or "beneficiary" in ack.lower()
    names = {c.name for c in pivoted.capabilities}
    assert "split" not in names
    assert pivoted.parameters.get("timeout_days") == 365
    assert pivoted.parameters.get("asset_type") == "ft"
