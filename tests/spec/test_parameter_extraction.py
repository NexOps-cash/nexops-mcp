"""Tests for deterministic parameter extraction."""

from src.models import CapabilityInstance, ContractSpecification
from src.services.spec.conversation import apply_conversation_turn
from src.services.spec.parameter_extraction import extract_parameters_from_message


def _escrow_spec() -> ContractSpecification:
    return ContractSpecification(
        intent="BCH escrow for equipment purchase",
        capabilities=[
            CapabilityInstance(name="escrow"),
            CapabilityInstance(name="multisig"),
        ],
    )


def test_escrow_party_roles_extract_signers():
    spec = _escrow_spec()
    updates = extract_parameters_from_message(
        "buyer, seller, and a neutral arbiter hold the keys",
        spec,
    )
    assert updates["signers"] == ["Buyer", "Seller", "Arbiter"]


def test_both_parties_sign_sets_threshold_two():
    spec = _escrow_spec()
    spec.parameters["signers"] = ["Buyer", "Seller", "Arbiter"]
    updates = extract_parameters_from_message(
        "Funds may be released only after both buyer and seller sign.",
        spec,
    )
    assert updates.get("threshold") == 2


def test_reclaim_within_days_sets_timeout():
    spec = _escrow_spec()
    updates = extract_parameters_from_message(
        "If the seller does not complete delivery within 30 days, the buyer may reclaim the funds.",
        spec,
    )
    assert updates.get("timeout_days") == 30


def test_requirements_bullet_list_merges_fields():
    spec = _escrow_spec()
    text = """Requirements:
- Buyer deposits 20 BCH into escrow.
- Funds may be released only after both buyer and seller sign.
- If the seller does not complete delivery within 30 days, the buyer may reclaim the funds."""
    updates = extract_parameters_from_message(text, spec)
    assert updates.get("threshold") == 2
    assert updates.get("timeout_days") == 30
    assert "Buyer" in updates.get("signers", [])


def test_comma_separated_signers():
    spec = ContractSpecification(
        intent="multisig",
        capabilities=[CapabilityInstance(name="multisig")],
    )
    updates = extract_parameters_from_message("Alice,Bob,Carol", spec)
    assert updates["signers"] == ["Alice", "Bob", "Carol"]


def test_apply_conversation_turn_escrow_bullets():
    spec = _escrow_spec()
    updated = apply_conversation_turn(
        spec,
        "- If the seller does not complete delivery within 30 days, the buyer may reclaim the funds.",
    )
    assert updated.parameters.get("timeout_days") == 30


def test_founder_vesting_full_requirements():
    from src.models import CapabilityInstance, ContractSpecification

    spec = ContractSpecification(
        intent="Create a founder vesting vault",
        capabilities=[
            CapabilityInstance(name="vault"),
            CapabilityInstance(name="timelock"),
            CapabilityInstance(name="split"),
        ],
    )
    text = """Create a founder vesting vault.
Requirements:
- Funds remain locked for 180 days.
- After the lock expires, funds are released.
- Released funds are distributed:
  - 60% to Founder A
  - 40% to Founder B
- Preserve BCH value."""
    updates = extract_parameters_from_message(text, spec)
    assert updates.get("timeout_days") == 180
    assert updates.get("asset_type") == "bch"
    assert updates.get("recipients") == ["Founder A", "Founder B"]
    assert updates.get("shares") == [60, 40]
