"""Tests for IntentModel derivation from ContractSpecification."""

from src.models import CapabilityInstance, ContractSpecification
from src.services.spec.orchestrator import derive_intent_model, _normalize_signers
from src.services.spec.parameter_extraction import apply_parameter_updates, extract_parameters_from_message


def test_normalize_signers_from_int():
    assert _normalize_signers(4) == ["Signer1", "Signer2", "Signer3", "Signer4"]


def test_derive_intent_model_tolerates_int_signers():
    spec = ContractSpecification(
        intent="governance dao",
        capabilities=[CapabilityInstance(name="multisig")],
        parameters={"signers": 4, "threshold": 1},
    )
    model = derive_intent_model(spec, "multisig")
    assert model.signers == ["Signer1", "Signer2", "Signer3", "Signer4"]
    assert model.threshold == 1


def test_four_people_equal_weights_extracts_signers_list():
    spec = ContractSpecification(
        intent="dao",
        capabilities=[CapabilityInstance(name="multisig")],
    )
    updates = extract_parameters_from_message("4 ppl equal weights", spec)
    assert updates["signers"] == ["Signer1", "Signer2", "Signer3", "Signer4"]

    updated = apply_parameter_updates(spec, updates)
    model = derive_intent_model(updated, "multisig")
    assert len(model.signers) == 4
    assert model.signers[0] == "Signer1"


def test_one_enough_extracts_threshold():
    spec = ContractSpecification(
        intent="dao",
        capabilities=[CapabilityInstance(name="multisig")],
        parameters={"signers": ["A", "B", "C", "D"]},
    )
    updates = extract_parameters_from_message("1 enough", spec)
    assert updates.get("threshold") == 1
