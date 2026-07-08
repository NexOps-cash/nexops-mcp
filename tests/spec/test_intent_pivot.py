"""Tests for mid-chat pivots and unsafe-request handling."""

from src.models import CapabilityInstance, ContractSpecification
from src.services.spec.intent_pivot import (
    backdoor_refusal_message,
    is_backdoor_request,
    looks_like_cashscript_injection,
    try_pivot_specification,
)


def test_backdoor_is_detected():
    assert is_backdoor_request("i want a small backdoor code in contract only i know about")
    assert is_backdoor_request("in specs i want small backdoor")
    assert not is_backdoor_request("i want a documented owner recovery key")


def test_cashscript_injection_requires_real_syntax():
    assert looks_like_cashscript_injection("pragma cashscript ^0.13.0;")
    assert not looks_like_cashscript_injection("i want a small backdoor code in contract only i know")


def test_pivot_fund_lock_away_from_dao():
    dao = ContractSpecification(
        intent="governance dao",
        capabilities=[
            CapabilityInstance(name="treasury"),
            CapabilityInstance(name="vault"),
            CapabilityInstance(name="weighted_multisig"),
            CapabilityInstance(name="multisig"),
        ],
        parameters={"signers": ["a", "b"]},
        confirmed_fields=["signers"],
    )
    pivoted, ack = try_pivot_specification(dao, "lets do a fund lock code instead")
    assert pivoted is not None
    names = {c.name for c in pivoted.capabilities}
    assert "vault" in names
    assert "timelock" in names
    assert "weighted_multisig" not in names
    assert pivoted.parameters == {}
    assert ack and "pivoting" in ack.lower()


def test_pivot_burn_forever():
    dao = ContractSpecification(
        intent="dao",
        capabilities=[CapabilityInstance(name="multisig")],
    )
    pivoted, ack = try_pivot_specification(dao, "we must never release once gone forever stuck")
    assert pivoted is not None
    names = {c.name for c in pivoted.capabilities}
    assert "vault" in names
    assert "forever" in ack.lower() or "permanent" in ack.lower() or "irreversible" in ack.lower()


def test_refusal_message_offers_honest_alternatives():
    msg = backdoor_refusal_message()
    assert "backdoor" in msg.lower()
    assert "timelock" in msg.lower() or "burn" in msg.lower()
