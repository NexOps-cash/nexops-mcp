"""Fast /generate intent routing must not default to multisig."""

from src.models import RawIntent
from src.services.spec.detection import detect_capabilities, is_cliff_vesting_vault


def test_vesting_contract_not_multisig():
    spec = detect_capabilities(
        RawIntent(intent="generic", capabilities=[]),
        "a vesting contract",
        allow_generic_multisig_default=False,
    )
    names = {c.name for c in spec.capabilities}
    assert "multisig" not in names
    assert is_cliff_vesting_vault("a vesting contract")
    assert "vault" in names or "timelock" in names


def test_hashlock_not_multisig():
    spec = detect_capabilities(
        RawIntent(intent="generic", capabilities=[]),
        "hashlock",
        allow_generic_multisig_default=False,
    )
    names = {c.name for c in spec.capabilities}
    assert "multisig" not in names
    assert "timelock" in names or "escrow" in names


def test_vault_alone_not_treasury_governance():
    spec = detect_capabilities(
        RawIntent(intent="vault", capabilities=[]),
        "vault contract",
        allow_generic_multisig_default=False,
    )
    names = {c.name for c in spec.capabilities}
    assert "weighted_multisig" not in names
    assert "vault" in names


def test_linear_decay_not_bare_vault_only():
    spec = detect_capabilities(
        RawIntent(intent="generic", capabilities=["linear_decay"]),
        "linear decay",
        allow_generic_multisig_default=False,
    )
    names = {c.name for c in spec.capabilities}
    assert "linear_decay" in names
    assert "multisig" not in names
