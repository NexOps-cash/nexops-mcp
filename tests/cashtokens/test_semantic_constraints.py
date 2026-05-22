"""Constraint precedence resolution."""

from src.models import IntentModel
from src.services.semantic_profiles import resolve_semantic_constraints


def test_soulbound_blocks_migratory():
    m = IntentModel(
        ownership_mode="soulbound",
        lifecycle_mode="migratory",
    )
    resolve_semantic_constraints(m)
    assert m.lifecycle_mode == "state_transition"


def test_covenant_retained_blocks_terminating():
    m = IntentModel(
        ownership_mode="covenant_retained",
        lifecycle_mode="terminating",
        supply_mode="capped_mint",
    )
    resolve_semantic_constraints(m)
    assert m.lifecycle_mode == "persistent"
    assert m.ownership_mode == "covenant_retained"
