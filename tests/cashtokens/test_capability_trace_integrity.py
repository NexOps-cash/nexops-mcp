"""Wave 2A.5 — Capability trace integrity (4 capabilities × 3 fixture classes)."""

from pathlib import Path

import pytest

from src.services.semantic_capabilities import extract_semantic_capabilities
from tests.cashtokens._capability_trace_helpers import assert_capability_trace

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "capability_traces"
GOLDEN = Path(__file__).resolve().parents[2] / "knowledge" / "golden" / "patterns"

CAPABILITIES = (
    "enforces_supply_cap",
    "preserves_token_category",
    "preserves_token_amount",
    "capability_retained",
)

FIXTURE_CLASSES = ("valid", "missing_evidence", "misleading_lookalike")

MATRIX = [
    (cap, cls, cls == "valid")
    for cap in CAPABILITIES
    for cls in FIXTURE_CLASSES
]


@pytest.mark.parametrize("capability,fixture_class,expected", MATRIX)
def test_capability_trace_matrix(capability: str, fixture_class: str, expected: bool):
    path = FIXTURES / capability / f"{fixture_class}.cash"
    code = path.read_text(encoding="utf-8")
    caps = extract_semantic_capabilities(code, contract_mode=capability)
    subs = None
    if capability == "enforces_supply_cap" and expected:
        subs = ["maxsupply", "<="]
    if capability == "preserves_token_category" and expected:
        subs = ["tokencategory", "activeinputindex"]
    if capability == "preserves_token_amount" and expected:
        subs = ["tokenamount", "activeinputindex"]
    if capability == "capability_retained" and expected:
        subs = ["lockingbytecode", "activebytecode"]
    assert_capability_trace(caps, capability, expected, required_anchor_substrings=subs)


@pytest.mark.parametrize(
    "golden_file,capability",
    [
        ("ft_mint_authority.cash", "enforces_supply_cap"),
        ("ft_transfer.cash", "preserves_token_category"),
        ("ft_transfer.cash", "preserves_token_amount"),
        ("nft_minting_authority.cash", "capability_retained"),
    ],
)
def test_golden_satisfies_valid_trace(golden_file: str, capability: str):
    code = (GOLDEN / golden_file).read_text(encoding="utf-8")
    caps = extract_semantic_capabilities(code, contract_mode=capability)
    assert_capability_trace(caps, capability, True)
