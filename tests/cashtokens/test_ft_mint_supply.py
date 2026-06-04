"""Wave 2A — FT mint supply enforcement (capability, lint, detector)."""

from pathlib import Path

import pytest

from src.services.anti_pattern_detectors import UnboundedMintDetector
from src.services.dsl_lint import DSLLinter, _mint_supply_cap_in_requires
from src.services.semantic_capabilities import extract_semantic_capabilities
from src.utils.cashscript_ast import CashScriptAST

ROOT = Path(__file__).resolve().parents[2]
GOLDEN = ROOT / "knowledge" / "golden" / "patterns" / "ft_mint_authority.cash"

CAPPED_MINT = """
pragma cashscript ^0.13.0;
contract C(pubkey auth, bytes32 cat, int maxSupply, int totalMinted) {
    function mint(sig s, int mintAmount, bytes dest) {
        require(checkSig(s, auth));
        require(totalMinted + mintAmount <= maxSupply);
        require(tx.outputs[0].tokenCategory == cat);
        require(tx.outputs[0].tokenAmount == mintAmount);
    }
}
"""

UNBOUNDED_MINT = """
pragma cashscript ^0.13.0;
contract C(pubkey auth, bytes32 cat, int maxSupply, int totalMinted) {
    function mint(sig s, int mintAmount, bytes dest) {
        require(checkSig(s, auth));
        require(tx.outputs[0].tokenCategory == cat);
        require(tx.outputs[0].tokenAmount == mintAmount);
    }
}
"""

LOOKALIKE_MAXSUPPLY = """
pragma cashscript ^0.13.0;
contract C(pubkey auth, bytes32 cat, int maxSupply, int totalMinted) {
    function mint(sig s, int mintAmount, bytes dest) {
        int cap = maxSupply;
        require(checkSig(s, auth));
        require(tx.outputs[0].tokenAmount == mintAmount);
    }
}
"""


@pytest.fixture
def golden_code():
    return GOLDEN.read_text(encoding="utf-8")


def test_golden_enforces_supply_cap(golden_code):
    caps = extract_semantic_capabilities(golden_code, contract_mode="ft_mint_authority")
    assert caps.get("enforces_supply_cap") is True


def test_capped_mint_capability_true():
    caps = extract_semantic_capabilities(CAPPED_MINT, contract_mode="ft_mint")
    assert caps.get("enforces_supply_cap") is True


def test_unbounded_mint_capability_false():
    caps = extract_semantic_capabilities(UNBOUNDED_MINT, contract_mode="ft_mint")
    assert caps.get("enforces_supply_cap") is not True


def test_lookalike_maxsupply_only_false():
    caps = extract_semantic_capabilities(LOOKALIKE_MAXSUPPLY, contract_mode="ft_mint")
    assert caps.get("enforces_supply_cap") is not True


def test_mint_supply_cap_helper():
    assert _mint_supply_cap_in_requires(CAPPED_MINT) is True
    assert _mint_supply_cap_in_requires(UNBOUNDED_MINT) is False
    assert _mint_supply_cap_in_requires(LOOKALIKE_MAXSUPPLY) is False


def test_lnc_017_blocks_ft_mint_without_cap():
    linter = DSLLinter()
    result = linter.lint(
        UNBOUNDED_MINT,
        contract_mode="ft_mint_authority",
        semantic={"supply_mode": "capped_mint"},
    )
    assert result["passed"] is False
    assert any(v["rule_id"] == "LNC-017" for v in result["violations"])


def test_lnc_017_passes_golden(golden_code):
    linter = DSLLinter()
    result = linter.lint(
        golden_code,
        contract_mode="ft_mint_authority",
        semantic={"supply_mode": "capped_mint"},
    )
    assert result["passed"] is True


def test_unbounded_mint_detector_fires():
    det = UnboundedMintDetector()
    ast = CashScriptAST(UNBOUNDED_MINT, contract_mode="ft_mint")
    v = det.detect(ast)
    assert v is not None
    assert v.rule == "unbounded_mint"


def test_unbounded_mint_detector_clean_on_golden(golden_code):
    det = UnboundedMintDetector()
    ast = CashScriptAST(golden_code, contract_mode="ft_mint_authority")
    assert det.detect(ast) is None
