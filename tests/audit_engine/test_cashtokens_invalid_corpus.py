"""Wave 2B — CashTokens invalid-logic detector corpus (secure vs vulnerable)."""

from pathlib import Path

import pytest

from src.services.cashtokens_token_detectors import CASHTOKENS_INVALID_DETECTOR_REGISTRY
from src.utils.cashscript_ast import CashScriptAST

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "cashtokens_invalid"

DETECTOR_BY_ID = {d.id: d for d in CASHTOKENS_INVALID_DETECTOR_REGISTRY}


@pytest.mark.parametrize("detector_id", sorted(DETECTOR_BY_ID.keys()))
def test_vulnerable_fixture_triggers_detector(detector_id: str):
    code = (FIXTURES / detector_id / "vulnerable.cash").read_text(encoding="utf-8")
    ast = CashScriptAST(code, contract_mode=detector_id)
    v = DETECTOR_BY_ID[detector_id].detect(ast)
    assert v is not None, f"{detector_id}: expected violation on vulnerable fixture"
    assert v.rule == detector_id


@pytest.mark.parametrize("detector_id", sorted(DETECTOR_BY_ID.keys()))
def test_secure_fixture_clean(detector_id: str):
    code = (FIXTURES / detector_id / "secure.cash").read_text(encoding="utf-8")
    ast = CashScriptAST(code, contract_mode=detector_id)
    v = DETECTOR_BY_ID[detector_id].detect(ast)
    assert v is None, f"{detector_id}: false positive on secure fixture: {v}"


def test_registry_has_eight_detectors():
    assert len(CASHTOKENS_INVALID_DETECTOR_REGISTRY) == 8
