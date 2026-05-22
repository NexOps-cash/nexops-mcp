"""Regression tests for repair-loop structural corruption detection."""

from pathlib import Path

import pytest

from src.services.structural_integrity import (
    apply_deterministic_micro_fixes,
    diagnose_structure,
    is_structurally_valid,
    prepend_new_locking_bytecode,
)

FIXTURES = Path(__file__).parent / "fixtures" / "structural_corruption"


def _load(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


class TestStructuralDetection:
    @pytest.mark.parametrize(
        "fixture,expected_issue_substr",
        [
            ("extra_closing_brace.cash", "brace_imbalance"),
            ("missing_closing_brace.cash", "brace_imbalance"),
            ("dangling_require.cash", "dangling_require"),
            ("truncated_function.cash", "dangling_require"),
            ("truncated_constructor.cash", "truncated_constructor"),
        ],
    )
    def test_corrupt_fixtures_invalid(self, fixture, expected_issue_substr):
        code = _load(fixture)
        diag = diagnose_structure(code)
        assert not diag.valid
        assert any(expected_issue_substr in i for i in diag.issues)

    def test_valid_minimal_passes(self):
        code = _load("valid_minimal.cash")
        assert is_structurally_valid(code)
        assert diagnose_structure(code).issues == []

    def test_missing_new_p2pkh_detected(self):
        code = _load("missing_new_p2pkh.cash")
        diag = diagnose_structure(code)
        assert diag.missing_new_p2pkh >= 1


class TestDeterministicMicroFixes:
    def test_prepend_new_p2pkh(self):
        code = _load("missing_new_p2pkh.cash")
        fixed, repairs = apply_deterministic_micro_fixes(code)
        assert "prepend_new_locking_bytecode_p2pkh" in repairs
        assert "new LockingBytecodeP2PKH" in fixed
        assert diagnose_structure(fixed).missing_new_p2pkh == 0

    def test_no_unsafe_brace_append_on_dangling_require(self):
        code = _load("dangling_require.cash")
        fixed, repairs = apply_deterministic_micro_fixes(
            code, {"type": "ExtraneousInputError", "token": "<EOF>", "raw": "EOF"}
        )
        assert "append_single_closing_brace" not in repairs
        assert not is_structurally_valid(fixed)

    def test_single_missing_brace_safe_append(self):
        code = """pragma cashscript ^0.13.0;
contract X(pubkey o) {
    function f(sig s) {
        require(checkSig(s, o));
    }
"""
        fixed, repairs = apply_deterministic_micro_fixes(
            code, {"type": "ExtraneousInputError", "token": "<EOF>", "raw": "EOF"}
        )
        assert "append_single_closing_brace" in repairs
        assert is_structurally_valid(fixed)

    def test_bytes32_not_applied_in_constructor_signature(self):
        code = """pragma cashscript ^0.13.0;
contract Voucher(pubkey owner, bytes recipientLock) {
    function redeem(sig ownerSig) {
        require(checkSig(ownerSig, owner));
    }
}
"""
        fixed, repairs = apply_deterministic_micro_fixes(
            code,
            {"type": "TypeMismatchError", "raw": "expected bytes32", "token": ""},
        )
        assert "bytes_to_bytes32_body_only" in repairs or repairs == []
        assert "bytes recipientLock" in fixed


class TestPipelineEngineIntegration:
    def test_request_syntax_fix_aborts_on_corrupt_llm_output(self):
        import asyncio
        from unittest.mock import AsyncMock, MagicMock, patch

        from src.models import ContractIR, ContractMetadata, IntentModel
        from src.services.pipeline_engine import GuardedPipelineEngine

        engine = GuardedPipelineEngine()
        corrupt = _load("truncated_function.cash")
        ir = ContractIR(
            contract_name="Test",
            metadata=ContractMetadata(
                intent_model=IntentModel(
                    contract_type="generic",
                    features=[],
                    ownership_mode="transferable",
                )
            ),
        )

        async def fake_llm(*_a, **_k):
            return corrupt + "\n// still broken"

        with patch(
            "src.services.llm.factory.LLMFactory.get_provider"
        ) as mock_factory:
            mock_provider = MagicMock()
            mock_provider.complete = AsyncMock(side_effect=fake_llm)
            mock_factory.return_value = mock_provider
            with patch("src.services.pipeline._extract_cash_code", side_effect=lambda x: x):
                result, aborted = asyncio.run(
                    engine._request_syntax_fix(
                        code=_load("valid_minimal.cash"),
                        error_obj={"type": "UnknownError", "raw": "EOF"},
                        ir=ir,
                    )
                )
        assert aborted
        assert result == _load("valid_minimal.cash")
