"""
test_audit_repair.py — Hybrid Scoring v2 Unit Tests

Three deterministic cases:
  Case 1: Clean escrow → det=70, sem=30, total=100, deployment=True
  Case 2: Escrow with funds deadlock → det=70, sem=0, total=70, deployment=False
  Case 3: Structural token inflation (CRITICAL issue) → det≤50, deployment depends on gate

LLM calls are fully mocked — no real API dependency.
"""

import asyncio
import json
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from src.services.audit_agent import AuditAgent


# ── Shared contracts ────────────────────────────────────────────────────────

CLEAN_ESCROW = """\
pragma cashscript ^0.10.0;

contract CleanEscrow(pubkey sender, pubkey recipient, pubkey arbiter) {
    function release(sig arbiterSig) {
        require(checkSig(arbiterSig, arbiter));
        require(tx.outputs.length == 1);
        require(tx.outputs[0].lockingBytecode == new LockingBytecodeP2PKH(hash160(recipient)));
        require(tx.outputs[0].value >= tx.inputs[this.activeInputIndex].value - 1000);
    }

    function refund(sig senderSig) {
        require(checkSig(senderSig, sender));
        require(tx.outputs.length == 1);
        require(tx.outputs[0].lockingBytecode == new LockingBytecodeP2PKH(hash160(sender)));
        require(tx.outputs[0].value >= tx.inputs[this.activeInputIndex].value - 1000);
    }
}
"""

DEADLOCK_ESCROW = """\
pragma cashscript ^0.10.0;

// Deadlock: funds can only be sent back to this same contract, no external exit.
contract DeadlockEscrow(bytes20 selfHash) {
    function lock(sig anySig) {
        // Only output allowed is back to self — permanent deadlock.
        require(tx.outputs.length == 1);
        require(tx.outputs[0].lockingBytecode == new LockingBytecodeP2SH20(selfHash));
    }
}
"""

TOKEN_INFLATION_CONTRACT = """\
pragma cashscript ^0.10.0;

// Structural flaw: output token amount is unbounded — classic inflation vector.
contract TokenInflation(pubkey owner) {
    function withdraw(sig ownerSig) {
        require(checkSig(ownerSig, owner));
        // Missing: no check that output token value <= input token value
        require(tx.outputs[0].value > 0);
    }
}
"""


# ── Helpers ─────────────────────────────────────────────────────────────────

def _make_mock_provider(category: str, explanation: str = "Test explanation.", confidence: float = 0.9):
    """Build a mock LLM provider that returns a well-formed semantic JSON response."""
    provider = MagicMock()
    provider.complete = AsyncMock(
        return_value=json.dumps({
            "category": category,
            "explanation": explanation,
            "confidence": confidence,
        })
    )
    return provider


def _compile_ok(code: str) -> dict:
    return {"success": True, "artifact": {}}


def _lint_ok(code: str, contract_mode: str = "") -> dict:
    return {"passed": True, "violations": []}


def _toll_gate_ok(code: str):
    result = MagicMock()
    result.passed = True
    result.violations = []
    result.structural_score = 1.0
    return result


def _toll_gate_critical(code: str):
    """Inject one CRITICAL violation (token sum not preserved → -20 det deduction)."""
    violation = MagicMock()
    violation.rule = "token_sum_not_preserved"
    violation.severity = "CRITICAL"
    violation.reason = "Output token amount not bounded by input amount."
    violation.exploit = "Attacker can inflate token supply."
    violation.fix_hint = "Add require(tx.outputs[0].tokenAmount <= tx.inputs[this.activeInputIndex].tokenAmount)."
    violation.location = {"line": 7}
    result = MagicMock()
    result.passed = False
    result.violations = [violation]
    result.structural_score = 0.5
    return result


# ── Test Cases ───────────────────────────────────────────────────────────────

class TestHybridScoringV2(unittest.IsolatedAsyncioTestCase):

    # ────────────────────────────────────────────────────────────────────────
    # Case 1: Clean escrow — no issues, semantic category = "none"
    # Expected: det=70, sem=30, total=100, deployment=True
    # ────────────────────────────────────────────────────────────────────────
    @patch("src.services.audit_agent.Phase3.validate", side_effect=_toll_gate_ok)
    @patch("src.services.audit_agent.get_dsl_linter", return_value=MagicMock(lint=_lint_ok))
    @patch("src.services.audit_agent.get_compiler_service", return_value=MagicMock(compile=_compile_ok))
    @patch("src.services.llm.factory.LLMFactory.get_provider")
    async def test_case1_clean_escrow_scores_100(self, mock_llm, *_):
        mock_llm.return_value = _make_mock_provider("none", "No logic issues found.")

        agent = AuditAgent()
        report = await agent.audit(CLEAN_ESCROW, intent="Standard 3-party escrow.")

        print(f"\n[Case 1] det={report.deterministic_score} sem={report.semantic_score} "
              f"total={report.total_score} deploy={report.deployment_allowed}")

        self.assertEqual(report.deterministic_score, 70, "Clean contract must score 70 det")
        self.assertEqual(report.semantic_score, 30, "Category 'none' must map to sem=30")
        self.assertEqual(report.total_score, 100, "Total must be 100")
        self.assertTrue(report.deployment_allowed, "Clean escrow must pass deployment gate")
        self.assertEqual(report.semantic_category, "none")

    # ────────────────────────────────────────────────────────────────────────
    # Case 2: Deadlock escrow — semantic category = "funds_unspendable"
    # Expected: det=70, sem=0, total=70 (floor=70>20), deployment=False
    # ────────────────────────────────────────────────────────────────────────
    @patch("src.services.audit_agent.Phase3.validate", side_effect=_toll_gate_ok)
    @patch("src.services.audit_agent.get_dsl_linter", return_value=MagicMock(lint=_lint_ok))
    @patch("src.services.audit_agent.get_compiler_service", return_value=MagicMock(compile=_compile_ok))
    @patch("src.services.llm.factory.LLMFactory.get_provider")
    async def test_case2_deadlock_escrow_blocks_deployment(self, mock_llm, *_):
        mock_llm.return_value = _make_mock_provider(
            "funds_unspendable",
            "Funds can only flow back to self with no external exit.",
        )

        agent = AuditAgent()
        report = await agent.audit(DEADLOCK_ESCROW)

        print(f"\n[Case 2] det={report.deterministic_score} sem={report.semantic_score} "
              f"total={report.total_score} deploy={report.deployment_allowed}")

        self.assertEqual(report.deterministic_score, 70, "No structural issues → det=70")
        self.assertEqual(report.semantic_score, 0, "funds_unspendable must map to sem=0")
        self.assertEqual(report.total_score, 70, "Total (pre-floor 70 >= 20) must be 70")
        self.assertFalse(report.deployment_allowed, "funds_unspendable must block deployment")
        self.assertEqual(report.semantic_category, "funds_unspendable")

    # ────────────────────────────────────────────────────────────────────────
    # Case 3: Token inflation — CRITICAL structural violation → det reduced
    # Expected: det=50 (70-20 for one CRITICAL), sem=30, deployment depends on gate
    # ────────────────────────────────────────────────────────────────────────
    @patch("src.services.audit_agent.Phase3.validate", side_effect=_toll_gate_critical)
    @patch("src.services.audit_agent.get_dsl_linter", return_value=MagicMock(lint=_lint_ok))
    @patch("src.services.audit_agent.get_compiler_service", return_value=MagicMock(compile=_compile_ok))
    @patch("src.services.llm.factory.LLMFactory.get_provider")
    async def test_case3_token_inflation_reduces_det_score(self, mock_llm, *_):
        mock_llm.return_value = _make_mock_provider(
            "major_protocol_flaw",
            "Token amount inflation is unbounded — critical protocol flaw.",
        )

        agent = AuditAgent()
        report = await agent.audit(TOKEN_INFLATION_CONTRACT, intent="Token withdrawal contract.")

        print(f"\n[Case 3] det={report.deterministic_score} sem={report.semantic_score} "
              f"total={report.total_score} deploy={report.deployment_allowed}")

        # One CRITICAL deduction applied to the 70-pt bucket:  70 - 20 = 50
        self.assertEqual(report.deterministic_score, 50, "One CRITICAL issue: 70-20=50 det")
        # major_protocol_flaw → sem=10
        self.assertEqual(report.semantic_score, 10, "major_protocol_flaw must map to sem=10")
        # total=60, floor=max(20,60)=60
        self.assertEqual(report.total_score, 60)
        # Gate: det(50)>=50 AND sem(10)>0 AND display(60)<75 → blocked
        self.assertFalse(report.deployment_allowed, "display_score<75 must block deployment gate")
        self.assertEqual(report.semantic_category, "major_protocol_flaw")
        self.assertGreater(len(report.issues), 0, "At least one structural issue must be present")


# ── Entry point ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    unittest.main(verbosity=2)
