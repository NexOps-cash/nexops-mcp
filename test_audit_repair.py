"""
test_audit_repair.py — Hybrid Scoring v2 Unit Tests (Revised Semantic Split)

Semantic bucket = category (0-20 structured) + business_logic_score (0-10 free-form)
Combined: min(30, cat + biz)
funds_unspendable always forces semantic → 0.

Case 1: Clean escrow  → cat=20 + biz=10 → sem=30, det=70, total=100
Case 2: Deadlock      → funds_unspendable → sem=0,  det=70, total=70, deploy=False
Case 3: Token inflation (CRITICAL) → det=50, cat=5 + biz=3 → sem=8, total=58, deploy=False
"""

import json
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from src.services.audit_agent import AuditAgent


# ── Contracts ────────────────────────────────────────────────────────────────

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

contract DeadlockEscrow(bytes20 selfHash) {
    function lock(sig anySig) {
        require(tx.outputs.length == 1);
        require(tx.outputs[0].lockingBytecode == new LockingBytecodeP2SH20(selfHash));
    }
}
"""

TOKEN_INFLATION_CONTRACT = """\
pragma cashscript ^0.10.0;

contract TokenInflation(pubkey owner) {
    function withdraw(sig ownerSig) {
        require(checkSig(ownerSig, owner));
        require(tx.outputs[0].value > 0);
    }
}
"""


# ── Helpers ──────────────────────────────────────────────────────────────────

def _mock_provider(category: str, biz_score: int, explanation: str = "Test.", biz_notes: str = ""):
    provider = MagicMock()
    provider.complete = AsyncMock(
        return_value=json.dumps({
            "category": category,
            "explanation": explanation,
            "confidence": 0.9,
            "business_logic_score": biz_score,
            "business_logic_notes": biz_notes or f"Business logic score: {biz_score}/10.",
        })
    )
    return provider


def _compile_ok(code): return {"success": True}
def _lint_ok(code, contract_mode=""): return {"passed": True, "violations": []}

def _toll_gate_ok(code):
    r = MagicMock(); r.passed = True; r.violations = []; r.structural_score = 1.0
    return r

def _toll_gate_critical(code):
    v = MagicMock()
    v.rule = "token_sum_not_preserved"; v.severity = "CRITICAL"
    v.reason = "Output token amount not bounded."; v.exploit = "Token inflation possible."
    v.fix_hint = "Add token amount check."; v.location = {"line": 7}
    r = MagicMock(); r.passed = False; r.violations = [v]; r.structural_score = 0.5
    return r


# ── Tests ────────────────────────────────────────────────────────────────────

class TestHybridScoringV2(unittest.IsolatedAsyncioTestCase):

    # ── Case 1: Perfect clean escrow ─────────────────────────────────────────
    # cat=none(20) + biz=10 → sem=30, det=70, total=100
    # (In practice AI won't give 10/10, but this validates the ceiling)
    @patch("src.services.audit_agent.Phase3.validate", side_effect=_toll_gate_ok)
    @patch("src.services.audit_agent.get_dsl_linter", return_value=MagicMock(lint=_lint_ok))
    @patch("src.services.audit_agent.get_compiler_service", return_value=MagicMock(compile=_compile_ok))
    @patch("src.services.llm.factory.LLMFactory.get_provider")
    async def test_case1_clean_escrow_scores_100(self, mock_llm, *_):
        mock_llm.return_value = _mock_provider("none", biz_score=10, explanation="No issues.")

        report = await AuditAgent().audit(CLEAN_ESCROW, intent="Standard 3-party escrow.")

        print(f"\n[Case 1] det={report.deterministic_score} sem={report.semantic_score} "
              f"total={report.total_score} deploy={report.deployment_allowed}")

        self.assertEqual(report.deterministic_score, 70)
        self.assertEqual(report.semantic_score, 30,  "none(20) + biz(10) = 30")
        self.assertEqual(report.total_score, 100)
        self.assertTrue(report.deployment_allowed)
        self.assertEqual(report.semantic_category, "none")

    # ── Case 2: Deadlock — funds_unspendable ─────────────────────────────────
    # sem forced to 0 regardless of biz_score, deploy blocked
    @patch("src.services.audit_agent.Phase3.validate", side_effect=_toll_gate_ok)
    @patch("src.services.audit_agent.get_dsl_linter", return_value=MagicMock(lint=_lint_ok))
    @patch("src.services.audit_agent.get_compiler_service", return_value=MagicMock(compile=_compile_ok))
    @patch("src.services.llm.factory.LLMFactory.get_provider")
    async def test_case2_deadlock_blocks_deployment(self, mock_llm, *_):
        # Even biz=8 doesn't help — funds_unspendable overrides to sem=0
        mock_llm.return_value = _mock_provider(
            "funds_unspendable", biz_score=8,
            explanation="Only output is back to self — permanent deadlock.",
        )

        report = await AuditAgent().audit(DEADLOCK_ESCROW)

        print(f"\n[Case 2] det={report.deterministic_score} sem={report.semantic_score} "
              f"total={report.total_score} deploy={report.deployment_allowed}")

        self.assertEqual(report.deterministic_score, 70)
        self.assertEqual(report.semantic_score, 0,   "funds_unspendable forces sem=0")
        self.assertEqual(report.total_score, 70)
        self.assertFalse(report.deployment_allowed,  "sem=0 must block deployment")
        self.assertEqual(report.semantic_category, "funds_unspendable")

    # ── Case 3: Token inflation — CRITICAL structural + poor biz logic ───────
    # det: 70 - 20(CRITICAL) = 50
    # sem: major_protocol_flaw(5) + biz(3) = 8
    # total: 58, display: 58 (>= floor 20), deploy: 58 < 75 → False
    @patch("src.services.audit_agent.Phase3.validate", side_effect=_toll_gate_critical)
    @patch("src.services.audit_agent.get_dsl_linter", return_value=MagicMock(lint=_lint_ok))
    @patch("src.services.audit_agent.get_compiler_service", return_value=MagicMock(compile=_compile_ok))
    @patch("src.services.llm.factory.LLMFactory.get_provider")
    async def test_case3_token_inflation_reduces_both_scores(self, mock_llm, *_):
        mock_llm.return_value = _mock_provider(
            "major_protocol_flaw", biz_score=3,
            explanation="Token amount not bounded — inflation possible.",
            biz_notes="Clear race condition on UTXO selection; no economic alignment.",
        )

        report = await AuditAgent().audit(TOKEN_INFLATION_CONTRACT, intent="Token withdrawal.")

        print(f"\n[Case 3] det={report.deterministic_score} sem={report.semantic_score} "
              f"total={report.total_score} deploy={report.deployment_allowed}")

        self.assertEqual(report.deterministic_score, 50,  "70-20(CRITICAL)=50")
        self.assertEqual(report.semantic_score, 8,        "major_protocol_flaw(5)+biz(3)=8")
        self.assertEqual(report.total_score, 58)
        self.assertFalse(report.deployment_allowed)
        self.assertEqual(report.semantic_category, "major_protocol_flaw")


if __name__ == "__main__":
    unittest.main(verbosity=2)
