"""
CashTokens invalid-logic detectors (Wave 2B).

Stable detector IDs for corpus tests and negative benchmarks.
"""

from __future__ import annotations

import re
from typing import Optional

from src.services.anti_pattern_detectors import AntiPatternDetector, Violation
from src.services.semantic_capabilities import (
    _capability_retained_guard,
    _preserves_token_amount_guard,
    _preserves_token_category_guard,
)
from src.utils.cashscript_ast import CashScriptAST


def _critical_violation(detector_id: str, reason: str, exploit: str) -> Violation:
    return Violation(
        rule=detector_id,
        reason=reason,
        exploit=exploit,
        location={"line": 0, "function": "all"},
        severity="critical",
        issue_class="real_issue",
        exploit_severity="direct_fund_loss",
    )


class AuthorityLeakDetector(AntiPatternDetector):
    """Minting authority (0x02) not bound to this.activeBytecode."""

    id = "authority_leak"

    def detect(self, ast: CashScriptAST) -> Optional[Violation]:
        if not re.search(r"0x02", ast.code):
            return None
        retained, _ = _capability_retained_guard(ast.code)
        if retained:
            return None
        return _critical_violation(
            self.id,
            "Minting capability (0x02) without lockingBytecode custody on this.activeBytecode",
            "Authority NFT can leave covenant and mint unlimited children.",
        )


class MutableCapabilityLeakDetector(AntiPatternDetector):
    """Mutable NFT (0x01) path without covenant re-anchor."""

    id = "mutable_capability_leak"

    def detect(self, ast: CashScriptAST) -> Optional[Violation]:
        if not re.search(r"0x01", ast.code) and "nftCommitment" not in ast.code:
            return None
        if re.search(r"lockingBytecode\s*==\s*this\.activeBytecode", ast.code):
            return None
        if not re.search(r"nftCommitment", ast.code):
            return None
        return _critical_violation(
            self.id,
            "Mutable NFT update without lockingBytecode == this.activeBytecode re-anchor",
            "Attacker can redirect mutable capability to an arbitrary script.",
        )


class TokenCategoryDriftDetector(AntiPatternDetector):
    """Output token category not tied to active input category."""

    id = "token_category_drift"

    def detect(self, ast: CashScriptAST) -> Optional[Violation]:
        if "tokenCategory" not in ast.code:
            return None
        ok, _ = _preserves_token_category_guard(ast.code)
        if ok:
            return None
        if not re.search(r"tokenCategory", ast.code):
            return None
        return _critical_violation(
            self.id,
            "tokenCategory used without input/output category continuity",
            "Category confusion allows swapping token types across outputs.",
        )


class TokenAmountInflationDetector(AntiPatternDetector):
    """Output token amount exceeds input without mint authority path."""

    id = "token_amount_inflation"

    def detect(self, ast: CashScriptAST) -> Optional[Violation]:
        if "tokenAmount" not in ast.code:
            return None
        ok, _ = _preserves_token_amount_guard(ast.code)
        if ok:
            return None
        if re.search(r"0x02", ast.code) and re.search(r"\bmint\b", ast.code, re.I):
            return None
        if re.search(
            r"outputs\[[^\]]+\]\.tokenAmount\s*>\s*tx\.inputs\[this\.activeInputIndex\]\.tokenAmount",
            ast.code,
        ):
            return _critical_violation(
                self.id,
                "Output tokenAmount exceeds input tokenAmount without mint authority",
                "Inflation mints extra tokens without cap or authority checks.",
            )
        if re.search(r"tokenAmount", ast.code) and not ok:
            return _critical_violation(
                self.id,
                "tokenAmount not preserved from active input on payout outputs",
                "Attacker can set arbitrary tokenAmount on outputs.",
            )
        return None


class TokenAmountBurnDetector(AntiPatternDetector):
    """Burn to 0x category without input category constraint."""

    id = "token_amount_burn"

    def detect(self, ast: CashScriptAST) -> Optional[Violation]:
        if not re.search(r"outputs\[[^\]]+\]\.tokenCategory\s*==\s*0x\b", ast.code):
            return None
        if re.search(r"inputs\[[^\]]+\]\.tokenCategory\s*==", ast.code):
            return None
        return _critical_violation(
            self.id,
            "Output burn (tokenCategory == 0x) without input category constraint",
            "Unauthenticated burn can destroy supply or grief holders.",
        )


class NftCommitmentLossDetector(AntiPatternDetector):
    """Immutable NFT path missing nftCommitment preservation."""

    id = "nft_commitment_loss"

    def detect(self, ast: CashScriptAST) -> Optional[Violation]:
        if "tokenCategory" not in ast.code and "nftCommitment" not in ast.code:
            return None
        if re.search(
            r"outputs\[[^\]]+\]\.nftCommitment\s*==\s*tx\.inputs\[this\.activeInputIndex\]\.nftCommitment",
            ast.code,
            re.DOTALL,
        ):
            return None
        if re.search(r"outputs\[[^\]]+\]\.nftCommitment\s*==", ast.code):
            return None
        if re.search(r"outputs\[[^\]]+\]\.tokenCategory", ast.code):
            return _critical_violation(
            self.id,
            "NFT transfer/update missing nftCommitment preservation guard",
            "Commitment can be stripped or replaced — NFT integrity lost.",
        )


class HybridContinuityBreakDetector(AntiPatternDetector):
    """Hybrid migration without token category preservation."""

    id = "hybrid_continuity_break"

    def detect(self, ast: CashScriptAST) -> Optional[Violation]:
        mode = (ast.contract_mode or "").lower()
        if mode not in {"hybrid_token", "hybrid", "hybrid_continuity_break", ""}:
            if not re.search(r"nftCommitment", ast.code):
                return None
        migratory = bool(
            re.search(r"lockingBytecode\s*==\s*(?!this\.activeBytecode)(\w+)", ast.code)
        )
        if not migratory:
            return None
        ok, _ = _preserves_token_category_guard(ast.code)
        if ok:
            return None
        if "tokenCategory" not in ast.code:
            return None
        return _critical_violation(
            self.id,
            "Hybrid migratory output without token category preservation",
            "Hybrid state transition can swap category or leak wrong asset.",
        )


class UnrestrictedTokenTransferDetector(AntiPatternDetector):
    """Token payout to external lockingBytecode without covenant anchor."""

    id = "unrestricted_token_transfer"

    def detect(self, ast: CashScriptAST) -> Optional[Violation]:
        if "tokenCategory" not in ast.code and "tokenAmount" not in ast.code:
            return None
        external = bool(
            re.search(
                r"outputs\[[^\]]+\]\.lockingBytecode\s*==\s*(?!this\.activeBytecode)(\w+)",
                ast.code,
            )
        )
        if not external:
            return None
        if re.search(r"lockingBytecode\s*==\s*this\.activeBytecode", ast.code):
            return None
        return _critical_violation(
            self.id,
            "Token-bearing output sent to external lockingBytecode without retention policy",
            "Tokens can be sent to an arbitrary script outside the covenant.",
        )


CASHTOKENS_INVALID_DETECTOR_REGISTRY = [
    AuthorityLeakDetector(),
    MutableCapabilityLeakDetector(),
    TokenCategoryDriftDetector(),
    TokenAmountInflationDetector(),
    TokenAmountBurnDetector(),
    NftCommitmentLossDetector(),
    HybridContinuityBreakDetector(),
    UnrestrictedTokenTransferDetector(),
]
