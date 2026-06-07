"""
Capability-backed invariant detectors (Wave 1.5).

Detection policy uses SemanticCapabilities snapshots — no nested policy in extraction.
Same-contract input/output path reasoning only.
"""

from __future__ import annotations

import re
from typing import Optional

from src.services.anti_pattern_detectors import AntiPatternDetector, Violation
from src.services.semantic_capabilities import (
    CAPABILITY_REGISTRY,
    extract_semantic_capabilities,
)
from src.utils.cashscript_ast import CashScriptAST


def _capability_domain(rule_id: str) -> str:
    tier, _ = CAPABILITY_REGISTRY.get(rule_id.replace("capability_", ""), ("Structural", ""))
    return tier


class CapabilityBackedDetector(AntiPatternDetector):
    """Base for detectors driven by extract_semantic_capabilities."""

    capability_key: str = ""
    capability_domain: str = "Structural"

    def detect(self, ast: CashScriptAST) -> Optional[Violation]:
        caps = extract_semantic_capabilities(ast.code, contract_mode=ast.contract_mode)
        return self._detect_with_caps(ast, caps)

    def _detect_with_caps(self, ast: CashScriptAST, caps) -> Optional[Violation]:
        raise NotImplementedError


class MissingAuthorizationStateMutationDetector(CapabilityBackedDetector):
    """State mutation (nftCommitment) without signature/multisig authorization."""

    id = "capability_missing_auth_state_mutation"
    capability_domain = "Authorization"

    def _detect_with_caps(self, ast: CashScriptAST, caps) -> Optional[Violation]:
        if not re.search(r"nftCommitment", ast.code):
            return None
        if caps.authorization.get("unrestricted_state_update"):
            return Violation(
                rule=self.id,
                reason="NFT commitment mutation without signature or multisig authorization",
                exploit="Anyone can mutate on-chain NFT metadata without proving control of keys.",
                location={"line": 0, "function": "all", "capability_domain": self.capability_domain},
                severity="critical",
                issue_class="real_issue",
                exploit_severity="direct_fund_loss",
            )
        if caps.authorization.get("requires_signature") or caps.authorization.get("requires_multisig"):
            return None
        if re.search(r"nftCommitment\s*=", ast.code) and not re.search(
            r"checkSig|checkMultiSig", ast.code
        ):
            return Violation(
                rule=self.id,
                reason="Commitment field present but no checkSig/checkMultiSig in contract",
                exploit="Unauthenticated state updates allow arbitrary metadata replacement.",
                location={"line": 0, "function": "all", "capability_domain": self.capability_domain},
                severity="high",
            )
        return None


class UnrestrictedNftTransferDetector(CapabilityBackedDetector):
    """Soulbound / retained ownership: external lockingBytecode payout without covenant."""

    id = "capability_unrestricted_nft_transfer"
    capability_domain = "Authorization"

    def _detect_with_caps(self, ast: CashScriptAST, caps) -> Optional[Violation]:
        mode = (ast.contract_mode or "").lower()
        if mode not in {"nft_immutable", "soulbound", ""} and "soulbound" not in mode:
            if not re.search(r"ownership_mode|soulbound", ast.code, re.I):
                return None
        if caps.authorization.get("unrestricted_external_transfer"):
            return Violation(
                rule=self.id,
                reason="Output lockingBytecode allows transfer outside covenant anchor",
                exploit="Soulbound or retained NFT can be sent to an arbitrary external script.",
                location={"line": 0, "function": "all", "capability_domain": self.capability_domain},
                severity="critical",
                issue_class="real_issue",
                exploit_severity="direct_fund_loss",
            )
        return None


class MutableNftMissingReanchorDetector(CapabilityBackedDetector):
    """Mutable NFT path without lockingBytecode == this.activeBytecode continuation."""

    id = "capability_mutable_nft_no_reanchor"
    capability_domain = "Lifecycle"

    def _detect_with_caps(self, ast: CashScriptAST, caps) -> Optional[Violation]:
        mode = (ast.contract_mode or "").lower()
        if mode not in {"nft_mutable", "hybrid_token", ""}:
            return None
        if not re.search(r"nftCommitment|0x01", ast.code):
            return None
        if caps.lifecycle.get("reanchors_covenant"):
            return None
        if ast.is_stateful or re.search(r"function\s+\w+.*mutable", ast.code, re.I):
            return Violation(
                rule=self.id,
                reason="Mutable NFT / hybrid path missing covenant re-anchor on activeBytecode",
                exploit="Attacker can strip mutable capability or redirect covenant to arbitrary script.",
                location={"line": 0, "function": "all", "capability_domain": self.capability_domain},
                severity="critical",
                issue_class="real_issue",
                exploit_severity="direct_fund_loss",
            )
        return None


class TokenContinuityBreakDetector(CapabilityBackedDetector):
    """Token-bearing contract without category or amount continuity guards."""

    id = "capability_token_continuity_break"
    capability_domain = "TokenFlow"

    def _detect_with_caps(self, ast: CashScriptAST, caps) -> Optional[Violation]:
        mode = (ast.contract_mode or "").lower()
        if mode in {"ft_mint", "ft_mint_authority", "token_ft_mint", "nft_minting", "nft_minting_authority"}:
            return None
        if "tokenCategory" not in ast.code and "tokenAmount" not in ast.code:
            return None
        if caps.token_flow.get("preserves_token_category") or caps.token_flow.get(
            "burns_output_tokens"
        ):
            return None
        if caps.token_flow.get("token_category_constrained"):
            return None
        if caps.token_flow.get("enforces_supply_cap"):
            return None
        return Violation(
            rule=self.id,
            reason="tokenCategory used without input/output category continuity or burn guard",
            exploit="Category confusion allows swapping token types across spending paths.",
            location={"line": 0, "function": "all", "capability_domain": self.capability_domain},
            severity="high",
            issue_class="real_issue",
            exploit_severity="partial_violation",
        )


class UnintendedBurnPathDetector(CapabilityBackedDetector):
    """Burn to 0x category without constraining source input category."""

    id = "capability_unintended_burn"
    capability_domain = "TokenFlow"

    def _detect_with_caps(self, ast: CashScriptAST, caps) -> Optional[Violation]:
        if not caps.token_flow.get("burns_output_tokens"):
            return None
        if caps.token_flow.get("token_category_constrained"):
            return None
        return Violation(
            rule=self.id,
            reason="Output burn (tokenCategory == 0x) without input category constraint",
            exploit="Unauthenticated burn path can destroy supply or grief holders.",
            location={"line": 0, "function": "all", "capability_domain": self.capability_domain},
            severity="high",
            issue_class="real_issue",
            exploit_severity="partial_violation",
        )


class HybridMigrationMismatchDetector(CapabilityBackedDetector):
    """Migratory lockingBytecode without preserving token category on outputs."""

    id = "capability_hybrid_migration_mismatch"
    capability_domain = "Lifecycle"

    def _detect_with_caps(self, ast: CashScriptAST, caps) -> Optional[Violation]:
        mode = (ast.contract_mode or "").lower()
        if mode in {"ft_mint", "ft_mint_authority", "token_ft_mint", "token_ft", "ft_transfer"}:
            return None
        if mode not in {"hybrid_token", "marketplace", ""}:
            if not caps.lifecycle.get("migratory_output"):
                return None
        if not caps.lifecycle.get("migratory_output"):
            return None
        if caps.token_flow.get("preserves_token_category"):
            return None
        if caps.token_flow.get("enforces_supply_cap"):
            return None
        if "tokenCategory" not in ast.code and "tokenAmount" not in ast.code:
            return None
        return Violation(
            rule=self.id,
            reason="Migratory output path without token category preservation",
            exploit="Hybrid migration can swap token category or leak wrong asset to recipient.",
            location={"line": 0, "function": "all", "capability_domain": self.capability_domain},
            severity="high",
            issue_class="real_issue",
            exploit_severity="partial_violation",
        )


class UnrestrictedPayoutPathDetector(CapabilityBackedDetector):
    """Terminal payout/release path without signature or multisig gate."""

    id = "capability_unrestricted_payout"
    capability_domain = "Authorization"

    def _detect_with_caps(self, ast: CashScriptAST, caps) -> Optional[Violation]:
        if not caps.lifecycle.get("terminating_output"):
            return None
        if caps.authorization.get("has_signature_auth") or caps.authorization.get(
            "has_multisig_auth"
        ):
            return None
        if re.search(r"checkSig|checkMultiSig", ast.code):
            return None
        return Violation(
            rule=self.id,
            reason="Payout/termination path detected without authorization capability",
            exploit="Anyone can trigger fund release without proving key control.",
            location={"line": 0, "function": "all", "capability_domain": self.capability_domain},
            severity="critical",
            issue_class="real_issue",
            exploit_severity="direct_fund_loss",
        )


CAPABILITY_DETECTOR_REGISTRY = [
    MissingAuthorizationStateMutationDetector(),
    UnrestrictedNftTransferDetector(),
    MutableNftMissingReanchorDetector(),
    TokenContinuityBreakDetector(),
    UnintendedBurnPathDetector(),
    HybridMigrationMismatchDetector(),
    UnrestrictedPayoutPathDetector(),
]

# Audit profile: high-signal subset (skip noisy continuity on partial templates)
AUDIT_CAPABILITY_DETECTOR_REGISTRY = [
    MissingAuthorizationStateMutationDetector(),
    UnrestrictedNftTransferDetector(),
    MutableNftMissingReanchorDetector(),
    TokenContinuityBreakDetector(),
    UnintendedBurnPathDetector(),
    HybridMigrationMismatchDetector(),
    UnrestrictedPayoutPathDetector(),
]
