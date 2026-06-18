"""
Audit classification stress-test scenarios.

Shared by pytest (tests/test_audit_classification_matrix.py) and the report
generator (scripts/generate_audit_classification_report.py).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Callable, List, Optional, Set

from src.models import (
    AuditIssue,
    AuditReport,
    ConfidenceLevel,
    FindingKind,
    IntentModel,
    Provenance,
    Severity,
    Triggerability,
)


# ── Contract fixtures ─────────────────────────────────────────────────────────

PAYROLL_RECIPIENTS_ONLY = """
pragma cashscript ^0.13.0;
contract Payroll(
    pubkey owner,
    bytes employee1Lock,
    bytes employee2Lock,
    bytes employee3Lock
) {
    function distribute(sig ownerSig) {
        require(checkSig(ownerSig, owner));
        require(tx.outputs.length == 3);
        require(tx.outputs[0].lockingBytecode == employee1Lock);
        require(tx.outputs[1].lockingBytecode == employee2Lock);
        require(tx.outputs[2].lockingBytecode == employee3Lock);
        require(
            tx.outputs[0].tokenAmount + tx.outputs[1].tokenAmount + tx.outputs[2].tokenAmount ==
            tx.inputs[this.activeInputIndex].tokenAmount
        );
        require(
            tx.outputs[0].tokenCategory ==
            tx.inputs[this.activeInputIndex].tokenCategory
        );
        require(
            tx.outputs[1].tokenCategory ==
            tx.inputs[this.activeInputIndex].tokenCategory
        );
        require(
            tx.outputs[2].tokenCategory ==
            tx.inputs[this.activeInputIndex].tokenCategory
        );
    }
}
"""

PAYROLL_FIXED_SALARY = """
pragma cashscript ^0.13.0;
contract Payroll(
    pubkey owner,
    bytes employee1Lock,
    bytes employee2Lock,
    int salary1,
    int salary2
) {
    function distribute(sig ownerSig) {
        require(checkSig(ownerSig, owner));
        require(tx.outputs.length == 2);
        require(tx.outputs[0].lockingBytecode == employee1Lock);
        require(tx.outputs[1].lockingBytecode == employee2Lock);
        require(tx.outputs[0].tokenAmount == salary1);
        require(tx.outputs[1].tokenAmount == salary2);
        require(
            tx.outputs[0].tokenAmount + tx.outputs[1].tokenAmount ==
            tx.inputs[this.activeInputIndex].tokenAmount
        );
    }
}
"""

PAYROLL_NO_AUTH = """
pragma cashscript ^0.13.0;
contract PayrollNoAuth(bytes employee1Lock, bytes employee2Lock) {
    function distribute() {
        require(tx.outputs.length == 2);
        require(tx.outputs[0].lockingBytecode == employee1Lock);
        require(tx.outputs[1].lockingBytecode == employee2Lock);
        require(
            tx.outputs[0].value + tx.outputs[1].value ==
            tx.inputs[this.activeInputIndex].value
        );
    }
}
"""

ESCROW_RELEASE_ONLY = """
pragma cashscript ^0.13.0;
contract Escrow(pubkey sender, pubkey recipient, pubkey arbiter) {
    function release(sig arbiterSig) {
        require(checkSig(arbiterSig, arbiter));
        require(tx.outputs.length == 1);
        require(tx.outputs[0].lockingBytecode == new LockingBytecodeP2PKH(hash160(recipient)));
        require(tx.outputs[0].value >= tx.inputs[this.activeInputIndex].value - 1000);
    }
}
"""

ESCROW_WITH_REFUND = """
pragma cashscript ^0.13.0;
contract Escrow(pubkey sender, pubkey recipient, pubkey arbiter, int timeout) {
    function release(sig arbiterSig) {
        require(checkSig(arbiterSig, arbiter));
        require(tx.outputs.length == 1);
        require(tx.outputs[0].lockingBytecode == new LockingBytecodeP2PKH(hash160(recipient)));
        require(tx.outputs[0].value >= tx.inputs[this.activeInputIndex].value - 1000);
    }
    function refund(sig senderSig) {
        require(checkSig(senderSig, sender));
        require(tx.time >= timeout);
        require(tx.outputs.length == 1);
        require(tx.outputs[0].lockingBytecode == new LockingBytecodeP2PKH(hash160(sender)));
        require(tx.outputs[0].value >= tx.inputs[this.activeInputIndex].value - 1000);
    }
}
"""

MULTISIG_WEAK = """
pragma cashscript ^0.13.0;
contract Treasury(pubkey alice) {
    function spend(sig aliceSig) {
        require(checkSig(aliceSig, alice));
        require(tx.outputs.length == 1);
        require(tx.outputs[0].value == tx.inputs[this.activeInputIndex].value);
    }
}
"""

MULTISIG_STRONG = """
pragma cashscript ^0.13.0;
contract Treasury(pubkey alice, pubkey bob, pubkey carol) {
    function spend(sig aliceSig, sig bobSig) {
        require(checkSig(aliceSig, alice));
        require(checkSig(bobSig, bob));
        require(tx.outputs.length == 1);
        require(tx.outputs[0].value == tx.inputs[this.activeInputIndex].value);
    }
}
"""

VAULT_NO_TIMELOCK = """
pragma cashscript ^0.13.0;
contract Vault(pubkey owner) {
    function withdraw(sig ownerSig) {
        require(checkSig(ownerSig, owner));
        require(tx.outputs.length == 1);
        require(tx.outputs[0].value == tx.inputs[this.activeInputIndex].value);
    }
}
"""

VAULT_WITH_TIMELOCK = """
pragma cashscript ^0.13.0;
contract Vault(pubkey owner, int unlockTime) {
    function withdraw(sig ownerSig) {
        require(checkSig(ownerSig, owner));
        require(tx.time >= unlockTime);
        require(tx.outputs.length == 1);
        require(tx.outputs[0].value == tx.inputs[this.activeInputIndex].value);
    }
}
"""

SPLIT_RECIPIENTS_ONLY = """
pragma cashscript ^0.13.0;
contract Split(pubkey owner, bytes aliceLock, bytes bobLock) {
    function pay(sig ownerSig) {
        require(checkSig(ownerSig, owner));
        require(tx.outputs.length == 2);
        require(tx.outputs[0].lockingBytecode == aliceLock);
        require(tx.outputs[1].lockingBytecode == bobLock);
        require(
            tx.outputs[0].value + tx.outputs[1].value ==
            tx.inputs[this.activeInputIndex].value
        );
    }
}
"""

SPLIT_RECIPIENTS_AND_AMOUNTS = """
pragma cashscript ^0.13.0;
contract Split(pubkey owner, bytes aliceLock, bytes bobLock, int aliceShare, int bobShare) {
    function pay(sig ownerSig) {
        require(checkSig(ownerSig, owner));
        require(tx.outputs.length == 2);
        require(tx.outputs[0].lockingBytecode == aliceLock);
        require(tx.outputs[1].lockingBytecode == bobLock);
        require(tx.outputs[0].value == aliceShare);
        require(tx.outputs[1].value == bobShare);
        require(
            tx.outputs[0].value + tx.outputs[1].value ==
            tx.inputs[this.activeInputIndex].value
        );
    }
}
"""

TOKEN_UNAUTHORIZED_MINT = """
pragma cashscript ^0.13.0;
contract Minter(bytes32 authCategory, bytes32 tokenCategory) {
    function mint() {
        require(tx.outputs[0].tokenCategory == tokenCategory);
        require(tx.outputs[0].tokenAmount > 0);
    }
}
"""

TOKEN_NO_SUPPLY_CAP = """
pragma cashscript ^0.13.0;
contract Minter(pubkey owner, bytes32 tokenCategory, int maxSupply) {
    function mint(sig ownerSig, int amount) {
        require(checkSig(ownerSig, owner));
        require(tx.outputs[0].tokenCategory == tokenCategory);
        require(tx.outputs[0].tokenAmount == amount);
    }
}
"""

PAYROLL_INTENT_FIXED = (
    "Payroll contract with fixed recipients and fixed salary amounts for each employee. "
    "Owner must sign. Preserve token category across outputs."
)

SPLIT_INTENT_FIXED = (
    "Split payment to fixed recipients with fixed predetermined amounts per recipient. "
    "Owner must sign. Sum of outputs must equal input."
)


@dataclass
class ClassificationExpectation:
    """Expected properties for a primary finding (or absence)."""

    rule_id: Optional[str] = None
    absent_rule_id: Optional[str] = None
    kinds: Optional[Set[FindingKind]] = None
    forbidden_kinds: Set[FindingKind] = field(default_factory=set)
    severities: Optional[Set[Severity]] = None
    forbidden_severities: Set[Severity] = field(default_factory=set)
    triggerabilities: Optional[Set[Triggerability]] = None
    confidences: Optional[Set[ConfidenceLevel]] = None
    forbidden_confidences: Set[ConfidenceLevel] = field(default_factory=set)
    title_prefixes: Optional[Set[str]] = None
    forbidden_title_substrings: Set[str] = field(default_factory=set)
    provenance: Optional[Provenance] = None
    max_severity: Optional[Severity] = None
    source: Optional[str] = None


@dataclass
class ClassificationScenario:
    scenario_id: str
    suite: str
    description: str
    code: str
    intent: str = ""
    effective_mode: str = ""
    intent_model: Optional[IntentModel] = None
    llm_payload: Optional[dict] = None
    legacy_llm_payload: Optional[dict] = None
    expectation: ClassificationExpectation = field(default_factory=ClassificationExpectation)
    skip_full_audit: bool = False
    policy_only_fn: Optional[str] = None
    policy_only_kwargs: Optional[dict] = None


def _reasoning_steps() -> List[str]:
    return [
        "Examined declared intent invariants for this contract pattern.",
        "Identified attacker-controlled transaction inputs relevant to the spend path.",
        "Assessed value impact on BCH and token flows.",
        "Determined whether an attacker gains unauthorized value or authorization.",
    ]


def _safe_llm_legacy() -> dict:
    return {
        "category": "SAFE",
        "exploit_severity": "n/a",
        "explanation": "No additional semantic issues.",
        "confidence": 0.9,
        "business_logic_score": 8,
        "business_logic_notes": "",
    }


def _safe_llm_v2() -> dict:
    return {
        "judge_version": "2.0",
        "verdict": "no_issue",
        "intent_fidelity_score": 8,
        "intent_fidelity_notes": "",
    }


def _v2_finding(
    *,
    gap_id: str,
    attacker_gain: bool,
    authorization_impact: bool = False,
    value_impact: str = "none",
    trust_assumption: str = "none",
    summary: str = "",
    reasoning: str = "",
    recommendation: str = "",
    confidence: float = 0.9,
    intent_fidelity_score: int = 8,
    intent_fidelity_notes: str = "",
    deferred_validation: bool = False,
    affected_invariant: str = "",
    evidence_gaps: Optional[List[str]] = None,
    uncertainty_reason: str = "",
    exploit_class: Optional[str] = None,
) -> dict:
    return {
        "judge_version": "2.0",
        "verdict": "finding",
        "intent_fidelity_score": intent_fidelity_score,
        "intent_fidelity_notes": intent_fidelity_notes,
        "finding": {
            "gap_id": gap_id,
            "attacker_gain": attacker_gain,
            "authorization_impact": authorization_impact,
            "value_impact": value_impact,
            "exploit_class": exploit_class,
            "trust_assumption": trust_assumption,
            "affected_invariant": affected_invariant,
            "deferred_validation": deferred_validation,
            "attacker_controlled_inputs": ["tx.inputs"] if attacker_gain else [],
            "spend_path": {"function": "", "line_hint": 0},
            "fact_refs": [],
            "contradicts_fact_ids": [],
            "evidence_gaps": evidence_gaps or [],
            "uncertainty_reason": uncertainty_reason,
            "reasoning_steps": _reasoning_steps(),
            "summary": summary,
            "reasoning": reasoning,
            "recommendation": recommendation,
            "confidence": confidence,
        },
    }


def _safe_llm() -> dict:
    """Default V2 mock payload for matrix scenarios."""
    return _safe_llm_v2()


SCENARIOS: List[ClassificationScenario] = [
    # ── Payroll ──────────────────────────────────────────────────────────────
    ClassificationScenario(
        scenario_id="payroll_a",
        suite="Payroll",
        description="Recipients fixed; salary amounts NOT fixed",
        code=PAYROLL_RECIPIENTS_ONLY,
        intent=PAYROLL_INTENT_FIXED,
        effective_mode="split_payment",
        llm_payload=_safe_llm(),
        expectation=ClassificationExpectation(
            rule_id="intent_fixed_amount_per_recipient",
            kinds={FindingKind.INVARIANT_GAP},
            forbidden_kinds={FindingKind.OPERATIONAL_RISK, FindingKind.OBSERVATION},
            severities={Severity.MEDIUM},
            triggerabilities={Triggerability.ATTACKER},
            confidences={ConfidenceLevel.PROVEN},
            title_prefixes={"Policy Gap"},
            provenance=Provenance.DETERMINISTIC,
        ),
    ),
    ClassificationScenario(
        scenario_id="payroll_b",
        suite="Payroll",
        description="Recipients fixed; salary amounts fixed",
        code=PAYROLL_FIXED_SALARY,
        intent=PAYROLL_INTENT_FIXED,
        effective_mode="split_payment",
        llm_payload=_safe_llm(),
        expectation=ClassificationExpectation(
            absent_rule_id="intent_fixed_amount_per_recipient",
        ),
    ),
    ClassificationScenario(
        scenario_id="payroll_c",
        suite="Payroll",
        description="Correct payroll contract; LLM raises treasury underfunding",
        code=PAYROLL_FIXED_SALARY,
        intent=PAYROLL_INTENT_FIXED,
        effective_mode="split_payment",
        llm_payload=_v2_finding(
            gap_id="semantic.treasury_prefunding",
            attacker_gain=False,
            value_impact="none",
            trust_assumption="external_funding",
            summary="Treasury may be underfunded relative to payroll obligations.",
            reasoning="Liquidity failure, not an on-chain authorization bypass.",
            recommendation="Ensure treasury is pre-funded off-chain.",
            confidence=0.91,
            intent_fidelity_score=4,
            intent_fidelity_notes="Ensure treasury is pre-funded off-chain.",
            evidence_gaps=["treasury balance not visible on-chain"],
            uncertainty_reason="requires off-chain funding assumptions",
        ),
        legacy_llm_payload={
            "category": "EXPLOIT",
            "exploit_severity": "direct_fund_loss",
            "explanation": "Treasury may be underfunded relative to payroll obligations.",
            "confidence": 0.91,
            "business_logic_score": 4,
            "business_logic_notes": "Ensure treasury is pre-funded off-chain.",
        },
        expectation=ClassificationExpectation(
            kinds={FindingKind.OPERATIONAL_RISK, FindingKind.DEPLOYMENT_REQUIREMENT},
            forbidden_kinds={FindingKind.VULNERABILITY},
            severities={Severity.LOW},
            forbidden_severities={Severity.CRITICAL, Severity.HIGH},
            triggerabilities={Triggerability.NON_ATTACKER},
            confidences={ConfidenceLevel.FIRM, ConfidenceLevel.LIKELY},
            forbidden_title_substrings={"Security Vulnerability", "Major Protocol Flaw"},
            source="semantic",
        ),
    ),
    ClassificationScenario(
        scenario_id="payroll_d",
        suite="Payroll",
        description="Missing admin signature on payout path",
        code=PAYROLL_NO_AUTH,
        intent="Payroll distribution to employees. Owner must sign.",
        effective_mode="split_payment",
        llm_payload=_safe_llm(),
        expectation=ClassificationExpectation(
            rule_id="intent_auth_gate",
            kinds={FindingKind.VULNERABILITY},
            severities={Severity.HIGH},
            triggerabilities={Triggerability.ATTACKER},
            confidences={ConfidenceLevel.PROVEN},
            forbidden_severities={Severity.INFO, Severity.LOW, Severity.MEDIUM},
            forbidden_kinds={FindingKind.INVARIANT_GAP},
            title_prefixes={"Security Vulnerability"},
            provenance=Provenance.DETERMINISTIC,
        ),
    ),
    # ── Escrow ───────────────────────────────────────────────────────────────
    ClassificationScenario(
        scenario_id="escrow_a",
        suite="Escrow",
        description="Refund path missing (semantic)",
        code=ESCROW_RELEASE_ONLY,
        intent="Two-party escrow with release to recipient and refund path for sender after timeout.",
        effective_mode="escrow",
        llm_payload=_v2_finding(
            gap_id="semantic.escrow_refund_missing",
            attacker_gain=True,
            authorization_impact=True,
            value_impact="medium",
            summary="Refund path missing; sender cannot recover funds after timeout.",
            reasoning="Missing refund path allows value lock for sender.",
            recommendation="Add refund function with timelock.",
            confidence=0.88,
            intent_fidelity_score=3,
            intent_fidelity_notes="Add refund function with timelock.",
        ),
        legacy_llm_payload={
            "category": "EXPLOIT",
            "exploit_severity": "partial_violation",
            "explanation": "Refund path missing; sender cannot recover funds after timeout.",
            "confidence": 0.88,
            "business_logic_score": 3,
            "business_logic_notes": "Add refund function with timelock.",
        },
        expectation=ClassificationExpectation(
            rule_id="semantic_moderate_logic_risk",
            kinds={FindingKind.VULNERABILITY, FindingKind.INVARIANT_GAP},
            triggerabilities={Triggerability.ATTACKER, Triggerability.UNKNOWN},
            forbidden_kinds={FindingKind.OPERATIONAL_RISK, FindingKind.DESIGN_TRADE_OFF},
            source="semantic",
        ),
    ),
    ClassificationScenario(
        scenario_id="escrow_b",
        suite="Escrow",
        description="Refund exists but relies on external funding assumption",
        code=ESCROW_WITH_REFUND,
        intent="Escrow with release and refund; external liquidity provider funds the escrow UTXO.",
        effective_mode="escrow",
        llm_payload=_v2_finding(
            gap_id="semantic.escrow_external_funding",
            attacker_gain=False,
            value_impact="none",
            trust_assumption="external_funding",
            summary="Safety relies on external treasury pre-funding the escrow UTXO off-chain.",
            reasoning="Deployment assumption, not an on-chain exploit.",
            recommendation="Document deployment funding requirement.",
            confidence=0.87,
            intent_fidelity_score=6,
            intent_fidelity_notes="Document deployment funding requirement.",
            uncertainty_reason="requires off-chain funding assumptions",
        ),
        legacy_llm_payload={
            "category": "ASSUMPTION",
            "exploit_severity": "n/a",
            "explanation": "Safety relies on external treasury pre-funding the escrow UTXO off-chain.",
            "confidence": 0.87,
            "business_logic_score": 6,
            "business_logic_notes": "Document deployment funding requirement.",
        },
        expectation=ClassificationExpectation(
            rule_id="semantic_minor_design_risk",
            kinds={FindingKind.DEPLOYMENT_REQUIREMENT},
            severities={Severity.LOW},
            triggerabilities={Triggerability.NON_ATTACKER},
            forbidden_kinds={FindingKind.VULNERABILITY},
            forbidden_severities={Severity.CRITICAL, Severity.HIGH},
            forbidden_title_substrings={"Security Vulnerability"},
            source="semantic",
        ),
    ),
    # ── Multisig ─────────────────────────────────────────────────────────────
    ClassificationScenario(
        scenario_id="multisig_a",
        suite="Multisig",
        description="Threshold bypass — single signature on 2-of-3 intent",
        code=MULTISIG_WEAK,
        intent="2-of-3 multisig treasury spend.",
        effective_mode="multisig",
        intent_model=IntentModel(
            contract_type="multisig",
            features=["multisig"],
            signers=["alice", "bob", "carol"],
            threshold=2,
        ),
        llm_payload=_safe_llm(),
        expectation=ClassificationExpectation(
            rule_id="intent_sanity_check",
            kinds={FindingKind.VULNERABILITY},
            severities={Severity.HIGH},
            triggerabilities={Triggerability.ATTACKER},
            forbidden_severities={Severity.INFO, Severity.LOW, Severity.MEDIUM},
            forbidden_kinds={FindingKind.INVARIANT_GAP},
            confidences={ConfidenceLevel.PROVEN},
            title_prefixes={"Security Vulnerability"},
            provenance=Provenance.DETERMINISTIC,
        ),
    ),
    ClassificationScenario(
        scenario_id="multisig_b",
        suite="Multisig",
        description="Threshold enforced — dual checkSig",
        code=MULTISIG_STRONG,
        intent="2-of-3 multisig treasury spend.",
        effective_mode="multisig",
        intent_model=IntentModel(
            contract_type="multisig",
            features=["multisig"],
            signers=["alice", "bob", "carol"],
            threshold=2,
        ),
        llm_payload=_safe_llm(),
        expectation=ClassificationExpectation(
            absent_rule_id="intent_sanity_check",
        ),
    ),
    # ── Vault ────────────────────────────────────────────────────────────────
    ClassificationScenario(
        scenario_id="vault_a",
        suite="Vault",
        description="Missing timelock on delayed withdrawal intent",
        code=VAULT_NO_TIMELOCK,
        intent="Vault with timelock-delayed withdrawal. Owner must sign.",
        effective_mode="vault",
        intent_model=IntentModel(
            contract_type="timelock",
            features=["timelock"],
            signers=["owner"],
            threshold=1,
        ),
        llm_payload=_safe_llm(),
        expectation=ClassificationExpectation(
            rule_id="intent_sanity_check",
            kinds={FindingKind.VULNERABILITY},
            severities={Severity.HIGH},
            triggerabilities={Triggerability.ATTACKER},
            confidences={ConfidenceLevel.PROVEN},
            forbidden_kinds={FindingKind.INVARIANT_GAP},
            forbidden_severities={Severity.MEDIUM, Severity.LOW, Severity.INFO},
            title_prefixes={"Security Vulnerability"},
            provenance=Provenance.DETERMINISTIC,
        ),
    ),
    ClassificationScenario(
        scenario_id="vault_b",
        suite="Vault",
        description="Timelock enforced",
        code=VAULT_WITH_TIMELOCK,
        intent="Vault with timelock-delayed withdrawal. Owner must sign.",
        effective_mode="vault",
        intent_model=IntentModel(
            contract_type="timelock",
            features=["timelock"],
            signers=["owner"],
            threshold=1,
        ),
        llm_payload=_safe_llm(),
        expectation=ClassificationExpectation(
            absent_rule_id="intent_sanity_check",
        ),
    ),
    # ── Split payment ────────────────────────────────────────────────────────
    ClassificationScenario(
        scenario_id="split_a",
        suite="Split Payment",
        description="Recipient binding only; fixed amounts missing",
        code=SPLIT_RECIPIENTS_ONLY,
        intent=SPLIT_INTENT_FIXED,
        effective_mode="split_payment",
        llm_payload=_safe_llm(),
        expectation=ClassificationExpectation(
            rule_id="intent_fixed_amount_per_recipient",
            kinds={FindingKind.INVARIANT_GAP},
            severities={Severity.MEDIUM},
            triggerabilities={Triggerability.ATTACKER},
            confidences={ConfidenceLevel.PROVEN},
            title_prefixes={"Policy Gap"},
        ),
    ),
    ClassificationScenario(
        scenario_id="split_b",
        suite="Split Payment",
        description="Recipient and amount binding present",
        code=SPLIT_RECIPIENTS_AND_AMOUNTS,
        intent=SPLIT_INTENT_FIXED,
        effective_mode="split_payment",
        llm_payload=_safe_llm(),
        expectation=ClassificationExpectation(
            absent_rule_id="intent_fixed_amount_per_recipient",
        ),
    ),
    # ── CashTokens ───────────────────────────────────────────────────────────
    ClassificationScenario(
        scenario_id="token_a",
        suite="CashToken",
        description="Unauthorized mint path (no auth category check)",
        code=TOKEN_UNAUTHORIZED_MINT,
        intent="Mint only with authority category on input.",
        effective_mode="nft_minting",
        llm_payload=_safe_llm(),
        expectation=ClassificationExpectation(
            rule_id="unbounded_mint",
            kinds={FindingKind.VULNERABILITY},
            triggerabilities={Triggerability.ATTACKER},
            forbidden_kinds={FindingKind.OPERATIONAL_RISK},
            title_prefixes={"Security Vulnerability"},
        ),
    ),
    ClassificationScenario(
        scenario_id="token_b",
        suite="CashToken",
        description="Supply cap not enforced on-chain (semantic)",
        code=TOKEN_NO_SUPPLY_CAP,
        intent="Capped token mint with maximum supply of 1 million tokens. Owner must sign.",
        effective_mode="ft_mint",
        llm_payload=_v2_finding(
            gap_id="semantic.supply_cap_missing",
            attacker_gain=True,
            authorization_impact=False,
            value_impact="medium",
            summary="Mint path does not enforce maxSupply cap on-chain.",
            reasoning="Uncapped mint allows supply inflation beyond intent.",
            recommendation="Add require(amount <= maxSupply).",
            confidence=0.86,
            intent_fidelity_score=3,
            intent_fidelity_notes="Add require(amount <= maxSupply).",
        ),
        legacy_llm_payload={
            "category": "EXPLOIT",
            "exploit_severity": "partial_violation",
            "explanation": "Mint path does not enforce maxSupply cap on-chain.",
            "confidence": 0.86,
            "business_logic_score": 3,
            "business_logic_notes": "Add require(amount <= maxSupply).",
        },
        expectation=ClassificationExpectation(
            rule_id="semantic_moderate_logic_risk",
            kinds={FindingKind.VULNERABILITY, FindingKind.INVARIANT_GAP},
            triggerabilities={Triggerability.ATTACKER, Triggerability.UNKNOWN},
            forbidden_kinds={FindingKind.OPERATIONAL_RISK},
            source="semantic",
        ),
    ),
    # ── Design trade-off ─────────────────────────────────────────────────────
    ClassificationScenario(
        scenario_id="design_exact_equality",
        suite="Design Trade-Off",
        description="Exact equality constraint (semantic)",
        code=PAYROLL_FIXED_SALARY,
        intent="Payroll with fixed salaries.",
        effective_mode="split_payment",
        llm_payload=_v2_finding(
            gap_id="semantic.exact_equality_rigidity",
            attacker_gain=False,
            value_impact="low",
            summary="Exact equality constraints on output amounts may cause operational failure if fees vary.",
            reasoning="Design rigidity without attacker gain.",
            recommendation="Accepted rigidity.",
            confidence=0.9,
            intent_fidelity_score=5,
            intent_fidelity_notes="Accepted rigidity.",
            exploit_class="griefing",
        ),
        legacy_llm_payload={
            "category": "DESIGN_TRADEOFF",
            "exploit_severity": "direct_fund_loss",
            "explanation": "Exact equality constraints on output amounts may cause operational failure if fees vary.",
            "confidence": 0.9,
            "business_logic_score": 5,
            "business_logic_notes": "Accepted rigidity.",
        },
        expectation=ClassificationExpectation(
            rule_id="semantic_moderate_logic_risk",
            kinds={FindingKind.DESIGN_TRADE_OFF},
            severities={Severity.INFO},
            triggerabilities={Triggerability.NON_ATTACKER},
            forbidden_severities={Severity.HIGH, Severity.CRITICAL},
            forbidden_kinds={FindingKind.VULNERABILITY},
            title_prefixes={"Design Trade-off"},
            forbidden_title_substrings={"Security"},
            source="semantic",
        ),
    ),
    ClassificationScenario(
        scenario_id="design_no_change",
        suite="Design Trade-Off",
        description="No change output support (semantic)",
        code=PAYROLL_FIXED_SALARY,
        intent="Payroll with fixed salaries.",
        effective_mode="split_payment",
        llm_payload=_v2_finding(
            gap_id="semantic.no_change_output",
            attacker_gain=False,
            value_impact="low",
            summary="Contract does not handle change outputs or dust change.",
            reasoning="Operational design choice without attacker benefit.",
            recommendation="Intentional exact-output design.",
            confidence=0.88,
            intent_fidelity_score=6,
            intent_fidelity_notes="Intentional exact-output design.",
        ),
        legacy_llm_payload={
            "category": "DESIGN_TRADEOFF",
            "exploit_severity": "n/a",
            "explanation": "Contract does not handle change outputs or dust change.",
            "confidence": 0.88,
            "business_logic_score": 6,
            "business_logic_notes": "Intentional exact-output design.",
        },
        expectation=ClassificationExpectation(
            rule_id="semantic_moderate_logic_risk",
            kinds={FindingKind.DESIGN_TRADE_OFF},
            severities={Severity.INFO},
            triggerabilities={Triggerability.NON_ATTACKER},
            forbidden_title_substrings={"Security Vulnerability", "Major Protocol Flaw"},
            source="semantic",
        ),
    ),
    # ── Confidence validation ────────────────────────────────────────────────
    ClassificationScenario(
        scenario_id="confidence_deterministic",
        suite="Confidence",
        description="Deterministic intent finding is PROVEN",
        code=PAYROLL_RECIPIENTS_ONLY,
        intent=PAYROLL_INTENT_FIXED,
        effective_mode="split_payment",
        llm_payload=_safe_llm(),
        expectation=ClassificationExpectation(
            rule_id="intent_fixed_amount_per_recipient",
            confidences={ConfidenceLevel.PROVEN},
            provenance=Provenance.DETERMINISTIC,
        ),
    ),
    ClassificationScenario(
        scenario_id="confidence_llm_only",
        suite="Confidence",
        description="LLM-only finding is never PROVEN",
        code=PAYROLL_FIXED_SALARY,
        intent=PAYROLL_INTENT_FIXED,
        effective_mode="split_payment",
        llm_payload=_v2_finding(
            gap_id="semantic.payout_ordering",
            attacker_gain=True,
            value_impact="low",
            summary="Edge case in payout ordering may confuse operators.",
            reasoning="Partial violation in rare ordering layouts.",
            recommendation="Review ordering.",
            confidence=0.75,
            intent_fidelity_score=4,
            intent_fidelity_notes="Review ordering.",
        ),
        legacy_llm_payload={
            "category": "EXPLOIT",
            "exploit_severity": "partial_violation",
            "explanation": "Edge case in payout ordering may confuse operators.",
            "confidence": 0.75,
            "business_logic_score": 4,
            "business_logic_notes": "Review ordering.",
        },
        expectation=ClassificationExpectation(
            rule_id="semantic_moderate_logic_risk",
            forbidden_confidences={ConfidenceLevel.PROVEN},
            provenance=Provenance.LLM,
            source="semantic",
        ),
    ),
    # ── Triggerability validation ────────────────────────────────────────────
    ClassificationScenario(
        scenario_id="trigger_attacker_payout",
        suite="Triggerability",
        description="Unrestricted payout path",
        code=PAYROLL_NO_AUTH,
        intent="Payroll payout. Owner must sign.",
        effective_mode="split_payment",
        llm_payload=_safe_llm(),
        expectation=ClassificationExpectation(
            rule_id="intent_auth_gate",
            triggerabilities={Triggerability.ATTACKER},
            kinds={FindingKind.VULNERABILITY},
            severities={Severity.HIGH},
        ),
    ),
    ClassificationScenario(
        scenario_id="trigger_non_attacker_treasury",
        suite="Triggerability",
        description="Treasury underfunding narrative",
        code=PAYROLL_FIXED_SALARY,
        intent=PAYROLL_INTENT_FIXED,
        effective_mode="split_payment",
        llm_payload=_v2_finding(
            gap_id="semantic.treasury_underfunding",
            attacker_gain=False,
            value_impact="none",
            trust_assumption="external_funding",
            summary="Treasury may be underfunded; insufficient funds could block payroll.",
            reasoning="Operational liquidity concern, not unauthorized extraction.",
            recommendation="Pre-fund treasury.",
            confidence=0.9,
            intent_fidelity_score=3,
            intent_fidelity_notes="Pre-fund treasury.",
            uncertainty_reason="requires off-chain funding assumptions",
        ),
        legacy_llm_payload={
            "category": "EXPLOIT",
            "exploit_severity": "direct_fund_loss",
            "explanation": "Treasury may be underfunded; insufficient funds could block payroll.",
            "confidence": 0.9,
            "business_logic_score": 3,
            "business_logic_notes": "Pre-fund treasury.",
        },
        expectation=ClassificationExpectation(
            triggerabilities={Triggerability.NON_ATTACKER},
            forbidden_kinds={FindingKind.VULNERABILITY},
            max_severity=Severity.LOW,
            source="semantic",
        ),
    ),
    ClassificationScenario(
        scenario_id="trigger_non_attacker_dust",
        suite="Triggerability",
        description="Dust and fee assumptions",
        code=PAYROLL_FIXED_SALARY,
        intent=PAYROLL_INTENT_FIXED,
        effective_mode="split_payment",
        llm_payload=_v2_finding(
            gap_id="semantic.dust_fee_assumptions",
            attacker_gain=False,
            value_impact="low",
            summary="Fee assumptions and dust outputs are not handled; honest spends may fail.",
            reasoning="Design/operational friction without attacker gain.",
            recommendation="Operational consideration.",
            confidence=0.85,
            intent_fidelity_score=5,
            intent_fidelity_notes="Operational consideration.",
        ),
        legacy_llm_payload={
            "category": "DESIGN_TRADEOFF",
            "exploit_severity": "n/a",
            "explanation": "Fee assumptions and dust outputs are not handled; honest spends may fail.",
            "confidence": 0.85,
            "business_logic_score": 5,
            "business_logic_notes": "Operational consideration.",
        },
        expectation=ClassificationExpectation(
            triggerabilities={Triggerability.NON_ATTACKER},
            kinds={FindingKind.DESIGN_TRADE_OFF, FindingKind.OPERATIONAL_RISK},
            max_severity=Severity.INFO,
            source="semantic",
        ),
    ),
    ClassificationScenario(
        scenario_id="trigger_unknown_capped",
        suite="Triggerability",
        description="Ambiguous edge case must not exceed MEDIUM",
        code=PAYROLL_FIXED_SALARY,
        intent=PAYROLL_INTENT_FIXED,
        effective_mode="split_payment",
        llm_payload=_v2_finding(
            gap_id="semantic.output_ordering_edge",
            attacker_gain=True,
            authorization_impact=False,
            value_impact="medium",
            summary="Output ordering edge case under rare transaction layouts.",
            reasoning="Ambiguous partial violation under rare layouts.",
            recommendation="Needs review.",
            confidence=0.55,
            intent_fidelity_score=4,
            intent_fidelity_notes="Needs review.",
            evidence_gaps=["full transaction layout not proven"],
            uncertainty_reason="ambiguous edge case",
        ),
        legacy_llm_payload={
            "category": "EXPLOIT",
            "exploit_severity": "partial_violation",
            "explanation": "Output ordering edge case under rare transaction layouts.",
            "confidence": 0.55,
            "business_logic_score": 4,
            "business_logic_notes": "Needs review.",
        },
        expectation=ClassificationExpectation(
            triggerabilities={Triggerability.ATTACKER, Triggerability.UNKNOWN},
            max_severity=Severity.MEDIUM,
            source="semantic",
        ),
    ),
]


@dataclass
class ScenarioResult:
    scenario_id: str
    suite: str
    description: str
    passed: bool
    primary_rule_id: Optional[str]
    actual_kind: Optional[str]
    actual_severity: Optional[str]
    actual_triggerability: Optional[str]
    actual_confidence: Optional[str]
    actual_provenance: Optional[str]
    actual_title: Optional[str]
    expected_summary: str
    mismatches: List[str]
    all_issue_summaries: List[str]


def _issue_summary(issue: AuditIssue) -> str:
    return (
        f"{issue.rule_id} | {issue.kind.value} | {issue.severity.value} | "
        f"{issue.triggerability.value} | {issue.confidence.value} | "
        f"{issue.provenance.value} | {issue.title}"
    )


def _find_primary(report: AuditReport, exp: ClassificationExpectation) -> Optional[AuditIssue]:
    if exp.rule_id:
        matches = [i for i in report.issues if i.rule_id == exp.rule_id]
        if matches:
            return matches[0]
        if exp.source:
            src_matches = [i for i in report.issues if i.source == exp.source]
            if src_matches:
                return src_matches[0]
        return None
    if exp.source:
        src_matches = [i for i in report.issues if i.source == exp.source]
        return src_matches[0] if src_matches else None
    return report.issues[0] if report.issues else None


def evaluate_scenario(report: AuditReport, scenario: ClassificationScenario) -> ScenarioResult:
    exp = scenario.expectation
    mismatches: List[str] = []
    all_summaries = [_issue_summary(i) for i in report.issues]

    if exp.absent_rule_id:
        found = [i for i in report.issues if i.rule_id == exp.absent_rule_id]
        if found:
            mismatches.append(
                f"Expected absence of {exp.absent_rule_id}, found: {_issue_summary(found[0])}"
            )
        return ScenarioResult(
            scenario_id=scenario.scenario_id,
            suite=scenario.suite,
            description=scenario.description,
            passed=len(mismatches) == 0,
            primary_rule_id=None,
            actual_kind=None,
            actual_severity=None,
            actual_triggerability=None,
            actual_confidence=None,
            actual_provenance=None,
            actual_title=None,
            expected_summary=f"no finding with rule_id={exp.absent_rule_id}",
            mismatches=mismatches,
            all_issue_summaries=all_summaries,
        )

    primary = _find_primary(report, exp)
    if primary is None:
        mismatches.append(f"No primary finding for rule_id={exp.rule_id!r}")
        return ScenarioResult(
            scenario_id=scenario.scenario_id,
            suite=scenario.suite,
            description=scenario.description,
            passed=False,
            primary_rule_id=exp.rule_id,
            actual_kind=None,
            actual_severity=None,
            actual_triggerability=None,
            actual_confidence=None,
            actual_provenance=None,
            actual_title=None,
            expected_summary=_format_expected(exp),
            mismatches=mismatches,
            all_issue_summaries=all_summaries,
        )

    def _check_set(name: str, actual, allowed: Optional[Set], forbidden: Set):
        if allowed is not None and actual not in allowed:
            mismatches.append(f"{name}: got {actual!r}, expected one of {sorted(x.value for x in allowed)}")
        if actual in forbidden:
            mismatches.append(f"{name}: forbidden {actual!r}")

    _check_set("kind", primary.kind, exp.kinds, exp.forbidden_kinds)
    _check_set("severity", primary.severity, exp.severities, exp.forbidden_severities)
    _check_set("triggerability", primary.triggerability, exp.triggerabilities, set())
    _check_set("confidence", primary.confidence, exp.confidences, exp.forbidden_confidences)

    if exp.provenance is not None and primary.provenance != exp.provenance:
        mismatches.append(
            f"provenance: got {primary.provenance.value}, expected {exp.provenance.value}"
        )
    if exp.title_prefixes:
        if not any(primary.title.startswith(p) for p in exp.title_prefixes):
            mismatches.append(
                f"title prefix: got {primary.title!r}, expected one of {exp.title_prefixes}"
            )
    for bad in exp.forbidden_title_substrings:
        if bad.lower() in primary.title.lower():
            mismatches.append(f"forbidden title substring present: {bad!r}")

    if exp.max_severity is not None:
        order = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
        if order.index(primary.severity) > order.index(exp.max_severity):
            mismatches.append(
                f"severity {primary.severity.value} exceeds max {exp.max_severity.value}"
            )

    return ScenarioResult(
        scenario_id=scenario.scenario_id,
        suite=scenario.suite,
        description=scenario.description,
        passed=len(mismatches) == 0,
        primary_rule_id=primary.rule_id,
        actual_kind=primary.kind.value,
        actual_severity=primary.severity.value,
        actual_triggerability=primary.triggerability.value,
        actual_confidence=primary.confidence.value,
        actual_provenance=primary.provenance.value,
        actual_title=primary.title,
        expected_summary=_format_expected(exp),
        mismatches=mismatches,
        all_issue_summaries=all_summaries,
    )


def _format_expected(exp: ClassificationExpectation) -> str:
    parts = []
    if exp.absent_rule_id:
        parts.append(f"absent:{exp.absent_rule_id}")
    if exp.rule_id:
        parts.append(f"rule_id={exp.rule_id}")
    if exp.kinds:
        parts.append("kind=" + "|".join(sorted(k.value for k in exp.kinds)))
    if exp.severities:
        parts.append("severity=" + "|".join(sorted(s.value for s in exp.severities)))
    if exp.triggerabilities:
        parts.append("trigger=" + "|".join(sorted(t.value for t in exp.triggerabilities)))
    if exp.confidences:
        parts.append("confidence=" + "|".join(sorted(c.value for c in exp.confidences)))
    if exp.title_prefixes:
        parts.append("title_prefix=" + "|".join(exp.title_prefixes))
    if exp.max_severity:
        parts.append(f"max_severity={exp.max_severity.value}")
    return "; ".join(parts) if parts else "(see scenario)"
