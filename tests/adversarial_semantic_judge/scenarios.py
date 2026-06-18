"""
Adversarial red-team scenarios for Semantic Security Judge V2.

Each scenario supplies an intentionally flawed or edge-case LLM judgment
to stress guards, policy mapping, and deterministic fact layers.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set

from src.models import FindingKind, IntentModel

from tests.audit_classification_matrix.scenarios import (
    MULTISIG_WEAK,
    PAYROLL_FIXED_SALARY,
    PAYROLL_NO_AUTH,
    PAYROLL_RECIPIENTS_ONLY,
    VAULT_NO_TIMELOCK,
    VAULT_WITH_TIMELOCK,
)

# ── Adversarial contract fixtures ─────────────────────────────────────────────

ONE_SATOSHI_REDIRECT = """
pragma cashscript ^0.13.0;
contract LeakyPayout(pubkey owner, bytes victimLock, bytes attackerLock) {
    function pay(sig ownerSig) {
        require(checkSig(ownerSig, owner));
        require(tx.outputs.length == 2);
        require(tx.outputs[0].lockingBytecode == victimLock);
        // Output[1] destination unconstrained — attacker can redirect dust or full remainder.
        require(tx.outputs[0].value + tx.outputs[1].value == tx.inputs[this.activeInputIndex].value);
    }
}
"""

TOKEN_BURN_NO_GAIN = """
pragma cashscript ^0.13.0;
contract TokenBurner() {
    function burn() {
        require(tx.outputs.length == 1);
        require(tx.outputs[0].tokenAmount == 0);
        require(tx.outputs[0].tokenCategory == 0x00);
    }
}
"""

PERMANENT_LOCK = """
pragma cashscript ^0.13.0;
contract PermanentLock() {
    function deposit() {
        require(false);
    }
}
"""

PARTIAL_AUTH_BYPASS = """
pragma cashscript ^0.13.0;
contract DualPath(pubkey admin, bytes publicLock) {
    function adminSpend(sig adminSig) {
        require(checkSig(adminSig, admin));
        require(tx.outputs.length == 1);
        require(tx.outputs[0].value == tx.inputs[this.activeInputIndex].value);
    }
    function publicSpend() {
        require(tx.outputs.length == 1);
        require(tx.outputs[0].lockingBytecode == publicLock);
        require(tx.outputs[0].value == tx.inputs[this.activeInputIndex].value);
    }
}
"""

ORACLE_PRICE = """
pragma cashscript ^0.13.0;
contract OracleSwap(pubkey owner, bytes oracleLock, int minPrice) {
    function swap(sig ownerSig) {
        require(checkSig(ownerSig, owner));
        require(tx.inputs.length >= 2);
        require(tx.inputs[1].lockingBytecode == oracleLock);
        require(tx.outputs.length == 1);
        require(tx.outputs[0].value >= minPrice);
    }
}
"""

OFFCHAIN_KEY_ROTATION = """
pragma cashscript ^0.13.0;
contract RotatedKeys(pubkey operator) {
    function operate(sig operatorSig) {
        require(checkSig(operatorSig, operator));
        require(tx.outputs.length == 1);
        require(tx.outputs[0].value == tx.inputs[this.activeInputIndex].value);
    }
}
"""

TOKEN_NO_CATEGORY = """
pragma cashscript ^0.13.0;
contract LooseToken() {
    function transfer() {
        require(tx.outputs.length == 1);
        require(tx.outputs[0].tokenAmount == tx.inputs[this.activeInputIndex].tokenAmount);
    }
}
"""

NFT_COMMITMENT_BROKEN = """
pragma cashscript ^0.13.0;
contract BrokenNFT() {
    function spend() {
        require(tx.outputs.length == 1);
        require(tx.outputs[0].tokenCategory == tx.inputs[this.activeInputIndex].tokenCategory);
    }
}
"""

MUTABLE_METADATA_ONLY = """
pragma cashscript ^0.13.0;
contract MutableMeta(pubkey owner) {
    function update(sig ownerSig, bytes newCommitment) {
        require(checkSig(ownerSig, owner));
        require(tx.outputs.length == 1);
        require(tx.outputs[0].nftCommitment == newCommitment);
        require(tx.outputs[0].tokenCategory == tx.inputs[this.activeInputIndex].tokenCategory);
    }
}
"""

MIXED_TREASURY_NO_AUTH = """
pragma cashscript ^0.13.0;
contract MixedPayroll(bytes e1Lock, bytes e2Lock) {
    function pay() {
        require(tx.outputs.length == 2);
        require(tx.outputs[0].lockingBytecode == e1Lock);
        require(tx.outputs[1].lockingBytecode == e2Lock);
        require(
            tx.outputs[0].value + tx.outputs[1].value ==
            tx.inputs[this.activeInputIndex].value
        );
    }
}
"""

MIXED_SALARY_MULTISIG = """
pragma cashscript ^0.13.0;
contract MixedOps(pubkey alice, bytes e1Lock) {
    function pay(sig aliceSig) {
        require(checkSig(aliceSig, alice));
        require(tx.outputs.length == 1);
        require(tx.outputs[0].lockingBytecode == e1Lock);
    }
}
"""

PAYROLL_INTENT_FIXED = (
    "Payroll distributing fixed salary amounts to predetermined employee lockingBytecode "
    "destinations. Owner must authorize each payout."
)


def _steps(*parts: str) -> List[str]:
    base = [
        "Examined declared intent invariants for this contract pattern.",
        "Identified attacker-controlled transaction inputs relevant to the spend path.",
        "Assessed value impact on BCH and token flows.",
        "Determined whether an attacker gains unauthorized value or authorization.",
    ]
    return list(parts) if parts else base


def _v21_steps(
    invariant: str,
    attacker_control: str,
    value_impact: str,
    attacker_gain_reason: str,
    trust_check: str,
    contradiction_check: str,
) -> List[str]:
    return [
        f"Invariant examined: {invariant}",
        f"Attacker control: {attacker_control}",
        f"Value impact: {value_impact}",
        f"Attacker gain: {attacker_gain_reason}",
        f"Trust assumption check: {trust_check}",
        f"Contradiction check: {contradiction_check}",
    ]


def _finding(
    *,
    gap_id: str,
    attacker_gain: bool = False,
    authorization_impact: bool = False,
    value_impact: str = "none",
    trust_assumption: str = "none",
    summary: str = "",
    reasoning: str = "",
    recommendation: str = "",
    confidence: float = 0.9,
    attacker_controlled_inputs: Optional[List[str]] = None,
    fact_refs: Optional[List[str]] = None,
    contradicts_fact_ids: Optional[List[str]] = None,
    evidence_gaps: Optional[List[str]] = None,
    uncertainty_reason: str = "",
    affected_invariant: str = "",
    deferred_validation: bool = False,
    exploit_class: Optional[str] = None,
    reasoning_steps: Optional[List[str]] = None,
) -> Dict[str, Any]:
    return {
        "gap_id": gap_id,
        "attacker_gain": attacker_gain,
        "authorization_impact": authorization_impact,
        "value_impact": value_impact,
        "trust_assumption": trust_assumption,
        "affected_invariant": affected_invariant,
        "deferred_validation": deferred_validation,
        "attacker_controlled_inputs": attacker_controlled_inputs
        if attacker_controlled_inputs is not None
        else (["tx.outputs[1]"] if attacker_gain else []),
        "spend_path": {"function": "", "line_hint": 0},
        "fact_refs": fact_refs or [],
        "contradicts_fact_ids": contradicts_fact_ids or [],
        "evidence_gaps": evidence_gaps or [],
        "uncertainty_reason": uncertainty_reason,
        "reasoning_steps": reasoning_steps or _steps(),
        "summary": summary,
        "reasoning": reasoning,
        "recommendation": recommendation,
        "confidence": confidence,
        "exploit_class": exploit_class,
    }


def _judgment(
    finding: Optional[Dict[str, Any]] = None,
    *,
    verdict: str = "finding",
    fidelity: int = 5,
    notes: str = "",
    judge_version: str = "2.0",
) -> Dict[str, Any]:
    payload: Dict[str, Any] = {
        "judge_version": judge_version,
        "verdict": verdict,
        "intent_fidelity_score": fidelity,
        "intent_fidelity_notes": notes,
    }
    if finding is not None:
        payload["finding"] = finding
    return payload


def _judgment_v21(
    finding: Optional[Dict[str, Any]] = None,
    *,
    verdict: str = "finding",
    fidelity: int = 5,
    notes: str = "",
) -> Dict[str, Any]:
    return _judgment(finding, verdict=verdict, fidelity=fidelity, notes=notes, judge_version="2.1")


@dataclass
class AdversarialScenario:
    scenario_id: str
    category: str
    intent: str
    behavior: str
    code: str
    adversarial_judgment: Dict[str, Any]
    ground_truth_kinds: Set[FindingKind]
    ground_truth_notes: str
    effective_mode: str = ""
    intent_model: Optional[IntentModel] = None
    evaluation_mode: str = "semantic_only"  # semantic_only | full_audit
    expect_contradiction: bool = False
    expect_uncertainty_cap: bool = False
    max_confidence: Optional[float] = None
    forbidden_kinds: Set[FindingKind] = field(default_factory=set)
    must_include_deterministic: Optional[str] = None
    synthetic_bundle_overrides: Optional[Dict[str, Any]] = None
    v2_1_compliant_judgment: Optional[Dict[str, Any]] = None


ADVERSARIAL_SCENARIOS: List[AdversarialScenario] = [
    # ── Category 1: Attacker Gain ───────────────────────────────────────────
    AdversarialScenario(
        scenario_id="AG-1",
        category="Attacker Gain",
        intent="Owner-signed payroll; victim output fixed, second output unconstrained.",
        behavior="Attacker can redirect remainder (even 1 satoshi) via unconstrained output[1].",
        code=ONE_SATOSHI_REDIRECT,
        effective_mode="split_payment",
        adversarial_judgment=_judgment(
            _finding(
                gap_id="semantic.dust_redirect",
                attacker_gain=False,
                value_impact="none",
                summary="Only dust-level value could be redirected.",
                reasoning="Impact negligible; operational rounding issue.",
            )
        ),
        ground_truth_kinds={FindingKind.VULNERABILITY, FindingKind.INVARIANT_GAP},
        ground_truth_notes="Small value redirect is still attacker_gain with value_impact low+.",
        forbidden_kinds={FindingKind.OPERATIONAL_RISK, FindingKind.DEPLOYMENT_REQUIREMENT},
    ),
    AdversarialScenario(
        scenario_id="AG-2",
        category="Attacker Gain",
        intent="Token contract; burning should not destroy others' balances without authorization.",
        behavior="Anyone can burn tokens from contract input without auth gate.",
        code=TOKEN_BURN_NO_GAIN,
        adversarial_judgment=_judgment(
            _finding(
                gap_id="semantic.token_burn",
                attacker_gain=False,
                authorization_impact=False,
                value_impact="low",
                summary="Attacker burns tokens but gains nothing personally.",
                reasoning="Destructive but no direct profit.",
            )
        ),
        ground_truth_kinds={FindingKind.VULNERABILITY, FindingKind.INVARIANT_GAP},
        ground_truth_notes="Destructive unauthorized action = authorization_impact even without gain.",
        forbidden_kinds={FindingKind.DESIGN_TRADE_OFF, FindingKind.OBSERVATION},
    ),
    AdversarialScenario(
        scenario_id="AG-3",
        category="Attacker Gain",
        intent="Vault accepts deposits but has no spend path.",
        behavior="Funds permanently locked; denial-of-access.",
        code=PERMANENT_LOCK,
        adversarial_judgment=_judgment(
            _finding(
                gap_id="semantic.funds_unspendable",
                affected_invariant="funds_unspendable",
                attacker_gain=False,
                value_impact="none",
                summary="Funds cannot be spent by anyone.",
                reasoning="No spend path exists; griefing not attacker profit.",
            )
        ),
        ground_truth_kinds={FindingKind.VULNERABILITY},
        ground_truth_notes="Permanent lock is VULNERABILITY via funds_unspendable special case.",
    ),
    # ── Category 2: Authorization ───────────────────────────────────────────
    AdversarialScenario(
        scenario_id="AUTH-1",
        category="Authorization",
        intent="2-of-3 multisig treasury spend.",
        behavior="Only single checkSig; threshold not enforced on-chain.",
        code=MULTISIG_WEAK,
        effective_mode="multisig",
        intent_model=IntentModel(
            contract_type="multisig",
            features=["multisig"],
            signers=["alice", "bob", "carol"],
            threshold=2,
        ),
        adversarial_judgment=_judgment(verdict="no_issue"),
        evaluation_mode="full_audit",
        ground_truth_kinds={FindingKind.VULNERABILITY},
        ground_truth_notes="Deterministic intent_sanity_check must surface multisig bypass.",
        must_include_deterministic="intent_sanity_check",
        forbidden_kinds={FindingKind.INVARIANT_GAP},
    ),
    AdversarialScenario(
        scenario_id="AUTH-2",
        category="Authorization",
        intent=f"{PAYROLL_INTENT_FIXED} Owner must sign all spends.",
        behavior="Bundle proves checkSig present; judge hallucinates missing auth.",
        code=PAYROLL_FIXED_SALARY,
        effective_mode="split_payment",
        adversarial_judgment=_judgment(
            _finding(
                gap_id="semantic.missing_auth",
                attacker_gain=True,
                authorization_impact=True,
                value_impact="high",
                summary="Missing authorization on payout path.",
                reasoning="No signature gate protects funds.",
                fact_refs=["cap.has_signature_auth"],
            )
        ),
        ground_truth_kinds={
            FindingKind.INVARIANT_GAP,
            FindingKind.OBSERVATION,
            FindingKind.DEPLOYMENT_REQUIREMENT,
        },
        ground_truth_notes="Hallucinated missing auth should trigger contradicts_fact_ids; must not be VULNERABILITY.",
        expect_contradiction=True,
        max_confidence=0.5,
        forbidden_kinds={FindingKind.VULNERABILITY},
        synthetic_bundle_overrides={
            "capabilities": {
                "evidence": [
                    {
                        "fact_id": "cap.has_signature_auth",
                        "key": "has_signature_auth",
                        "value": True,
                        "tier": "Authorization",
                        "source": "ast",
                        "anchors": ["checkSig(ownerSig, owner)"],
                    }
                ]
            }
        },
    ),
    AdversarialScenario(
        scenario_id="AUTH-3",
        category="Authorization",
        intent="Admin path signed; public path must not move value without policy.",
        behavior="publicSpend() bypasses signature entirely.",
        code=PARTIAL_AUTH_BYPASS,
        adversarial_judgment=_judgment(
            _finding(
                gap_id="semantic.public_spend_bypass",
                attacker_gain=True,
                authorization_impact=True,
                value_impact="high",
                summary="Unsigned publicSpend drains input to chosen lock.",
                reasoning="Attacker calls publicSpend without admin signature.",
                attacker_controlled_inputs=["function selector", "tx.outputs[0].lockingBytecode"],
            )
        ),
        ground_truth_kinds={FindingKind.VULNERABILITY},
        ground_truth_notes="Partial authorization failure on alternate path.",
    ),
    # ── Category 3: Trust Assumption ─────────────────────────────────────────
    AdversarialScenario(
        scenario_id="TRUST-1",
        category="Trust Assumption",
        intent=f"{PAYROLL_INTENT_FIXED} Treasury must be externally pre-funded.",
        behavior="Script fails if input underfunded; no attacker extraction path.",
        code=PAYROLL_FIXED_SALARY,
        effective_mode="split_payment",
        adversarial_judgment=_judgment(
            _finding(
                gap_id="semantic.treasury_drain",
                attacker_gain=True,
                authorization_impact=True,
                value_impact="high",
                summary="Treasury underfunding enables fund theft.",
                reasoning="Attacker exploits low balance.",
            )
        ),
        ground_truth_kinds={FindingKind.DEPLOYMENT_REQUIREMENT, FindingKind.OPERATIONAL_RISK},
        ground_truth_notes="Treasury liquidity is deploy/ops, not VULNERABILITY.",
        forbidden_kinds={FindingKind.VULNERABILITY},
    ),
    AdversarialScenario(
        scenario_id="TRUST-2",
        category="Trust Assumption",
        intent="Swap uses honest oracle price feed on input[1].",
        behavior="Correct if oracle honest; trust assumption not auth bypass.",
        code=ORACLE_PRICE,
        adversarial_judgment=_judgment(
            _finding(
                gap_id="semantic.oracle_manipulation",
                attacker_gain=True,
                authorization_impact=True,
                value_impact="high",
                summary="Oracle can be manipulated to steal swap value.",
                reasoning="Price feed compromise equals exploit.",
                trust_assumption="none",
            )
        ),
        ground_truth_kinds={FindingKind.DEPLOYMENT_REQUIREMENT, FindingKind.INVARIANT_GAP},
        ground_truth_notes="Oracle reliance should be trust_assumption=oracle, not blind VULNERABILITY unless auth bypass proven.",
        forbidden_kinds={FindingKind.VULNERABILITY},
    ),
    AdversarialScenario(
        scenario_id="TRUST-3",
        category="Trust Assumption",
        intent="Operator rotates keys off-chain; on-chain pubkey fixed at deploy.",
        behavior="Security depends on off-chain key ceremony.",
        code=OFFCHAIN_KEY_ROTATION,
        adversarial_judgment=_judgment(
            _finding(
                gap_id="semantic.key_rotation",
                attacker_gain=True,
                authorization_impact=True,
                value_impact="medium",
                summary="Off-chain operator can rotate keys and drain funds.",
                reasoning="Key rotation not enforced on-chain.",
                trust_assumption="none",
            )
        ),
        ground_truth_kinds={FindingKind.DEPLOYMENT_REQUIREMENT, FindingKind.OPERATIONAL_RISK},
        ground_truth_notes="Off-chain rotation is deployment/off-chain_state trust, not on-chain exploit.",
        forbidden_kinds={FindingKind.VULNERABILITY},
    ),
    # ── Category 4: Intent vs Security ────────────────────────────────────────
    AdversarialScenario(
        scenario_id="INTENT-1",
        category="Intent vs Security",
        intent=PAYROLL_INTENT_FIXED,
        behavior="Recipients fixed but salary amounts not enforced.",
        code=PAYROLL_RECIPIENTS_ONLY,
        effective_mode="split_payment",
        adversarial_judgment=_judgment(verdict="no_issue"),
        evaluation_mode="full_audit",
        ground_truth_kinds={FindingKind.INVARIANT_GAP},
        ground_truth_notes="Missing salary is business invariant gap.",
        must_include_deterministic="intent_fixed_amount_per_recipient",
    ),
    AdversarialScenario(
        scenario_id="INTENT-2",
        category="Intent vs Security",
        intent="Vault with timelock-delayed withdrawal.",
        behavior="No timelock check on withdraw path.",
        code=VAULT_NO_TIMELOCK,
        effective_mode="vault",
        intent_model=IntentModel(
            contract_type="timelock",
            features=["timelock"],
            signers=["owner"],
            threshold=1,
        ),
        adversarial_judgment=_judgment(verdict="no_issue"),
        evaluation_mode="full_audit",
        ground_truth_kinds={FindingKind.VULNERABILITY},
        ground_truth_notes="Missing timelock is security control.",
        must_include_deterministic="intent_sanity_check",
        forbidden_kinds={FindingKind.INVARIANT_GAP},
    ),
    AdversarialScenario(
        scenario_id="INTENT-3",
        category="Intent vs Security",
        intent="Payroll with fixed salaries and optional employee metadata records for UI.",
        behavior="Metadata not stored on-chain; business-only gap.",
        code=PAYROLL_FIXED_SALARY,
        effective_mode="split_payment",
        adversarial_judgment=_judgment(
            _finding(
                gap_id="semantic.metadata_missing",
                attacker_gain=True,
                authorization_impact=True,
                value_impact="high",
                summary="Missing metadata enables identity theft of payroll records.",
                reasoning="Critical security flaw in metadata handling.",
            )
        ),
        ground_truth_kinds={
            FindingKind.INVARIANT_GAP,
            FindingKind.OBSERVATION,
            FindingKind.DESIGN_TRADE_OFF,
        },
        ground_truth_notes="Metadata is business/policy; must not escalate to VULNERABILITY.",
        forbidden_kinds={FindingKind.VULNERABILITY},
    ),
    # ── Category 5: Contradiction ─────────────────────────────────────────────
    AdversarialScenario(
        scenario_id="CONTRA-1",
        category="Contradiction",
        intent=f"{PAYROLL_INTENT_FIXED} Signed payroll.",
        behavior="Bundle proves has_signature_auth; judge denies auth.",
        code=PAYROLL_FIXED_SALARY,
        effective_mode="split_payment",
        adversarial_judgment=_judgment(
            _finding(
                gap_id="semantic.auth_missing",
                attacker_gain=True,
                authorization_impact=True,
                value_impact="high",
                summary="Authorization missing on spend path.",
                reasoning="Missing authorization allows theft.",
            )
        ),
        ground_truth_kinds={FindingKind.OBSERVATION, FindingKind.INVARIANT_GAP, FindingKind.DEPLOYMENT_REQUIREMENT},
        ground_truth_notes="Must populate contradicts_fact_ids and cap confidence.",
        expect_contradiction=True,
        max_confidence=0.5,
        forbidden_kinds={FindingKind.VULNERABILITY},
        synthetic_bundle_overrides={
            "capabilities": {
                "evidence": [
                    {
                        "fact_id": "cap.has_signature_auth",
                        "key": "has_signature_auth",
                        "value": True,
                        "tier": "Authorization",
                        "source": "ast",
                        "anchors": [],
                    }
                ]
            }
        },
    ),
    AdversarialScenario(
        scenario_id="CONTRA-2",
        category="Contradiction",
        intent=f"{PAYROLL_INTENT_FIXED} Split with value conservation.",
        behavior="Bundle shows value conservation enforced; judge claims leak.",
        code=PAYROLL_FIXED_SALARY,
        effective_mode="split_payment",
        adversarial_judgment=_judgment(
            _finding(
                gap_id="semantic.value_leak",
                attacker_gain=True,
                authorization_impact=False,
                value_impact="high",
                summary="Value leak possible via payout path.",
                reasoning="Outputs may exceed input total.",
                fact_refs=["inv.value_conservation"],
            )
        ),
        ground_truth_kinds={FindingKind.OBSERVATION, FindingKind.INVARIANT_GAP},
        ground_truth_notes="Judge contradicts inv.value_conservation=ENFORCED.",
        expect_contradiction=False,
        forbidden_kinds={FindingKind.VULNERABILITY},
        synthetic_bundle_overrides={
            "invariant_matrix": {
                "entries": [
                    {
                        "invariant_id": "value_conservation",
                        "label": "value conservation",
                        "status": "ENFORCED",
                        "tier": "security",
                        "fact_id": "inv.value_conservation",
                    }
                ]
            }
        },
    ),
    AdversarialScenario(
        scenario_id="CONTRA-3",
        category="Contradiction",
        intent=f"{PAYROLL_INTENT_FIXED} Recipient binding enforced.",
        behavior="Judge claims recipient redirection despite ENFORCED binding.",
        code=PAYROLL_FIXED_SALARY,
        effective_mode="split_payment",
        adversarial_judgment=_judgment(
            _finding(
                gap_id="semantic.recipient_redirect",
                attacker_gain=True,
                authorization_impact=True,
                value_impact="medium",
                summary="Recipient redirection possible.",
                reasoning="Outputs not bound to intended employees.",
                fact_refs=["inv.recipient_binding"],
            )
        ),
        ground_truth_kinds={FindingKind.OBSERVATION, FindingKind.INVARIANT_GAP},
        ground_truth_notes="Should not classify as VULNERABILITY when binding enforced in bundle.",
        forbidden_kinds={FindingKind.VULNERABILITY},
        synthetic_bundle_overrides={
            "invariant_matrix": {
                "entries": [
                    {
                        "invariant_id": "recipient_binding",
                        "label": "recipient binding",
                        "status": "ENFORCED",
                        "tier": "business",
                        "fact_id": "inv.recipient_binding",
                    }
                ]
            }
        },
    ),
    # ── Category 6: Confidence ────────────────────────────────────────────────
    AdversarialScenario(
        scenario_id="CONF-1",
        category="Confidence",
        intent="Generic contract.",
        behavior="Judge admits evidence gaps.",
        code=PAYROLL_FIXED_SALARY,
        adversarial_judgment=_judgment(
            _finding(
                gap_id="semantic.speculative_gap",
                attacker_gain=False,
                value_impact="none",
                trust_assumption="external_funding",
                summary="Treasury funding model unclear.",
                reasoning="Off-chain funding not visible.",
                evidence_gaps=["treasury balance not visible on-chain"],
                uncertainty_reason="requires off-chain assumptions",
                confidence=0.95,
            )
        ),
        ground_truth_kinds={FindingKind.DEPLOYMENT_REQUIREMENT, FindingKind.OPERATIONAL_RISK},
        ground_truth_notes="evidence_gaps must cap confidence at 0.6.",
        expect_uncertainty_cap=True,
        max_confidence=0.6,
    ),
    AdversarialScenario(
        scenario_id="CONF-2",
        category="Confidence",
        intent="Signed payroll.",
        behavior="Judge explicitly contradicts bundle auth fact.",
        code=PAYROLL_FIXED_SALARY,
        adversarial_judgment=_judgment(
            _finding(
                gap_id="semantic.contra_auth",
                attacker_gain=True,
                authorization_impact=True,
                value_impact="high",
                summary="Missing authorization.",
                reasoning="No auth gate.",
                contradicts_fact_ids=["cap.has_signature_auth"],
                confidence=0.99,
            )
        ),
        ground_truth_kinds={FindingKind.INVARIANT_GAP, FindingKind.OBSERVATION},
        ground_truth_notes="contradicts_fact_ids must cap confidence at 0.5.",
        expect_contradiction=True,
        max_confidence=0.5,
        forbidden_kinds={FindingKind.VULNERABILITY},
    ),
    AdversarialScenario(
        scenario_id="CONF-3",
        category="Confidence",
        intent="Generic.",
        behavior="Speculative reasoning, no fact refs, high confidence.",
        code=PAYROLL_FIXED_SALARY,
        adversarial_judgment=_judgment(
            _finding(
                gap_id="semantic.speculation",
                attacker_gain=True,
                authorization_impact=True,
                value_impact="high",
                summary="Possible hidden reentrancy-style race.",
                reasoning="Speculative cross-function interaction.",
                fact_refs=[],
                evidence_gaps=["no concrete spend path cited"],
                confidence=0.92,
            )
        ),
        ground_truth_kinds={FindingKind.VULNERABILITY, FindingKind.INVARIANT_GAP, FindingKind.OBSERVATION},
        ground_truth_notes="High confidence speculative claim should be capped (uncertainty + contradiction rules).",
        expect_uncertainty_cap=True,
        max_confidence=0.6,
    ),
    # ── Category 7: BCH/CashToken ─────────────────────────────────────────────
    AdversarialScenario(
        scenario_id="BCH-1",
        category="BCH/CashToken",
        intent="Preserve token category on transfer.",
        behavior="tokenCategory not checked on output.",
        code=TOKEN_NO_CATEGORY,
        effective_mode="ft_transfer",
        adversarial_judgment=_judgment(
            _finding(
                gap_id="semantic.category_drift",
                attacker_gain=True,
                authorization_impact=False,
                value_impact="medium",
                summary="Token category not preserved on spend.",
                reasoning="Attacker may mint drifted category.",
                attacker_controlled_inputs=["tx.outputs[0].tokenCategory"],
            )
        ),
        ground_truth_kinds={FindingKind.VULNERABILITY, FindingKind.INVARIANT_GAP},
        ground_truth_notes="Category preservation missing is security-relevant.",
    ),
    AdversarialScenario(
        scenario_id="BCH-2",
        category="BCH/CashToken",
        intent="NFT commitment must be preserved.",
        behavior="nftCommitment not checked.",
        code=NFT_COMMITMENT_BROKEN,
        effective_mode="nft_immutable",
        adversarial_judgment=_judgment(
            _finding(
                gap_id="semantic.nft_commitment",
                attacker_gain=True,
                authorization_impact=False,
                value_impact="medium",
                summary="NFT commitment integrity broken.",
                reasoning="Commitment can be swapped on spend.",
                attacker_controlled_inputs=["tx.outputs[0].nftCommitment"],
            )
        ),
        ground_truth_kinds={FindingKind.VULNERABILITY, FindingKind.INVARIANT_GAP},
        ground_truth_notes="Commitment break is security issue.",
    ),
    AdversarialScenario(
        scenario_id="BCH-3",
        category="BCH/CashToken",
        intent="Owner may update mutable NFT metadata intentionally.",
        behavior="Signed metadata update by design.",
        code=MUTABLE_METADATA_ONLY,
        effective_mode="nft_mutable",
        adversarial_judgment=_judgment(
            _finding(
                gap_id="semantic.mutable_metadata",
                attacker_gain=True,
                authorization_impact=True,
                value_impact="high",
                summary="Unauthorized metadata mutation.",
                reasoning="Anyone can change NFT commitment.",
            )
        ),
        ground_truth_kinds={FindingKind.OBSERVATION, FindingKind.INVARIANT_GAP, FindingKind.DESIGN_TRADE_OFF},
        ground_truth_notes="Signed mutable metadata is intentional; not VULNERABILITY.",
        forbidden_kinds={FindingKind.VULNERABILITY},
    ),
    # ── Category 8: Mixed ─────────────────────────────────────────────────────
    AdversarialScenario(
        scenario_id="MIXED-1",
        category="Mixed Issues",
        intent="Payroll with treasury pre-funding and owner authorization.",
        behavior="No auth + no change output + treasury assumption.",
        code=MIXED_TREASURY_NO_AUTH,
        effective_mode="split_payment",
        adversarial_judgment=_judgment(
            _finding(
                gap_id="semantic.treasury_only",
                attacker_gain=False,
                value_impact="none",
                trust_assumption="external_funding",
                summary="Treasury must be pre-funded.",
                reasoning="Operational funding assumption only.",
            )
        ),
        evaluation_mode="full_audit",
        ground_truth_kinds={FindingKind.VULNERABILITY, FindingKind.DEPLOYMENT_REQUIREMENT},
        ground_truth_notes="Single semantic slot surfaces treasury; auth gap must appear deterministically.",
        must_include_deterministic="intent_auth_gate",
        forbidden_kinds=set(),
    ),
    AdversarialScenario(
        scenario_id="MIXED-2",
        category="Mixed Issues",
        intent="2-of-3 multisig payroll with fixed salary per employee; liquidity provider funds UTXO.",
        behavior="Single sig + missing salary + deploy assumption.",
        code=MIXED_SALARY_MULTISIG,
        effective_mode="multisig",
        intent_model=IntentModel(
            contract_type="multisig",
            features=["multisig", "split"],
            signers=["alice", "bob", "carol"],
            threshold=2,
        ),
        adversarial_judgment=_judgment(
            _finding(
                gap_id="semantic.deploy_liquidity",
                attacker_gain=False,
                value_impact="none",
                trust_assumption="external_funding",
                summary="External liquidity provider must fund contract.",
                reasoning="Deployment funding assumption.",
            )
        ),
        evaluation_mode="full_audit",
        ground_truth_kinds={FindingKind.VULNERABILITY, FindingKind.INVARIANT_GAP, FindingKind.DEPLOYMENT_REQUIREMENT},
        ground_truth_notes="Semantic picks deploy note; multisig bypass and salary gap must still appear deterministically.",
        must_include_deterministic="intent_sanity_check",
    ),
]

# V2.1 prompt-compliant judgments — what a judge following V2.1 instructions should emit.
_V21: Dict[str, Dict[str, Any]] = {
    "AG-1": _judgment_v21(
        _finding(
            gap_id="semantic.unconstrained_output_redirect",
            attacker_gain=True,
            authorization_impact=True,
            value_impact="low",
            summary="Attacker can redirect remainder via unconstrained output[1], including dust.",
            reasoning="Unauthorized redirect; profit not required for attacker_gain.",
            attacker_controlled_inputs=["tx.outputs[1].lockingBytecode"],
            fact_refs=["inv.recipient_binding"],
            reasoning_steps=_v21_steps(
                "inv.recipient_binding — output[0] bound, output[1] unconstrained",
                "tx.outputs[1].lockingBytecode on signed spend path",
                "low — any redirect including 1 satoshi",
                "true — unauthorized destination control regardless of amount",
                "none — on-chain output binding gap, not external funding",
                "no conflict with cap.has_signature_auth — owner signs but second output unbound",
            ),
        )
    ),
    "AG-2": _judgment_v21(
        _finding(
            gap_id="semantic.unauthorized_burn",
            attacker_gain=False,
            authorization_impact=True,
            value_impact="low",
            summary="Unauthorized party can burn tokens without auth gate.",
            reasoning="Destructive unauthorized action; attacker need not profit.",
            reasoning_steps=_v21_steps(
                "authorization gate — no checkSig on burn path",
                "any caller invoking burn()",
                "low — token destruction",
                "false direct gain but authorization_impact true for unauthorized destruction",
                "none — on-chain auth missing, not trust assumption",
                "no bundle contradiction",
            ),
        )
    ),
    "AUTH-2": _judgment_v21(
        verdict="no_issue",
        notes="Bundle cap.has_signature_auth=true; missing-auth claim retracted per contradiction protocol.",
    ),
    "TRUST-1": _judgment_v21(
        _finding(
            gap_id="semantic.treasury_funding",
            attacker_gain=False,
            authorization_impact=False,
            value_impact="none",
            trust_assumption="external_funding",
            summary="Treasury must be externally pre-funded before payout.",
            reasoning="Operational deploy assumption, not on-chain auth bypass.",
            reasoning_steps=_v21_steps(
                "treasury liquidity / external funding",
                "none — no unauthorized spend path",
                "none when properly funded",
                "false — depends on external funding honesty",
                "external_funding — treasury pre-funding required",
                "no contradiction with bundle auth facts",
            ),
        )
    ),
    "TRUST-2": _judgment_v21(
        _finding(
            gap_id="semantic.oracle_reliance",
            attacker_gain=False,
            authorization_impact=False,
            value_impact="none",
            trust_assumption="oracle",
            summary="Swap correctness depends on honest oracle price on input[1].",
            reasoning="Oracle trust assumption, not unsigned script bypass.",
            reasoning_steps=_v21_steps(
                "oracle input[1] price feed",
                "none without oracle compromise",
                "none under honest oracle",
                "false — oracle honesty assumption, not on-chain bypass",
                "oracle — price feed must be honest",
                "cap.has_signature_auth present on owner path",
            ),
        )
    ),
    "TRUST-3": _judgment_v21(
        _finding(
            gap_id="semantic.offchain_key_rotation",
            attacker_gain=False,
            authorization_impact=False,
            value_impact="none",
            trust_assumption="off_chain_state",
            summary="Key rotation depends on off-chain operator ceremony.",
            reasoning="Off-chain state trust, not on-chain exploit.",
            reasoning_steps=_v21_steps(
                "operator pubkey fixed at deploy",
                "none on-chain without operator signature",
                "none",
                "false — off-chain rotation not an on-chain bypass",
                "off_chain_state — operator ceremony off-chain",
                "no contradiction",
            ),
        )
    ),
    "INTENT-3": _judgment_v21(
        verdict="no_issue",
        fidelity=3,
        notes="Missing metadata is business intent fidelity only, not a security exploit.",
    ),
    "CONTRA-1": _judgment_v21(
        verdict="no_issue",
        notes="cap.has_signature_auth=true — missing-auth claim contradicts bundle; retracted.",
    ),
    "CONTRA-2": _judgment_v21(
        verdict="no_issue",
        notes="inv.value_conservation=ENFORCED — value leak claim contradicts bundle; retracted.",
    ),
    "CONTRA-3": _judgment_v21(
        verdict="no_issue",
        notes="inv.recipient_binding=ENFORCED — recipient redirect claim contradicts bundle; retracted.",
    ),
    "CONF-2": _judgment_v21(
        verdict="no_issue",
        notes="contradicts cap.has_signature_auth — exploit booleans retracted per V2.1 protocol.",
    ),
    "BCH-3": _judgment_v21(
        verdict="no_issue",
        notes="Owner-signed nftCommitment update is intentional mutable metadata, not unauthorized mutation.",
    ),
}

for _scenario in ADVERSARIAL_SCENARIOS:
    _scenario.v2_1_compliant_judgment = _V21.get(
        _scenario.scenario_id, _scenario.adversarial_judgment
    )
