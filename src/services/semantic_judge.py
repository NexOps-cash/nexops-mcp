"""
Semantic Security Judge V2 — facts-first LLM judgment with structured output.
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any, Dict, List, Optional

from src.models import (
    AuditFactBundle,
    SemanticJudgment,
    SemanticVerdict,
    SpendPathRef,
    StructuredSemanticFinding,
    TrustAssumption,
    ValueImpact,
)

logger = logging.getLogger("nexops.semantic_judge")

JUDGE_VERSION = "2.1"

SEMANTIC_JUDGE_SYSTEM_PROMPT = """\
You are a BCH CashScript Security Judge.
Assess delta-only semantic risk using UTXO-aware reasoning.

You are NOT a classifier. Do NOT emit severity, title, finding kind, or category labels.

UTXO / BCH guardrails (must respect):
- Every input to a valid transaction is consumed when the spend succeeds; the spending path authorizes that input.
- If a required authorization or policy token appears on an input, that input is a controlled, signed spend of that UTXO — it is not automatically an "attacker-injected bypass" merely because a token appears on a different input in the same transaction.
- Distinguish (a) concrete on-chain value-loss or authorization-bypass from (b) design tradeoffs, operational failures, or off-chain/deploy assumptions.

The AUDIT_FACT_BUNDLE is authoritative. Do NOT re-report findings listed in existing_findings or MISSING invariants in invariant_matrix.

ATTACKER GAIN AND AUTHORIZATION IMPACT (read before setting booleans):

attacker_gain=true when ANY of the following hold on an attacker-reachable spend path:
- Attacker can redirect ANY BCH or fungible tokens to an attacker-chosen output (amount does NOT matter — 1 satoshi redirect is still attacker_gain=true).
- Attacker can destroy, burn, or permanently deny access to others' funds/tokens without authorization (even if attacker keeps nothing).
- Attacker can bypass a required signature, multisig threshold, or timelock.

authorization_impact=true when an unauthorized party can spend, redirect, destroy, lock, or bypass a required authorization gate — regardless of whether they profit.

Do NOT set attacker_gain=false solely because:
- the redirected amount is small or "dust";
- the attacker gains nothing personally (griefing/destruction still counts);
- value_conservation holds globally but one output destination is unconstrained.

When authorization is bypassed or an output destination is attacker-controlled, set authorization_impact=true and value_impact at least low (not none).

TRUST ASSUMPTION CHECK (mandatory before attacker_gain=true):

Ask: "Does this risk require off-chain honesty, external funding, deploy-time configuration, issuer policy, or an oracle — rather than an on-chain auth bypass?"

If YES, set trust_assumption accordingly and attacker_gain=false:
- Treasury/pre-funding/liquidity/underfund → external_funding
- Oracle/price-feed/input data honesty → oracle
- Off-chain operator/key ceremony/rotation not enforced on-chain → off_chain_state
- Issuer-defined policy off-chain → issuer_policy
- Constructor/deploy parameter assumptions → deployment_config

Only set attacker_gain=true for trust scenarios when you can cite a concrete on-chain path where an unauthorized caller bypasses script authorization (check cap.has_signature_auth and inv.auth_gate in the bundle first).

CONTRADICTION PROTOCOL (bundle facts are authoritative):

Before verdict=finding, cross-check your claim against the bundle:

A) Authorization claims:
   - If cap.has_signature_auth=true or inv.auth_gate=ENFORCED, you MUST NOT claim "missing authorization" unless you cite a specific UNSIGNED spend path (function name + line). Otherwise populate contradicts_fact_ids with the conflicting fact_id(s) and set attacker_gain=false, authorization_impact=false.

B) Value conservation claims:
   - If inv.value_conservation=ENFORCED, you MUST NOT claim "value leak" unless you identify a specific output/value rule absent in code. If the bundle says ENFORCED, populate contradicts_fact_ids=["inv.value_conservation"] and set attacker_gain=false.

C) Recipient binding claims:
   - If inv.recipient_binding=ENFORCED, you MUST NOT claim "recipient redirection" unless you identify an unconstrained output index in code. If the bundle says ENFORCED but your claim conflicts, populate contradicts_fact_ids and set attacker_gain=false.

When contradicts_fact_ids is non-empty:
- You MUST set attacker_gain=false and authorization_impact=false.
- Set value_impact=none unless a separate, non-contradicted exploit path exists.
- Prefer verdict=no_issue unless a non-contradicted intent/business gap remains.
- Set confidence ≤ 0.5 and explain the conflict in uncertainty_reason.

INTENT TIER VS SECURITY:

Distinguish business/intent fidelity gaps from security exploits:
- Missing metadata, UI labels, optional off-chain records, naming fields → intent fidelity only; attacker_gain=false, authorization_impact=false, value_impact=none. Do not frame as fund theft.
- Missing salary amounts, timelocks, multisig thresholds, auth gates, token category/commitment checks → may be security-relevant; cite the specific missing on-chain check.

INTENTIONAL MUTABILITY (BCH/CashTokens):
- If cap.has_signature_auth=true AND declared intent allows owner/admin to update metadata, nftCommitment, or token fields → authorized mutability, NOT an exploit. Set attacker_gain=false, authorization_impact=false.
- Only flag mutability when an UNSIGNED path allows commitment/category/amount change.
- Distinguish: missing category preservation (unsigned) vs owner-signed metadata update.

Before verdict=finding you MUST fill reasoning_steps with exactly these 6 answers in order:
1. What invariant was examined (cite inv.* or cap.* fact_id)?
2. What does the attacker control (if any)? If none, stop — attacker_gain=false.
3. What value impact exists (including dust redirects and destructive actions)?
4. Why does or does not attacker gain (profit NOT required for gain=true)?
5. Trust-assumption check: is this off-chain/deploy/oracle reliance? If yes, set trust_assumption and attacker_gain=false.
6. Contradiction check: does any bundle fact with status ENFORCED or cap.*=true conflict with this finding? If yes, populate contradicts_fact_ids and retract exploit booleans.

Classification inputs (only these drive downstream policy):
- attacker_gain (boolean)
- authorization_impact (boolean)
- value_impact: none | low | medium | high
- trust_assumption: none | external_funding | issuer_policy | oracle | off_chain_state | deployment_config

exploit_class if provided is optional narrative context only — not for severity.

When analysis depends on off-chain or deploy assumptions, set evidence_gaps and/or uncertainty_reason.

Hard rules:
- attacker_gain=false → value_impact is typically none or low UNLESS authorization_impact=true (then value_impact should be at least low).
- attacker_gain=true → attacker_controlled_inputs must be non-empty.
- trust_assumption≠none → attacker_gain MUST be false unless a separate unsigned bypass path exists (cite it explicitly).
- Every fact_refs entry MUST be reconciled: if a referenced fact contradicts your claim, move it to contradicts_fact_ids and retract exploit booleans.

Return strict JSON only:
{
  "judge_version": "2.1",
  "verdict": "finding | no_issue",
  "intent_fidelity_score": 0,
  "intent_fidelity_notes": "short rationale",
  "finding": {
    "gap_id": "semantic.example",
    "attacker_gain": false,
    "authorization_impact": false,
    "value_impact": "none | low | medium | high",
    "exploit_class": null,
    "trust_assumption": "none",
    "affected_invariant": "",
    "deferred_validation": false,
    "attacker_controlled_inputs": [],
    "spend_path": { "function": "", "line_hint": 0 },
    "fact_refs": [],
    "contradicts_fact_ids": [],
    "evidence_gaps": [],
    "uncertainty_reason": "",
    "reasoning_steps": ["...", "...", "...", "...", "...", "..."],
    "summary": "user-facing one sentence",
    "reasoning": "short rationale",
    "recommendation": "actionable fix",
    "confidence": 0.0
  }
}

When verdict=no_issue, omit finding or set finding to null."""


def semantic_judge_v2_enabled() -> bool:
    return os.environ.get("SEMANTIC_JUDGE_V2", "1").strip().lower() not in (
        "0",
        "false",
        "no",
        "off",
    )


def build_judge_user_prompt(
    code: str,
    intent: str,
    bundle: AuditFactBundle,
) -> str:
    from src.services.audit_fact_bundle import bundle_to_prompt_json

    parts: List[str] = []
    if intent:
        parts.append(f"DECLARED INTENT:\n{intent}\n")
    parts.append(f"AUDIT_FACT_BUNDLE (authoritative):\n{bundle_to_prompt_json(bundle)}\n")
    parts.append(f"CONTRACT TO AUDIT:\n{code}\n")
    parts.append("Assess delta-only semantic risk. Output strict JSON only.")
    return "\n".join(parts)


def _parse_value_impact(raw: Any) -> ValueImpact:
    try:
        return ValueImpact(str(raw or "none").strip().lower())
    except ValueError:
        return ValueImpact.NONE


def _parse_trust_assumption(raw: Any) -> TrustAssumption:
    try:
        return TrustAssumption(str(raw or "none").strip().lower())
    except ValueError:
        return TrustAssumption.NONE


def _parse_finding(data: Dict[str, Any]) -> StructuredSemanticFinding:
    spend = data.get("spend_path") or {}
    if not isinstance(spend, dict):
        spend = {}
    return StructuredSemanticFinding(
        gap_id=str(data.get("gap_id") or ""),
        attacker_gain=bool(data.get("attacker_gain", False)),
        authorization_impact=bool(data.get("authorization_impact", False)),
        value_impact=_parse_value_impact(data.get("value_impact")),
        exploit_class=data.get("exploit_class"),
        trust_assumption=_parse_trust_assumption(data.get("trust_assumption")),
        affected_invariant=str(data.get("affected_invariant") or ""),
        deferred_validation=bool(data.get("deferred_validation", False)),
        attacker_controlled_inputs=list(data.get("attacker_controlled_inputs") or []),
        spend_path=SpendPathRef(
            function=str(spend.get("function") or ""),
            line_hint=int(spend.get("line_hint") or 0),
        ),
        fact_refs=list(data.get("fact_refs") or []),
        contradicts_fact_ids=list(data.get("contradicts_fact_ids") or []),
        evidence_gaps=list(data.get("evidence_gaps") or []),
        uncertainty_reason=str(data.get("uncertainty_reason") or ""),
        reasoning_steps=list(data.get("reasoning_steps") or []),
        summary=str(data.get("summary") or ""),
        reasoning=str(data.get("reasoning") or ""),
        recommendation=str(data.get("recommendation") or ""),
        confidence=float(data.get("confidence") or 0.0),
    )


def parse_judgment_response(raw: str) -> SemanticJudgment:
    decoder = json.JSONDecoder()
    start = raw.find("{")
    if start == -1:
        raise ValueError("No JSON object found in semantic judge response.")
    data, _ = decoder.raw_decode(raw, start)

    if "verdict" not in data and "category" in data:
        return parse_legacy_semantic_response(data)

    verdict_raw = str(data.get("verdict", "no_issue")).strip().lower()
    if verdict_raw == "finding":
        verdict = SemanticVerdict.FINDING
    else:
        verdict = SemanticVerdict.NO_ISSUE

    finding_data = data.get("finding")
    finding: Optional[StructuredSemanticFinding] = None
    if finding_data and isinstance(finding_data, dict):
        finding = _parse_finding(finding_data)

    fidelity = data.get("intent_fidelity_score", data.get("business_logic_score", 5))
    notes = data.get("intent_fidelity_notes", data.get("business_logic_notes", ""))

    return SemanticJudgment(
        judge_version=str(data.get("judge_version") or JUDGE_VERSION),
        verdict=verdict,
        intent_fidelity_score=int(fidelity) if fidelity is not None else 5,
        intent_fidelity_notes=str(notes or ""),
        finding=finding,
    )


def _missing_invariant_ids(bundle: AuditFactBundle) -> set[str]:
    ids: set[str] = set()
    for entry in bundle.invariant_matrix.get("entries") or []:
        if isinstance(entry, dict) and entry.get("status") == "MISSING":
            inv_id = entry.get("invariant_id") or ""
            if inv_id:
                ids.add(str(inv_id).lower())
    return ids


def _existing_rule_ids(bundle: AuditFactBundle) -> set[str]:
    return {f.rule_id for f in bundle.existing_findings}


def _capability_true_keys(bundle: AuditFactBundle) -> Dict[str, bool]:
    out: Dict[str, bool] = {}
    for ev in bundle.capabilities.get("evidence") or []:
        if isinstance(ev, dict) and ev.get("value") is True:
            fid = ev.get("fact_id") or f"cap.{ev.get('key', '')}"
            out[str(fid)] = True
    return out


def apply_judgment_guards(
    judgment: SemanticJudgment,
    bundle: AuditFactBundle,
) -> SemanticJudgment:
    if judgment.verdict != SemanticVerdict.FINDING or not judgment.finding:
        return judgment

    finding = judgment.finding.model_copy(deep=True)

    if len(finding.reasoning_steps) < 4:
        logger.info(
            "[Semantic Judge] Rejected finding: reasoning_steps=%d (<4)",
            len(finding.reasoning_steps),
        )
        return SemanticJudgment(
            judge_version=judgment.judge_version,
            verdict=SemanticVerdict.NO_ISSUE,
            intent_fidelity_score=judgment.intent_fidelity_score,
            intent_fidelity_notes=judgment.intent_fidelity_notes,
            finding=None,
        )

    if finding.attacker_gain and not finding.attacker_controlled_inputs:
        logger.info("[Semantic Judge] Downgraded attacker_gain: empty attacker_controlled_inputs")
        finding.attacker_gain = False
        finding.confidence = min(finding.confidence, 0.5)

    gap = finding.gap_id or ""
    if gap in _existing_rule_ids(bundle):
        logger.info("[Semantic Judge] Deduped gap_id matching existing rule_id: %s", gap)
        return SemanticJudgment(
            judge_version=judgment.judge_version,
            verdict=SemanticVerdict.NO_ISSUE,
            intent_fidelity_score=judgment.intent_fidelity_score,
            intent_fidelity_notes=judgment.intent_fidelity_notes,
            finding=None,
        )

    affected = (finding.affected_invariant or "").lower()
    if affected and affected in _missing_invariant_ids(bundle):
        logger.info("[Semantic Judge] Deduped affected_invariant already MISSING: %s", affected)
        return SemanticJudgment(
            judge_version=judgment.judge_version,
            verdict=SemanticVerdict.NO_ISSUE,
            intent_fidelity_score=judgment.intent_fidelity_score,
            intent_fidelity_notes=judgment.intent_fidelity_notes,
            finding=None,
        )

    caps = _capability_true_keys(bundle)
    summary_lower = (finding.summary + " " + finding.reasoning).lower()
    if caps.get("cap.has_signature_auth") and any(
        p in summary_lower for p in ("missing auth", "missing authorization", "without signature")
    ):
        if "cap.has_signature_auth" not in finding.contradicts_fact_ids:
            finding.contradicts_fact_ids = list(finding.contradicts_fact_ids) + [
                "cap.has_signature_auth"
            ]
            logger.warning("[Semantic Judge] Auto-added contradicts_fact_ids: cap.has_signature_auth")

    if finding.contradicts_fact_ids:
        finding.confidence = min(finding.confidence, 0.5)
    if finding.evidence_gaps or finding.uncertainty_reason.strip():
        finding.confidence = min(finding.confidence, 0.6)

    return SemanticJudgment(
        judge_version=judgment.judge_version,
        verdict=SemanticVerdict.FINDING,
        intent_fidelity_score=judgment.intent_fidelity_score,
        intent_fidelity_notes=judgment.intent_fidelity_notes,
        finding=finding,
    )


def parse_legacy_semantic_response(data: Dict[str, Any]) -> SemanticJudgment:
    """Map legacy category/exploit_severity payload to SemanticJudgment."""
    category = str(data.get("category", "SAFE")).strip().lower()
    exploit_sev = str(data.get("exploit_severity", "n/a")).strip().lower()
    explanation = str(data.get("explanation") or "")
    biz_score = data.get("business_logic_score", 5)
    biz_notes = str(data.get("business_logic_notes") or "")
    try:
        confidence = max(0.0, min(1.0, float(data.get("confidence", 0.0))))
    except (TypeError, ValueError):
        confidence = 0.0

    if category in ("safe", "none"):
        return SemanticJudgment(
            verdict=SemanticVerdict.NO_ISSUE,
            intent_fidelity_score=int(biz_score) if biz_score is not None else 5,
            intent_fidelity_notes=biz_notes,
        )

    attacker_gain = category == "exploit"
    authorization_impact = category == "exploit" and exploit_sev in (
        "direct_fund_loss",
        "partial_violation",
    )
    if category == "funds_unspendable":
        attacker_gain = False
        authorization_impact = False

    text_lower = explanation.lower()
    _treasury_markers = (
        "treasury",
        "underfund",
        "pre-fund",
        "prefund",
        "insufficient fund",
        "liquidity",
    )
    if category == "exploit" and any(m in text_lower for m in _treasury_markers):
        attacker_gain = False
        authorization_impact = False

    value_impact = ValueImpact.NONE
    if category == "exploit" and attacker_gain:
        if exploit_sev == "direct_fund_loss":
            value_impact = ValueImpact.HIGH
        elif exploit_sev == "partial_violation":
            value_impact = ValueImpact.MEDIUM
        elif exploit_sev == "griefing":
            value_impact = ValueImpact.LOW
        else:
            value_impact = ValueImpact.MEDIUM

    trust = TrustAssumption.NONE
    deferred = False
    if category == "assumption":
        attacker_gain = False
        trust = TrustAssumption.EXTERNAL_FUNDING
        deferred = True
    elif category == "design_tradeoff":
        attacker_gain = False
        value_impact = ValueImpact.LOW
    elif attacker_gain is False and any(m in text_lower for m in _treasury_markers):
        trust = TrustAssumption.EXTERNAL_FUNDING

    gap_id = f"semantic.legacy_{category}"
    if category == "funds_unspendable":
        gap_id = "semantic.funds_unspendable"

    attacker_inputs: List[str] = []
    if attacker_gain:
        attacker_inputs = ["tx.inputs", "tx.outputs"]

    finding = StructuredSemanticFinding(
        gap_id=gap_id,
        attacker_gain=attacker_gain,
        authorization_impact=authorization_impact,
        value_impact=value_impact,
        trust_assumption=trust,
        affected_invariant="funds_unspendable" if category == "funds_unspendable" else "",
        deferred_validation=deferred,
        attacker_controlled_inputs=attacker_inputs,
        summary=explanation[:80] if explanation else category,
        reasoning=explanation,
        recommendation=biz_notes or "Review contract logic.",
        confidence=confidence,
        reasoning_steps=[
            "Legacy adapter: invariant inferred from category.",
            "Legacy adapter: attacker control inferred from category.",
            f"Legacy adapter: value_impact={value_impact.value}.",
            f"Legacy adapter: attacker_gain={attacker_gain}.",
        ],
    )

    return SemanticJudgment(
        verdict=SemanticVerdict.FINDING,
        intent_fidelity_score=int(biz_score) if biz_score is not None else 5,
        intent_fidelity_notes=biz_notes,
        finding=finding,
    )


async def run_semantic_judge(
    *,
    code: str,
    intent: str,
    bundle: AuditFactBundle,
    audit_provider,
) -> SemanticJudgment:
    user_prompt = build_judge_user_prompt(code, intent, bundle)
    raw_response = await audit_provider.complete(user_prompt, system=SEMANTIC_JUDGE_SYSTEM_PROMPT)
    judgment = parse_judgment_response(raw_response)
    return apply_judgment_guards(judgment, bundle)
