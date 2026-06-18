"""Run adversarial Semantic Judge V2 scenarios and collect results."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
import os
from unittest.mock import AsyncMock, MagicMock, patch

from src.models import (
    AuditFactBundle,
    AuditIssue,
    FindingKind,
    SemanticJudgment,
    SemanticVerdict,
)
from src.services.audit_engine.invariant_engine import InvariantEngine
from src.services.audit_engine.audit_phase import validate_audit
from src.services.audit_fact_bundle import build_audit_fact_bundle, bundle_to_prompt_json
from src.services.audit_engine.audit_lint import get_audit_linter as get_dsl_linter
from src.services.audit_agent import AuditAgent
from src.services.compiler import get_compiler_service
from src.services.finding_policy import finalize_from_judgment
from src.services.intent_invariants import build_invariant_matrix, verify_intent_invariants
from src.services.semantic_capabilities import extract_semantic_capabilities
from src.services.semantic_judge import apply_judgment_guards, parse_judgment_response
from src.utils.cashscript_ast import CashScriptAST

from tests.adversarial_semantic_judge.scenarios import ADVERSARIAL_SCENARIOS, AdversarialScenario


def _compile_ok(_code):
    return {"success": True}


@dataclass
class AdversarialResult:
    scenario_id: str
    category: str
    intent: str
    behavior: str
    bundle_json: str
    judgment_json: str
    final_kind: Optional[str]
    final_severity: Optional[str]
    final_triggerability: Optional[str]
    final_confidence: Optional[str]
    confidence_score: Optional[float]
    contradicts_fact_ids: List[str]
    evidence_gaps: List[str]
    uncertainty_reason: str
    passed: bool
    failures: List[str] = field(default_factory=list)
    deterministic_findings: List[str] = field(default_factory=list)
    semantic_rule_id: Optional[str] = None
    ground_truth: str = ""


def _apply_bundle_overrides(bundle: AuditFactBundle, overrides: Optional[Dict[str, Any]]) -> AuditFactBundle:
    if not overrides:
        return bundle
    data = bundle.model_dump()
    for key, val in overrides.items():
        if isinstance(val, dict) and isinstance(data.get(key), dict):
            data[key] = {**data[key], **val}
        else:
            data[key] = val
    return AuditFactBundle(**data)


def build_bundle_for_scenario(scenario: AdversarialScenario) -> tuple[List[AuditIssue], AuditFactBundle]:
    code = scenario.code
    issues: List[AuditIssue] = []
    compiler = get_compiler_service()
    compile_result = compiler.compile(code)
    compile_success = compile_result.get("success", False)

    if compile_success and (scenario.intent or scenario.intent_model):
        issues.extend(verify_intent_invariants(code, scenario.intent, scenario.intent_model))

    linter = get_dsl_linter()
    lint_result = linter.lint(code, contract_mode=scenario.effective_mode)
    for violation in lint_result.get("violations", []):
        issues.append(
            AuditIssue(
                title=violation.get("message", "lint"),
                severity="HIGH",
                line=violation.get("line_hint", 0),
                description=violation.get("message", ""),
                recommendation="",
                rule_id=violation.get("rule_id", "lint"),
            )
        )

    if compile_success:
        toll = validate_audit(code, scenario.effective_mode)
        for v in toll.violations:
            issues.append(
                AuditIssue(
                    title=v.rule,
                    severity=v.severity.upper() if hasattr(v, "severity") else "HIGH",
                    line=v.location.get("line", 0) if v.location else 0,
                    description=v.reason or v.exploit or "",
                    recommendation="",
                    rule_id=v.rule,
                )
            )

    invariant_matrix = build_invariant_matrix(code, scenario.intent, scenario.intent_model)
    sem_caps = extract_semantic_capabilities(code, contract_mode=scenario.effective_mode)
    engine_invariants: Dict[str, Any] = {}
    if compile_success:
        try:
            engine_invariants = InvariantEngine(CashScriptAST(code)).analyze()
        except Exception:
            engine_invariants = {}

    bundle = build_audit_fact_bundle(
        code=code,
        intent=scenario.intent,
        intent_model=scenario.intent_model,
        invariant_matrix=invariant_matrix,
        sem_caps=sem_caps,
        engine_invariants=engine_invariants,
        existing_issues=issues,
        effective_mode=scenario.effective_mode,
    )
    bundle = _apply_bundle_overrides(bundle, scenario.synthetic_bundle_overrides)
    return issues, bundle


def evaluate_semantic_path(
    scenario: AdversarialScenario,
    *,
    judgment_payload: Optional[Dict[str, Any]] = None,
) -> AdversarialResult:
    issues, bundle = build_bundle_for_scenario(scenario)
    payload = judgment_payload if judgment_payload is not None else scenario.adversarial_judgment
    raw_judgment = json.dumps(payload)
    judgment = parse_judgment_response(raw_judgment)
    guarded = apply_judgment_guards(judgment, bundle)

    final_kind: Optional[FindingKind] = None
    final_severity = None
    final_triggerability = None
    final_confidence = None
    confidence_score: Optional[float] = None
    semantic_rule_id = None

    if guarded.verdict == SemanticVerdict.FINDING and guarded.finding:
        finalized = finalize_from_judgment(guarded)
        if finalized:
            final_kind = finalized.kind
            final_severity = finalized.severity.value
            final_triggerability = finalized.triggerability.value
            final_confidence = finalized.confidence.value
            confidence_score = guarded.finding.confidence
            semantic_rule_id = f"semantic_{final_kind.value}"

    failures: List[str] = []
    finding = guarded.finding
    contradicts = list(finding.contradicts_fact_ids) if finding else []
    evidence_gaps = list(finding.evidence_gaps) if finding else []
    uncertainty = finding.uncertainty_reason if finding else ""

    if scenario.must_include_deterministic:
        det_ids = [i.rule_id for i in issues]
        if scenario.must_include_deterministic not in det_ids:
            failures.append(
                f"Missing deterministic finding {scenario.must_include_deterministic}; got {det_ids}"
            )

    if final_kind is None and payload.get("verdict") == "finding":
        if not scenario.must_include_deterministic:
            failures.append("Adversarial finding rejected or produced no final kind")

    if final_kind is not None:
        if scenario.ground_truth_kinds and final_kind not in scenario.ground_truth_kinds:
            failures.append(
                f"Kind {final_kind.value} not in ground truth {sorted(k.value for k in scenario.ground_truth_kinds)}"
            )
        if final_kind in scenario.forbidden_kinds:
            failures.append(f"Forbidden kind {final_kind.value}")

    if scenario.expect_contradiction and not contradicts and payload.get("verdict") == "finding":
        failures.append("Expected contradicts_fact_ids but none present after guards")

    if scenario.max_confidence is not None and confidence_score is not None:
        if confidence_score > scenario.max_confidence + 1e-9:
            failures.append(
                f"Confidence {confidence_score} exceeds cap {scenario.max_confidence}"
            )

    if scenario.expect_uncertainty_cap and confidence_score is not None:
        if confidence_score > 0.6 + 1e-9:
            failures.append(f"Uncertainty cap failed: confidence={confidence_score}")

    return AdversarialResult(
        scenario_id=scenario.scenario_id,
        category=scenario.category,
        intent=scenario.intent,
        behavior=scenario.behavior,
        bundle_json=bundle_to_prompt_json(bundle),
        judgment_json=raw_judgment,
        final_kind=final_kind.value if final_kind else None,
        final_severity=final_severity,
        final_triggerability=final_triggerability,
        final_confidence=final_confidence,
        confidence_score=confidence_score,
        contradicts_fact_ids=contradicts,
        evidence_gaps=evidence_gaps,
        uncertainty_reason=uncertainty,
        passed=len(failures) == 0,
        failures=failures,
        deterministic_findings=[i.rule_id for i in issues],
        semantic_rule_id=semantic_rule_id,
        ground_truth=scenario.ground_truth_notes,
    )


async def evaluate_full_audit(
    scenario: AdversarialScenario,
    *,
    judgment_payload: Optional[Dict[str, Any]] = None,
) -> AdversarialResult:
    payload = judgment_payload if judgment_payload is not None else scenario.adversarial_judgment
    base = evaluate_semantic_path(scenario, judgment_payload=payload)
    provider = MagicMock()
    provider.complete = AsyncMock(return_value=json.dumps(payload))

    with patch("src.services.llm.factory.LLMFactory.get_provider", return_value=provider), \
         patch("src.services.audit_agent.get_compiler_service", return_value=MagicMock(compile=_compile_ok)), \
         patch.dict(os.environ, {"SEMANTIC_JUDGE_V2": "1"}, clear=False):
        report = await AuditAgent.audit(
            code=scenario.code,
            intent=scenario.intent,
            effective_mode=scenario.effective_mode,
            intent_model=scenario.intent_model,
        )

    failures = list(base.failures)
    det_ids = [i.rule_id for i in report.issues if i.provenance.value == "deterministic" or not i.rule_id.startswith("semantic_")]

    if scenario.must_include_deterministic:
        all_rules = [i.rule_id for i in report.issues]
        if scenario.must_include_deterministic not in all_rules:
            failures.append(
                f"Full audit missing {scenario.must_include_deterministic}; issues={[i.rule_id for i in report.issues]}"
            )

    sem_issues = [i for i in report.issues if i.rule_id.startswith("semantic_")]
    final_kind = sem_issues[0].kind.value if sem_issues else base.final_kind
    final_severity = sem_issues[0].severity.value if sem_issues else base.final_severity
    final_trig = sem_issues[0].triggerability.value if sem_issues else base.final_triggerability
    final_conf = sem_issues[0].confidence.value if sem_issues else base.final_confidence

    if sem_issues:
        kind = sem_issues[0].kind
        if scenario.forbidden_kinds and kind in scenario.forbidden_kinds:
            failures.append(f"Full audit semantic kind forbidden: {kind.value}")
        if scenario.ground_truth_kinds and kind not in scenario.ground_truth_kinds:
            if not scenario.must_include_deterministic:
                failures.append(f"Full audit semantic kind {kind.value} not in ground truth")

    return AdversarialResult(
        scenario_id=base.scenario_id,
        category=base.category,
        intent=base.intent,
        behavior=base.behavior,
        bundle_json=base.bundle_json,
        judgment_json=base.judgment_json,
        final_kind=final_kind,
        final_severity=final_severity,
        final_triggerability=final_trig,
        final_confidence=final_conf,
        confidence_score=sem_issues[0].confidence_score if sem_issues else base.confidence_score,
        contradicts_fact_ids=base.contradicts_fact_ids,
        evidence_gaps=base.evidence_gaps,
        uncertainty_reason=base.uncertainty_reason,
        passed=len(failures) == 0,
        failures=failures,
        deterministic_findings=[i.rule_id for i in report.issues if not i.rule_id.startswith("semantic_")],
        semantic_rule_id=sem_issues[0].rule_id if sem_issues else None,
        ground_truth=base.ground_truth,
    )


async def run_adversarial_scenario(
    scenario: AdversarialScenario,
    *,
    judgment_payload: Optional[Dict[str, Any]] = None,
) -> AdversarialResult:
    payload = judgment_payload
    if scenario.evaluation_mode == "full_audit":
        return await evaluate_full_audit(scenario, judgment_payload=payload)
    return evaluate_semantic_path(scenario, judgment_payload=payload)


async def run_all_adversarial(
    *,
    use_v2_1_compliant: bool = False,
) -> List[AdversarialResult]:
    results: List[AdversarialResult] = []
    for scenario in ADVERSARIAL_SCENARIOS:
        payload = None
        if use_v2_1_compliant:
            payload = scenario.v2_1_compliant_judgment or scenario.adversarial_judgment
        results.append(await run_adversarial_scenario(scenario, judgment_payload=payload))
    return results


@dataclass
class ComparisonRow:
    scenario_id: str
    category: str
    v2_passed: bool
    v2_kind: Optional[str]
    v21_passed: bool
    v21_kind: Optional[str]
    v2_failures: List[str]
    v21_failures: List[str]


async def run_v2_v21_comparison() -> tuple[List[AdversarialResult], List[AdversarialResult], List[ComparisonRow]]:
    v2_results = await run_all_adversarial(use_v2_1_compliant=False)
    v21_results = await run_all_adversarial(use_v2_1_compliant=True)
    rows: List[ComparisonRow] = []
    for v2, v21 in zip(v2_results, v21_results):
        rows.append(
            ComparisonRow(
                scenario_id=v2.scenario_id,
                category=v2.category,
                v2_passed=v2.passed,
                v2_kind=v2.final_kind,
                v21_passed=v21.passed,
                v21_kind=v21.final_kind,
                v2_failures=v2.failures,
                v21_failures=v21.failures,
            )
        )
    return v2_results, v21_results, rows
