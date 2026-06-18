"""Run deterministic audit layers and compare to benchmark expectations."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional

from src.models import AuditIssue, FindingKind
from src.services.audit_engine.audit_phase import validate_audit
from src.services.audit_engine.audit_lint import get_audit_linter as get_dsl_linter
from src.services.compiler import get_compiler_service
from src.services.finding_policy import finalize_from_judgment
from src.services.intent_invariants import build_invariant_matrix, verify_intent_invariants
from src.services.semantic_judge import apply_judgment_guards, parse_judgment_response
from src.models import SemanticVerdict

from benchmark.audit_eval.contract_resolver import resolve_contract_ref
from benchmark.audit_eval.modes import EvaluationMode


@dataclass
class BenchmarkResult:
    benchmark_id: str
    status: str  # pass | fail | skip | dry_run
    mode: str
    expected: Dict[str, Any]
    actual: Dict[str, Any]
    mismatches: List[str] = field(default_factory=list)
    skip_reason: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def _issue_snapshot(issues: List[AuditIssue]) -> List[Dict[str, Any]]:
    return [
        {
            "rule_id": i.rule_id,
            "kind": i.kind.value if i.kind else None,
            "severity": i.severity.value if hasattr(i.severity, "value") else str(i.severity),
            "title": i.title,
        }
        for i in issues
    ]


def _invariant_snapshot(code: str, intent: str) -> Dict[str, str]:
    matrix = build_invariant_matrix(code, intent, None)
    out: Dict[str, str] = {}
    for entry in matrix.all_entries():
        out[entry.invariant_id] = entry.status
    return out


def _run_deterministic(
    code: str,
    intent: str,
    effective_mode: str,
    *,
    include_invariants: bool,
) -> tuple[List[AuditIssue], bool]:
    issues: List[AuditIssue] = []
    compiler = get_compiler_service()
    compile_result = compiler.compile(code)
    compile_success = bool(compile_result.get("success"))

    linter = get_dsl_linter()
    for violation in linter.lint(code, contract_mode=effective_mode).get("violations", []):
        issues.append(
            AuditIssue(
                title=violation.get("message", "lint"),
                severity=violation.get("severity", "HIGH").upper(),
                line=violation.get("line_hint", 0),
                description=violation.get("message", ""),
                recommendation="",
                rule_id=violation.get("rule_id", "lint"),
            )
        )

    if compile_success:
        toll = validate_audit(code, effective_mode)
        for v in toll.violations:
            issues.append(
                AuditIssue(
                    title=v.rule,
                    severity=(v.severity or "HIGH").upper(),
                    line=v.location.get("line", 0) if v.location else 0,
                    description=v.reason or v.exploit or "",
                    recommendation=v.fix_hint or "",
                    rule_id=v.rule,
                )
            )

        if include_invariants and intent:
            issues.extend(verify_intent_invariants(code, intent, None))

    return issues, compile_success


def _apply_policy_judgment(
    issues: List[AuditIssue],
    code: str,
    intent: str,
    effective_mode: str,
    judgment_payload: Dict[str, Any],
) -> List[AuditIssue]:
    """Policy-only path using fixture judgment — no LLM."""
    from src.services.audit_fact_bundle import build_audit_fact_bundle
    from src.services.audit_engine.invariant_engine import InvariantEngine
    from src.services.semantic_capabilities import extract_semantic_capabilities
    from src.utils.cashscript_ast import CashScriptAST

    matrix = build_invariant_matrix(code, intent, None)
    sem_caps = extract_semantic_capabilities(code, contract_mode=effective_mode)
    engine_inv: dict = {}
    try:
        engine_inv = InvariantEngine(CashScriptAST(code)).analyze()
    except Exception:
        pass
    bundle = build_audit_fact_bundle(
        code=code,
        intent=intent,
        intent_model=None,
        invariant_matrix=matrix,
        sem_caps=sem_caps,
        engine_invariants=engine_inv,
        existing_issues=issues,
        effective_mode=effective_mode,
    )
    judgment = parse_judgment_response(json.dumps(judgment_payload))
    guarded = apply_judgment_guards(judgment, bundle)
    out = list(issues)
    if guarded.verdict == SemanticVerdict.FINDING and guarded.finding:
        finalized = finalize_from_judgment(guarded)
        if finalized:
            out.append(
                AuditIssue(
                    title=finalized.title,
                    severity=finalized.severity.value,
                    line=0,
                    description=guarded.finding.reasoning or guarded.finding.summary,
                    recommendation=guarded.finding.recommendation or "",
                    rule_id=f"semantic_{finalized.kind.value}",
                    kind=finalized.kind,
                )
            )
    return out


def _compare(
    expected_findings: List[str],
    expected_severity: List[str],
    expected_invariants: List[str],
    expected_kind: List[str],
    issues: List[AuditIssue],
    invariants: Dict[str, str],
) -> List[str]:
    mismatches: List[str] = []
    actual_rule_ids = [i.rule_id for i in issues if i.rule_id]

    for exp in expected_findings:
        if not any(exp in rid or rid in exp for rid in actual_rule_ids):
            mismatches.append(f"Missing expected finding rule_id containing {exp!r}; got {actual_rule_ids}")

    for inv_spec in expected_invariants:
        if ":" not in inv_spec:
            continue
        inv_id, want_status = inv_spec.split(":", 1)
        got = invariants.get(inv_id, "ABSENT")
        if got != want_status:
            mismatches.append(f"Invariant {inv_id}: expected {want_status}, got {got}")

    if expected_kind:
        actual_kinds = [i.kind.value for i in issues if i.kind]
        for ek in expected_kind:
            if ek not in actual_kinds:
                # empty expected_kind with no findings is ok
                if ek or actual_kinds:
                    mismatches.append(f"Missing expected kind {ek!r}; got {actual_kinds}")

    return mismatches


def run_benchmark(
    entry: Dict[str, Any],
    *,
    mode: EvaluationMode,
    dry_run: bool = False,
) -> BenchmarkResult:
    bid = entry.get("id", "unknown")
    intent = entry.get("intent", "")
    contract_ref = entry.get("contract_ref", "")
    eval_mode = entry.get("evaluation_mode", "detector_only")
    expected = {
        "findings": entry.get("expected_findings", []),
        "severity": entry.get("expected_severity", []),
        "invariants": entry.get("expected_invariants", []),
        "kind": entry.get("expected_kind", []),
    }

    if dry_run:
        resolved = resolve_contract_ref(contract_ref)
        return BenchmarkResult(
            benchmark_id=bid,
            status="dry_run",
            mode=mode.value,
            expected=expected,
            actual={"resolvable": resolved is not None, "contract_ref": contract_ref},
            skip_reason=None if resolved else "contract not materialized",
        )

    resolved = resolve_contract_ref(contract_ref)
    if resolved is None:
        return BenchmarkResult(
            benchmark_id=bid,
            status="skip",
            mode=mode.value,
            expected=expected,
            actual={},
            skip_reason=f"Cannot resolve contract_ref: {contract_ref}",
        )

    include_inv = mode.uses_invariants and eval_mode in (
        "detector_only",
        "policy_only",
        "full_audit",
    )
    issues, compile_ok = _run_deterministic(
        resolved.code,
        intent,
        resolved.effective_mode,
        include_invariants=include_inv,
    )

    if mode.uses_policy and eval_mode == "policy_only" and entry.get("policy_judgment"):
        issues = _apply_policy_judgment(
            issues,
            resolved.code,
            intent,
            resolved.effective_mode,
            entry["policy_judgment"],
        )

    invariants = _invariant_snapshot(resolved.code, intent) if include_inv else {}
    actual = {
        "compile_success": compile_ok,
        "findings": _issue_snapshot(issues),
        "invariants": invariants,
    }

    if mode == EvaluationMode.FAST:
        # FAST ignores invariant expectations
        mismatches = _compare(
            expected["findings"],
            expected["severity"],
            [],
            [],
            issues,
            {},
        )
    else:
        mismatches = _compare(
            expected["findings"],
            expected["severity"],
            expected["invariants"],
            expected["kind"],
            issues,
            invariants,
        )

    status = "pass" if not mismatches else "fail"
    if entry.get("coverage_probe") and mismatches:
        status = "gap"

    return BenchmarkResult(
        benchmark_id=bid,
        status=status,
        mode=mode.value,
        expected=expected,
        actual=actual,
        mismatches=mismatches,
    )


def run_registry(
    registry: Dict[str, Any],
    *,
    mode: EvaluationMode,
    dry_run: bool = False,
    family: Optional[str] = None,
    ids: Optional[List[str]] = None,
    limit: Optional[int] = None,
) -> List[BenchmarkResult]:
    benchmarks = registry.get("benchmarks", [])
    if family:
        benchmarks = [b for b in benchmarks if b.get("family") == family]
    if ids:
        id_set = set(ids)
        benchmarks = [b for b in benchmarks if b.get("id") in id_set]

    results: List[BenchmarkResult] = []
    for entry in benchmarks:
        if limit is not None and len(results) >= limit:
            break
        results.append(run_benchmark(entry, mode=mode, dry_run=dry_run))
    return results
