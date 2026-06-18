"""Replay corpus runner — verifies V2.1 fixes without LLM calls."""

from __future__ import annotations

import asyncio
import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from tests.adversarial_semantic_judge.runner import evaluate_semantic_path
from tests.adversarial_semantic_judge.scenarios import ADVERSARIAL_SCENARIOS
from tests.audit_classification_matrix.runner import run_scenario
from tests.audit_classification_matrix.scenarios import SCENARIOS as CLASSIFICATION_SCENARIOS

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_REPLAY_INDEX = ROOT / "audit_replay_corpus" / "index.json"

_SCENARIO_BY_ID = {s.scenario_id: s for s in ADVERSARIAL_SCENARIOS}
_CLASS_BY_ID = {s.scenario_id: s for s in CLASSIFICATION_SCENARIOS}

# High-confidence replays with V2.1 fixture judgments (CI critical set)
CRITICAL_REPLAY_IDS = [
    "replay_payroll_treasury_001",
    "replay_auth_hallucination_001",
    "replay_contra_auth_001",
    "replay_contra_recipient_001",
    "replay_trust_oracle_001",
    "replay_trust_key_rotation_001",
    "replay_trust_lp_001",
    "replay_ag_dust_001",
    "replay_intent_metadata_001",
    "replay_conf_low_001",
    "replay_bch_oracle_secure_001",
]


@dataclass
class ReplayResult:
    replay_id: str
    status: str  # pass | fail | skip
    focus: str
    expected: Dict[str, Any]
    actual: Dict[str, Any]
    mismatches: List[str] = field(default_factory=list)
    skip_reason: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def run_replay(entry: Dict[str, Any]) -> ReplayResult:
    rid = entry.get("id", "unknown")
    focus = entry.get("replay_trigger", "")
    adversarial_id = entry.get("adversarial_id")
    expected = entry.get("actual_audit_v2_1") or entry.get("expected_audit") or {}

    if adversarial_id and adversarial_id in _SCENARIO_BY_ID:
        scenario = _SCENARIO_BY_ID[adversarial_id]
        v21 = getattr(scenario, "v2_1_compliant_judgment", scenario.adversarial_judgment)
        result = evaluate_semantic_path(scenario, judgment_payload=v21)
        actual = {
            "final_kind": (
                result.final_kind.value
                if hasattr(result.final_kind, "value")
                else result.final_kind
            ),
            "final_severity": result.final_severity,
            "contradicts_fact_ids": result.contradicts_fact_ids,
            "deterministic_findings": result.deterministic_findings,
            "passed": result.passed,
        }
        return ReplayResult(
            replay_id=rid,
            status="pass" if result.passed else "fail",
            focus=focus,
            expected=expected,
            actual=actual,
            mismatches=list(result.failures),
        )

    contract_ref = entry.get("contract_ref", "")
    if contract_ref.startswith("classification:"):
        sid = contract_ref.split(":", 1)[1]
        if sid in _CLASS_BY_ID:
            sc = _CLASS_BY_ID[sid]
            scenario_result = asyncio.run(run_scenario(sc, v2=True))
            actual = {
                "passed": scenario_result.passed,
                "primary_rule_id": scenario_result.primary_rule_id,
                "kind": scenario_result.kind,
            }
            return ReplayResult(
                replay_id=rid,
                status="pass" if scenario_result.passed else "fail",
                focus=focus,
                expected=expected,
                actual=actual,
                mismatches=list(scenario_result.mismatches),
            )

    return ReplayResult(
        replay_id=rid,
        status="skip",
        focus=focus,
        expected=expected,
        actual={},
        skip_reason="No adversarial_id or classification ref",
    )


def run_replay_index(
    index_path: Path = DEFAULT_REPLAY_INDEX,
    *,
    focus: Optional[str] = None,
    ids: Optional[List[str]] = None,
    adversarial_only: bool = False,
    critical_only: bool = False,
) -> List[ReplayResult]:
    data = json.loads(index_path.read_text(encoding="utf-8"))
    replays = data.get("replays", [])
    if focus:
        replays = [r for r in replays if r.get("replay_trigger") == focus]
    if adversarial_only:
        replays = [r for r in replays if r.get("adversarial_id")]
    if critical_only:
        crit = set(CRITICAL_REPLAY_IDS)
        replays = [r for r in replays if r.get("id") in crit]
    if ids:
        id_set = set(ids)
        replays = [r for r in replays if r.get("id") in id_set]
    return [run_replay(r) for r in replays]
