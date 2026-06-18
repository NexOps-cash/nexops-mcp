"""Tests for credit-free benchmark and replay runners."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from benchmark.audit_eval.modes import EvaluationMode
from benchmark.audit_eval.replay_runner import CRITICAL_REPLAY_IDS, run_replay_index
from benchmark.audit_eval.runner import run_registry

ROOT = Path(__file__).resolve().parents[1]
EXEC_REGISTRY = ROOT / "docs" / "benchmark_registry_executable.json"


@pytest.fixture
def executable_registry():
    return json.loads(EXEC_REGISTRY.read_text(encoding="utf-8"))


def test_benchmark_suite_standard_all_pass_or_gap(executable_registry):
    results = run_registry(
        executable_registry,
        mode=EvaluationMode.STANDARD,
        dry_run=False,
    )
    for r in results:
        assert r.status in ("pass", "gap"), f"{r.benchmark_id}: {r.mismatches}"


def test_benchmark_dry_run_resolves_executable(executable_registry):
    results = run_registry(executable_registry, mode=EvaluationMode.FAST, dry_run=True)
    resolved = sum(1 for r in results if r.actual.get("resolvable"))
    assert resolved == len(results)


def test_critical_replay_suite_passes():
    results = run_replay_index(critical_only=True)
    assert len(results) == len(CRITICAL_REPLAY_IDS)
    failures = [r for r in results if r.status != "pass"]
    assert not failures, [f"{r.replay_id}: {r.mismatches}" for r in failures]


def test_hashlock_coverage_probe_is_gap(executable_registry):
    results = run_registry(
        executable_registry,
        mode=EvaluationMode.STANDARD,
        ids=["bench_hashlock_002"],
    )
    assert len(results) == 1
    assert results[0].status == "gap"
