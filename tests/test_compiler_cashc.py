"""Tests for cashc path resolution and toolchain error handling."""

from pathlib import Path

from src.models import AuditIssue, Severity, IssueClass, ExploitSeverity
from src.services.compiler import (
    _parse_cashc_error,
    get_cashc_path,
    _find_project_root,
    _iter_cashc_commands,
    _toolchain_only_failure,
)
from src.services.scoring import (
    calculate_audit_report,
    TOOLCHAIN_NEUTRAL_DET_SCORE,
)


def test_parse_cashc_error_toolchain_source_tags():
    err = _parse_cashc_error("Error: sourceTags is not iterable\n")
    assert err["type"] == "ToolchainError"
    assert "sourceTags" in err["hint"] or "cashc" in err["hint"].lower()


def test_find_project_root_contains_package_json():
    root = _find_project_root()
    assert (root / "package.json").is_file()


def test_get_cashc_path_prefers_local_node_modules():
    """Local .bin first; else Windows global npm cashc.cmd; else PATH name `cashc`."""
    p = get_cashc_path()
    root = _find_project_root()
    local_bin = root / "node_modules" / ".bin"
    has_local = (local_bin / "cashc").is_file() or (local_bin / "cashc.cmd").is_file()
    norm = p.replace("\\", "/")
    if has_local:
        assert "node_modules/.bin" in norm
    elif "npm" in norm and "cashc" in norm.lower():
        assert True  # global npm fallback (dev machine)
    else:
        assert p == "cashc"


def test_iter_cashc_commands_includes_path_fallback():
    """After primary, a PATH cashc (or npm global) is available for retry."""
    p = get_cashc_path()
    seq = _iter_cashc_commands(p)
    assert len(seq) >= 1
    if (Path(p) != Path("cashc") and p != "cashc") or p.endswith("node_modules"):
        assert any(c == "cashc" or (isinstance(c, str) and "npm" in c) for c, _ in seq[1:]), (
            "expected a fallback after project-local primary"
        )


def test_toolchain_only_failure_detects_source_tags():
    assert _toolchain_only_failure("x sourceTags is not iterable y")
    assert not _toolchain_only_failure("Extraneous input 'while' at line 3")


def test_scoring_toolchain_error_uses_neutral_det_not_zero():
    issue = AuditIssue(
        title="Toolchain",
        severity=Severity.HIGH,
        line=0,
        description="crash",
        recommendation="npm ci",
        rule_id="compile_toolchain_error",
        can_fix=False,
        source="deterministic",
        issue_class=IssueClass.CONTEXTUAL,
        exploit_severity=ExploitSeverity.GRIEFING,
    )
    report = calculate_audit_report(
        issues=[issue],
        compile_success=False,
        dsl_passed=True,
        structural_score=1.0,
        semantic_category="none",
        business_logic_score=5,
        semantic_confidence=None,
        original_code="pragma cashscript ^0.13.0; contract T(){}",
        compile_toolchain_error=True,
    )
    assert report.deterministic_score == TOOLCHAIN_NEUTRAL_DET_SCORE
    # 40 + 20 (none) + 5 = 65 before floor; display is max(20, 65)
    assert report.total_score >= 60
