"""Wave 2C — audit registry includes CashTokens generation-parity detectors."""

from pathlib import Path

from src.services.audit_engine.audit_enforcer import audit_detector_registry
from src.services.audit_engine.audit_enforcer import AuditEnforcer
from src.services.anti_pattern_detectors import generation_detector_registry

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "cashtokens_invalid"


def test_audit_registry_includes_cashtokens_parity_ids():
    audit_ids = {d.id for d in audit_detector_registry()}
    assert "missing_token_amount_validation" in audit_ids
    assert "minting_authority_escape" in audit_ids
    assert "unbounded_mint" in audit_ids
    assert "authority_leak" in audit_ids


def test_audit_fires_on_authority_leak_fixture():
    code = (FIXTURES / "authority_leak" / "vulnerable.cash").read_text(encoding="utf-8")
    enforcer = AuditEnforcer()
    result = enforcer.validate_code(code, contract_mode="nft_minting")
    rules = result.get("violated_rules", [])
    assert any("authority_leak" in r or "minting_authority_escape" in r for r in rules)


def test_audit_clean_on_authority_leak_secure():
    code = (FIXTURES / "authority_leak" / "secure.cash").read_text(encoding="utf-8")
    enforcer = AuditEnforcer()
    result = enforcer.validate_code(code, contract_mode="nft_minting")
    critical = [
        v for v in result.get("violations", [])
        if v.get("severity") == "critical" and "authority" in v.get("rule", "")
    ]
    assert not critical


def test_generation_audit_id_overlap():
    gen_ids = {d.id for d in generation_detector_registry()}
    audit_ids = {d.id for d in audit_detector_registry()}
    overlap = gen_ids & audit_ids
    assert "unbounded_mint" in overlap
    assert "authority_leak" in overlap
