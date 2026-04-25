from src.services.audit_engine.audit_lint import get_audit_linter


def _ids(result):
    return [violation["rule_id"] for violation in result["violations"]]


def test_no_token_rules_in_vault():
    code = """
    contract C(bytes32 token) {
        function spend() {
            require(tx.outputs[0].tokenCategory == token);
        }
    }
    """
    result = get_audit_linter().lint(code, contract_mode="vault")
    ids = _ids(result)
    assert "LNC-014" not in ids
    assert "LNC-017" not in ids
    assert "LNC-018" not in ids
    assert not any("token_amount" in issue_id or "tokenAmount" in issue_id for issue_id in ids)


def test_lnc_003_skipped_in_vault():
    code = """
    contract C() {
        function spend() {
            require(tx.outputs.length == 1);
            require(tx.outputs[0].lockingBytecode == tx.inputs[this.activeInputIndex].lockingBytecode);
        }
    }
    """
    result = get_audit_linter().lint(code, contract_mode="vault")
    assert "LNC-003" not in _ids(result)


def test_lnc_004_only_manager():
    code = """
    contract C() {}
    require(tx.outputs[0].value == 1);
    """
    vault_result = get_audit_linter().lint(code, contract_mode="vault")
    manager_result = get_audit_linter().lint(code, contract_mode="manager")
    assert "LNC-004" not in _ids(vault_result)
    assert "LNC-004" in _ids(manager_result)


def test_lnc_001c_filtered():
    code = """
    contract C() {
        function spend() {
            require(tx.outputs[5].value == 1000);
        }
    }
    """
    result = get_audit_linter().lint(code, contract_mode="manager")
    assert "LNC-001c" not in _ids(result)
