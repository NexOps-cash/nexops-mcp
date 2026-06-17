"""Tests for deterministic intent invariant verification."""

from src.models import (
    ConfidenceLevel,
    FindingKind,
    IntentModel,
    Provenance,
    Severity,
    Triggerability,
)
from src.services.intent_invariants import (
    build_invariant_matrix,
    verify_intent_invariants,
)

PAYROLL_CODE_RECIPIENTS_ONLY = """
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

PAYROLL_CODE_WITH_FIXED_SALARIES = """
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

PAYROLL_INTENT = (
    "Payroll contract with fixed recipients and fixed salary amounts for each employee. "
    "Owner must sign. Preserve token category."
)


def test_matrix_shows_enforced_and_missing_for_payroll():
    matrix = build_invariant_matrix(PAYROLL_CODE_RECIPIENTS_ONLY, PAYROLL_INTENT)
    enforced_labels = {x.label for x in matrix.enforced}
    missing_labels = {x.label for x in matrix.missing}

    assert "recipient binding" in enforced_labels
    assert "value conservation" in enforced_labels
    assert "fixed amount per recipient" in missing_labels


def test_verify_emits_invariant_gap_for_missing_fixed_salary():
    issues = verify_intent_invariants(PAYROLL_CODE_RECIPIENTS_ONLY, PAYROLL_INTENT)
    salary_issue = next(
        (i for i in issues if i.rule_id == "intent_fixed_amount_per_recipient"),
        None,
    )
    assert salary_issue is not None
    assert salary_issue.kind == FindingKind.INVARIANT_GAP
    assert salary_issue.severity == Severity.MEDIUM
    assert salary_issue.confidence == ConfidenceLevel.PROVEN
    assert salary_issue.provenance == Provenance.DETERMINISTIC
    assert salary_issue.triggerability == Triggerability.ATTACKER
    assert "Policy Gap" in salary_issue.title


def test_fixed_salary_enforced_no_gap_finding():
    issues = verify_intent_invariants(PAYROLL_CODE_WITH_FIXED_SALARIES, PAYROLL_INTENT)
    assert not any(i.rule_id == "intent_fixed_amount_per_recipient" for i in issues)


def test_matrix_prompt_format():
    matrix = build_invariant_matrix(PAYROLL_CODE_RECIPIENTS_ONLY, PAYROLL_INTENT)
    text = matrix.format_for_prompt()
    assert "ENFORCED:" in text
    assert "MISSING:" in text
    assert "recipient binding" in text
    assert "fixed amount per recipient" in text


def test_intent_model_split_payment_triggers_checks():
    model = IntentModel(
        contract_type="split_payment",
        features=["split", "tokens"],
        purpose="Employee payroll distribution",
    )
    intent = "Distribute payroll with fixed salary amounts to employees."
    matrix = build_invariant_matrix(PAYROLL_CODE_RECIPIENTS_ONLY, intent, model)
    assert any(x.invariant_id == "fixed_amount_per_recipient" for x in matrix.missing)


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


def test_missing_auth_gate_is_vulnerability_high():
    issues = verify_intent_invariants(
        PAYROLL_NO_AUTH,
        "Payroll distribution to employees. Owner must sign.",
    )
    auth = next((i for i in issues if i.rule_id == "intent_auth_gate"), None)
    assert auth is not None
    assert auth.kind == FindingKind.VULNERABILITY
    assert auth.severity == Severity.HIGH
    assert auth.triggerability == Triggerability.ATTACKER
    assert "Security Vulnerability" in auth.title
