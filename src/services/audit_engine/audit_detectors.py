"""
Audit-only deterministic detectors.

This module intentionally does not import or mutate the generator detector
registry. Keep this list small and audit-scoped.
"""

from dataclasses import dataclass
import re
from typing import Any, Dict, List, Optional

from src.utils.cashscript_ast import CashScriptAST, OutputReference


@dataclass
class Violation:
    """Represents an audit detector violation."""

    rule: str
    reason: str
    exploit: str
    location: Dict[str, Any]
    severity: str = "medium"
    issue_class: str = "contextual"
    exploit_severity: str = "n/a"
    deferred_validation: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule": self.rule,
            "reason": self.reason,
            "exploit": self.exploit,
            "location": self.location,
            "severity": self.severity,
            "issue_class": self.issue_class,
            "exploit_severity": self.exploit_severity,
            "deferred_validation": self.deferred_validation,
        }


class AuditDetector:
    """Base class for audit-only detectors."""

    id: str = "base"

    def detect(self, ast: CashScriptAST) -> Optional[Violation]:
        raise NotImplementedError


class IndexUnderflowDetector(AuditDetector):
    """Detect activeInputIndex subtraction without lower-bound guard."""

    id = "index_underflow"

    def detect(self, ast: CashScriptAST) -> Optional[Violation]:
        risky_functions: List[str] = []
        for fn_name, body in ast._get_function_bodies().items():
            for match in re.finditer(r"this\.activeInputIndex\s*-\s*(\d+|\w+)", body):
                operand = match.group(1)
                guard = re.search(
                    rf"require\s*\(\s*this\.activeInputIndex\s*(>=|>)\s*{re.escape(operand)}\s*\)",
                    body,
                )
                if not guard:
                    risky_functions.append(fn_name)
                    break
        if not risky_functions:
            return None
        fn_name = risky_functions[0]
        return Violation(
            rule=self.id,
            reason=f"Function '{fn_name}' subtracts from this.activeInputIndex without a strict lower-bound guard",
            exploit=(
                "A crafted transaction placing this contract at index 0 can trigger script failure on index "
                "underflow. This is a denial-of-service/bricking risk for that spend path."
            ),
            location={"line": 0, "function": fn_name},
            severity="medium",
            issue_class="real_issue",
            exploit_severity="griefing",
        )


class InputOutputCouplingDetector(AuditDetector):
    """Detect forwarding functions that read inputs without coupled outputs."""

    id = "input_output_coupling"

    def detect(self, ast: CashScriptAST) -> Optional[Violation]:
        violations = [
            fn_name
            for fn_name in ast.has_input_without_output_coupling()
            if ast.classify_io_pattern(fn_name) != "aggregation"
        ]
        if not violations:
            return None
        fn_name = violations[0]
        return Violation(
            rule=self.id,
            reason=f"Forwarding function '{fn_name}' reads tx.inputs[i] without coupled tx.outputs[i] constraints",
            exploit=(
                "In positional forwarding logic, attacker-controlled output layout can violate intended "
                "per-index invariants when input and output coupling is not enforced."
            ),
            location={"line": 0, "function": fn_name},
            severity="high",
            issue_class="real_issue",
            exploit_severity="partial_violation",
        )


class PartialAggregationDetector(AuditDetector):
    """Detect aggregation loops that do not prove full input coverage."""

    id = "partial_aggregation_risk"

    def detect(self, ast: CashScriptAST) -> Optional[Violation]:
        if ast.contract_mode == "parser":
            return None
        risky_functions = [
            fn_name
            for fn_name in ast.has_partial_aggregation_risk()
            if ast.classify_io_pattern(fn_name) != "aggregation"
        ]
        if not risky_functions:
            return None
        fn_name = risky_functions[0]
        return Violation(
            rule=self.id,
            reason=f"Aggregation in '{fn_name}' has no boundary proof that all inputs are processed",
            exploit=(
                "Subset processing can make behavior input-order dependent. A malicious transaction builder "
                "may insert inputs to bypass expected full-coverage aggregation invariants."
            ),
            location={"line": 0, "function": fn_name},
            severity="medium",
            issue_class="contextual",
            exploit_severity="partial_violation",
        )


class CommitmentLengthSafetyDetector(AuditDetector):
    """Detect bytes parsing without minimum length checks."""

    id = "commitment_length_missing"

    def detect(self, ast: CashScriptAST) -> Optional[Violation]:
        if not ast.contains_bytes_parsing():
            return None
        risky_functions = ast.has_bytes_parse_without_length_check()
        if not risky_functions:
            return None
        fn_name = risky_functions[0]
        return Violation(
            rule=self.id,
            reason=f"Function '{fn_name}' parses bytes via split/slice without explicit length guard",
            exploit="Short commitment payloads can decode into unexpected empty/truncated values and violate downstream invariants.",
            location={"line": 0, "function": fn_name},
            severity="high",
            issue_class="real_issue",
            exploit_severity="direct_fund_loss",
        )


class OutputBindingDetector(AuditDetector):
    """Detect output value/token checks with missing lockingBytecode binding."""

    id = "output_binding_missing"

    def detect(self, ast: CashScriptAST) -> Optional[Violation]:
        if ast.contract_mode not in {"manager", "stateful", "covenant", "vault"}:
            return None
        refs: List[OutputReference] = []
        for ref in ast.get_unbound_output_refs():
            if ref.property_accessed == "tokenCategory" and ast.is_empty_token_output_policy(ref):
                continue
            refs.append(ref)
        if not refs:
            return None
        ref = refs[0]
        allowed_props = {"value", "tokenAmount"}
        if ast.contract_mode == "vault":
            allowed_props.add("tokenCategory")
        if ref.property_accessed not in allowed_props:
            return None
        if ref.property_accessed in ("value", "tokenAmount"):
            exploit = (
                "Value/token amount checks without lockingBytecode binding can be satisfied by outputs sent "
                "to attacker-chosen scripts if the contract never fixes the output's locking script."
            )
        else:
            exploit = (
                "Token category checks without lockingBytecode binding are policy-only: they do not show "
                "where funds or tokens are sent. Pair category checks with output locking script validation "
                "when the intended security property is destination control."
            )
        return Violation(
            rule=self.id,
            reason=f"Output {ref.index} in '{ref.location.function}' validates {ref.property_accessed} without lockingBytecode binding",
            exploit=exploit,
            location={
                "line": ref.location.line,
                "function": ref.location.function,
                "output_index": ref.index,
                "property": ref.property_accessed,
            },
            severity="medium",
            issue_class="contextual",
            exploit_severity="partial_violation",
        )


class AuthorizationModelClassifierDetector(AuditDetector):
    """Classify tokenCategory-based authorization without escalating it."""

    id = "authorization_model_classifier"

    def detect(self, ast: CashScriptAST) -> Optional[Violation]:
        has_category_auth = bool(
            "tokenCategory" in ast.code
            and any("tokenCategory" in validation.condition for validation in ast.validations)
        )
        if not has_category_auth:
            return None
        return Violation(
            rule=self.id,
            reason="Category-based authorization detected",
            exploit="Informational classification: shared category auth model should be reviewed in context.",
            location={"line": 0, "function": "all"},
            severity="info",
            issue_class="noise",
            exploit_severity="n/a",
        )


AUDIT_DETECTOR_REGISTRY = [
    IndexUnderflowDetector(),
    CommitmentLengthSafetyDetector(),
    OutputBindingDetector(),
    AuthorizationModelClassifierDetector(),
    PartialAggregationDetector(),
    InputOutputCouplingDetector(),
]
