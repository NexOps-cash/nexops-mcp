"""
Audit-only deterministic detectors.

This module intentionally does not import or mutate the generator detector
registry. Keep this list small and audit-scoped.
"""

from dataclasses import dataclass
import re
from typing import Any, Dict, List, Optional

from src.utils.cashscript_ast import CashScriptAST, OutputReference
from src.services.audit_engine.invariant_engine import (
    should_skip_commitment_rule_for_body,
    should_skip_input_output_coupling,
    fixed_output_index_unsafe,
    report_fixed_output_brief,
)


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

    def detect(
        self,
        ast: CashScriptAST,
        invariants: Optional[Dict[str, Any]] = None,
    ) -> Optional[Violation]:
        raise NotImplementedError


# ── Module-level helpers ────────────────────────────────────────────────────


def _index_subtract_guarded(body: str, k: int) -> bool:
    """k is int operand of this.activeInputIndex - k (e.g. 1 for ' - 1')."""
    if k < 0:
        return False
    if re.search(
        rf"require\s*\(\s*this\.activeInputIndex\s*>=\s*{k}\s*\)", body
    ):
        return True
    if k > 0 and re.search(
        rf"require\s*\(\s*this\.activeInputIndex\s*>\s*{k - 1}\s*\)", body
    ):
        return True
    if k == 1 and re.search(
        r"require\s*\(\s*this\.activeInputIndex\s*>\s*0\s*\)", body
    ):
        return True
    return False


def _has_hash_precondition(code: str) -> bool:
    """True when the given code contains hash256(var) == var — bytes are upstream-pinned."""
    return bool(re.search(r'hash256\s*\(\s*\w+\s*\)\s*==\s*\w+', code))


def _has_full_equality_coupling(code: str) -> bool:
    """
    True when active-index coupling is expressed as three explicit equality requires
    covering lockingBytecode, tokenCategory, AND nftCommitment.
    When all three are present the detector would be a false positive.
    """
    has_locking = bool(re.search(
        r'tx\.inputs\[this\.activeInputIndex\]\.lockingBytecode\s*==\s*tx\.outputs\[this\.activeInputIndex',
        code,
    ))
    has_category = bool(re.search(
        r'tx\.inputs\[this\.activeInputIndex\]\.tokenCategory\s*==\s*tx\.outputs\[this\.activeInputIndex',
        code,
    ))
    has_commitment = bool(re.search(
        r'tx\.inputs\[this\.activeInputIndex\]\.nftCommitment\s*==\s*tx\.outputs\[this\.activeInputIndex',
        code,
    ))
    return has_locking and has_category and has_commitment


# ── Detectors ───────────────────────────────────────────────────────────────


class IndexUnderflowDetector(AuditDetector):
    """Detect activeInputIndex subtraction without lower-bound guard."""

    id = "index_underflow"

    def detect(
        self,
        ast: CashScriptAST,
        invariants: Optional[Dict[str, Any]] = None,
    ) -> Optional[Violation]:
        risky_functions: List[str] = []
        for fn_name, body in ast._get_function_bodies().items():
            if re.search(r"this\.activeInputIndex\s*==\s*0\b", body):
                continue
            found_risky = False
            for match in re.finditer(r"this\.activeInputIndex\s*-\s*(\d+|\w+)", body):
                operand = match.group(1)
                if operand.isdigit():
                    k = int(operand)
                    if not _index_subtract_guarded(body, k):
                        found_risky = True
                        break
                    continue
                guard = re.search(
                    rf"require\s*\(\s*this\.activeInputIndex\s*(>=|>)\s*{re.escape(operand)}\s*\)",
                    body,
                )
                if not guard:
                    found_risky = True
                    break
            if found_risky:
                risky_functions.append(fn_name)
        if not risky_functions:
            return None
        fn_name = risky_functions[0]
        return Violation(
            rule=self.id,
            reason=f"Function '{fn_name}' subtracts from this.activeInputIndex without a lower-bound guard (e.g. require(this.activeInputIndex > 0) for '- 1', or require(this.activeInputIndex >= k) for '- k')",
            exploit=(
                "A crafted transaction placing this contract at index 0 can trigger script failure on index "
                "underflow. This is a denial-of-service/bricking risk for that spend path."
            ),
            location={"line": 0, "function": fn_name},
            severity="medium",
            issue_class="real_issue",
            exploit_severity="griefing",
        )


class PositiveOffsetOOBDetector(AuditDetector):
    """
    Detect tx.(inputs|outputs)[this.activeInputIndex + N] accesses without a
    matching length guard on the SAME collection (inputs or outputs).
    """

    id = "positive_offset_oob"

    def detect(
        self,
        ast: CashScriptAST,
        invariants: Optional[Dict[str, Any]] = None,
    ) -> Optional[Violation]:
        for fn_name, body in ast._get_function_bodies().items():
            for m in re.finditer(
                r'tx\.(inputs|outputs)\[this\.activeInputIndex\s*\+\s*(\d+)\]', body
            ):
                collection = m.group(1)   # "inputs" or "outputs" — must match guard
                offset = int(m.group(2))
                # Must tie length to placement: global require(tx.x.length == K) is not enough.
                guard = re.search(
                    rf'tx\.{collection}\.length\s*(>|>=)\s*this\.activeInputIndex\s*\+\s*{offset}',
                    body,
                )
                if not guard:
                    inv_note = report_fixed_output_brief(fn_name, invariants) if invariants else ""
                    return Violation(
                        rule=self.id,
                        reason=(
                            f"Function '{fn_name}' accesses tx.{collection}[this.activeInputIndex+{offset}] "
                            "without a per-placement length guard of the form "
                            f"require(tx.{collection}.length > this.activeInputIndex + {offset}) "
                            f"(or >= with the same right-hand side).{inv_note} "
                            "A standalone require(tx.outputs.length == or >= K) does not cap placement, "
                            "so it is not sufficient for this access pattern by itself."
                        ),
                        exploit=(
                            "Placement-driven script abort if the transaction has fewer "
                            f"{collection} than activeInputIndex + {offset}. "
                            "This is a denial-of-service/griefing risk for that spend path."
                        ),
                        location={"line": 0, "function": fn_name},
                        severity="medium",
                        issue_class="contextual",
                        exploit_severity="griefing",
                    )
        return None


class FixedIndexOOBDetector(AuditDetector):
    """
    tx.outputs[N] for N>0 must be paired with a length guard in the same function
    proving tx.outputs.length > N (any require(... length ... K ...) with K > N).
    """

    id = "fixed_index_oob"

    def detect(
        self,
        ast: CashScriptAST,
        invariants: Optional[Dict[str, Any]] = None,
    ) -> Optional[Violation]:
        if not invariants:
            return None
        for fn_name in ast._get_function_bodies().keys():
            if fixed_output_index_unsafe(fn_name, invariants):
                rbrief = report_fixed_output_brief(fn_name, invariants)
                return Violation(
                    rule=self.id,
                    reason=(
                        f"Function '{fn_name}' uses fixed tx.outputs[N] with N>0 without a "
                        "length guard (==, >=, or >) that guarantees enough outputs for the largest index used."
                        f"{rbrief}"
                    ),
                    exploit=(
                        "If the spend path assumes an output at index N that may not exist, "
                        "the script can fail at runtime — a grief/DoS risk for that path."
                    ),
                    location={"line": 0, "function": fn_name},
                    severity="medium",
                    issue_class="contextual",
                    exploit_severity="griefing",
                )
        return None


class UnsupportedWhileDetector(AuditDetector):
    """
    Detect a top-level while(...) loop that CashScript v0.13.x does not support.
    Valid do-while syntax is: do { ... } while (...); — the while token is always
    preceded (after stripping whitespace) by a closing brace.
    """

    id = "cashscript_unsupported_top_level_while"

    def detect(
        self,
        ast: CashScriptAST,
        invariants: Optional[Dict[str, Any]] = None,
    ) -> Optional[Violation]:
        # Strip line and block comments before scanning so comment text cannot
        # accidentally look like a standalone while keyword.
        clean = re.sub(r'//.*$', '', ast.code, flags=re.MULTILINE)
        clean = re.sub(r'/\*.*?\*/', '', clean, flags=re.DOTALL)

        for m in re.finditer(r'\bwhile\s*\(', clean):
            prefix = clean[:m.start()]
            # A valid do-while has } (possibly followed by whitespace) immediately
            # before the while keyword.  Use re.search so multi-line gaps are handled.
            if not re.search(r'\}\s*$', prefix):
                lineno = prefix.count('\n') + 1
                return Violation(
                    rule=self.id,
                    reason="Top-level while() loop detected (not a valid do-while closing)",
                    exploit=(
                        "CashScript v0.13.x only supports do { } while () loops. "
                        "A standalone while() causes a compile-time ExtraneousInputError "
                        "and makes the contract non-deployable."
                    ),
                    location={"line": lineno, "function": "any"},
                    severity="critical",
                    issue_class="real_issue",
                    exploit_severity="direct_fund_loss",
                )
        return None


class InputOutputCouplingDetector(AuditDetector):
    """Detect forwarding functions that read inputs without coupled outputs."""

    id = "input_output_coupling"

    def detect(
        self,
        ast: CashScriptAST,
        invariants: Optional[Dict[str, Any]] = None,
    ) -> Optional[Violation]:
        # If the contract fully expresses active-index coupling via three explicit
        # equality requires (locking + category + commitment), the detector would
        # be a false positive on every minter/manager that self-returns correctly.
        if _has_full_equality_coupling(ast.code):
            return None
        if invariants and should_skip_input_output_coupling(invariants):
            return None

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

    def detect(
        self,
        ast: CashScriptAST,
        invariants: Optional[Dict[str, Any]] = None,
    ) -> Optional[Violation]:
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

    def detect(
        self,
        ast: CashScriptAST,
        invariants: Optional[Dict[str, Any]] = None,
    ) -> Optional[Violation]:
        if not ast.contains_bytes_parsing():
            return None
        risky_functions = ast.has_bytes_parse_without_length_check()
        if not risky_functions:
            return None
        fn_name = risky_functions[0]

        # Severity is function-scoped: if the risky function itself contains a
        # hash256(var) == var precondition the bytes are upstream-pinned and the
        # worst-case impact is self-grief (griefing), not direct fund loss.
        risky_fn_body = ast._get_function_bodies().get(fn_name, "")
        if should_skip_commitment_rule_for_body(risky_fn_body):
            return None
        if _has_hash_precondition(risky_fn_body):
            severity = "medium"
            issue_class = "contextual"
            exploit_severity = "griefing"
        else:
            severity = "high"
            issue_class = "real_issue"
            exploit_severity = "direct_fund_loss"

        return Violation(
            rule=self.id,
            reason=f"Function '{fn_name}' parses bytes via split/slice without explicit length guard",
            exploit="Short commitment payloads can decode into unexpected empty/truncated values and violate downstream invariants.",
            location={"line": 0, "function": fn_name},
            severity=severity,
            issue_class=issue_class,
            exploit_severity=exploit_severity,
        )


class OutputBindingDetector(AuditDetector):
    """Detect output value/token checks with missing lockingBytecode binding."""

    id = "output_binding_missing"

    def detect(
        self,
        ast: CashScriptAST,
        invariants: Optional[Dict[str, Any]] = None,
    ) -> Optional[Violation]:
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
    """
    Classify tokenCategory-based authorization without escalating it.

    NOTE: This detector is intentionally NOT in AUDIT_DETECTOR_REGISTRY.
    The enforcer routes any result to `auth_classifier_metadata` instead of
    the violations list so it never surfaces as an AuditIssue.
    The class is kept here so that the enforcer can instantiate it separately
    if metadata tagging is desired in the future.
    """

    id = "authorization_model_classifier"

    def detect(
        self,
        ast: CashScriptAST,
        invariants: Optional[Dict[str, Any]] = None,
    ) -> Optional[Violation]:
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
    PositiveOffsetOOBDetector(),
    FixedIndexOOBDetector(),
    UnsupportedWhileDetector(),
    CommitmentLengthSafetyDetector(),
    OutputBindingDetector(),
    PartialAggregationDetector(),
    InputOutputCouplingDetector(),
    # AuthorizationModelClassifierDetector is NOT included here.
    # The enforcer routes it to auth_classifier_metadata (not violations).
]
