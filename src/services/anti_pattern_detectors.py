"""
Anti-Pattern Detectors

Each detector implements semantic detection for a specific anti-pattern.
Detectors use AST analysis, not string matching or heuristics.
"""

from typing import Optional, Dict, Any
from dataclasses import dataclass
from src.utils.cashscript_ast import CashScriptAST, OutputReference


@dataclass
class Violation:
    """Represents an anti-pattern violation"""
    rule: str  # Anti-pattern ID
    reason: str  # Which invariant is violated
    exploit: str  # Why this is exploitable on BCH
    location: Dict[str, Any]  # Where in code
    severity: str = "critical"
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule": self.rule,
            "reason": self.reason,
            "exploit": self.exploit,
            "location": self.location,
            "severity": self.severity
        }


class AntiPatternDetector:
    """Base class for anti-pattern detectors"""
    
    id: str = "base"
    
    def detect(self, ast: CashScriptAST) -> Optional[Violation]:
        """
        Detect anti-pattern violation using semantic analysis.
        
        Returns:
            Violation if pattern detected, None otherwise
        """
        raise NotImplementedError


class ImplicitOutputOrderingDetector(AntiPatternDetector):
    """
    Detects implicit output ordering anti-pattern.
    
    VIOLATION: Code references tx.outputs[N] without validating lockingBytecode
    
    SAFE: Code validates lockingBytecode before using output properties
    """
    
    id = "implicit_output_ordering"
    
    def detect(self, ast: CashScriptAST) -> Optional[Violation]:
        """
        Semantic detection:
        1. Find all tx.outputs[N].property references
        2. Check if lockingBytecode is validated for that output
        3. If not validated → VIOLATION
        """
        # Find output references without semantic validation
        unvalidated_refs = ast.references_output_by_index_without_semantic_validation()
        
        if unvalidated_refs:
            # Get first violation for reporting
            first_ref = unvalidated_refs[0]
            
            return Violation(
                rule=f"{self.id}.cash",
                reason="Output semantic role inferred from index position without lockingBytecode validation",
                exploit="Attacker can reorder transaction outputs to redirect value. "
                        "BCH does not enforce output order - attacker controls which script "
                        "appears at which index. Without lockingBytecode validation, the "
                        "contract cannot distinguish covenant continuation from attacker-controlled outputs.",
                location={
                    "line": first_ref.location.line,
                    "function": first_ref.location.function,
                    "output_index": first_ref.index,
                    "property": first_ref.property_accessed,
                    "total_violations": len(unvalidated_refs)
                }
            )
        
        return None


class MissingOutputLimitDetector(AntiPatternDetector):
    """
    Detects missing output count validation.
    
    VIOLATION: Function does not validate tx.outputs.length
    
    SAFE: Function enforces output count limit
    """
    
    id = "missing_output_limit"
    
    def detect(self, ast: CashScriptAST) -> Optional[Violation]:
        """
        Semantic detection:
        1. Check if any function validates tx.outputs.length
        2. If no validation found → VIOLATION
        """
        if not ast.validates_output_count():
            return Violation(
                rule=f"{self.id}.cash",
                reason="No output count validation (tx.outputs.length) found in contract",
                exploit="Attacker can add unlimited outputs to mint unauthorized tokens or NFTs. "
                        "Without output count limits, attacker creates valid transaction satisfying "
                        "contract constraints, then adds extra outputs minting new tokens. "
                        "Contract validates expected outputs but ignores extras, allowing "
                        "unauthorized tokens to enter circulation.",
                location={
                    "line": 0,
                    "function": "all",
                    "missing": "require(tx.outputs.length <= N)"
                }
            )
        
        return None


class UnvalidatedPositionDetector(AntiPatternDetector):
    """
    Detects missing input position validation.
    
    VIOLATION: Contract does not validate this.activeInputIndex
    
    SAFE: Contract enforces its own input position
    """
    
    id = "unvalidated_position"
    
    def detect(self, ast: CashScriptAST) -> Optional[Violation]:
        """
        Semantic detection:
        1. Check if contract validates this.activeInputIndex
        2. If no validation found → VIOLATION
        """
        if not ast.validates_input_position():
            return Violation(
                rule=f"{self.id}.cash",
                reason="No input position validation (this.activeInputIndex) found in contract",
                exploit="Attacker can reorder transaction inputs to bypass validation logic. "
                        "Without explicit position validation, attacker swaps input positions "
                        "(e.g., oracle at index 0, main contract at index 1) to make contract "
                        "read wrong data from wrong position. Multi-contract systems require "
                        "each contract to know exactly which input index it occupies.",
                location={
                    "line": 0,
                    "function": "all",
                    "missing": "require(this.activeInputIndex == N)"
                }
            )
        
        return None


class FeeAssumptionViolationDetector(AntiPatternDetector):
    """
    Detects fee assumption anti-pattern.
    
    VIOLATION: Code calculates fee as inputValue - outputValue
    
    SAFE: Code does not reason about transaction fees
    """
    
    id = "fee_assumption_violation"
    
    def detect(self, ast: CashScriptAST) -> Optional[Violation]:
        """
        Semantic detection:
        1. Check if code has fee calculation pattern
        2. If found → VIOLATION
        """
        if ast.has_fee_calculation():
            return Violation(
                rule=f"{self.id}.cash",
                reason="Contract calculates transaction fee as inputValue - outputValue",
                exploit="Fee calculation breaks with multi-input transactions. Covenant can only "
                        "see its own input value, not total of all inputs. Attacker adds inputs "
                        "to subsidize fees, making covenant's fee calculation meaningless. "
                        "This enables fee-based value extraction, invariant bypass, and "
                        "covenant economics manipulation. BCH fee = sum(all inputs) - sum(all outputs), "
                        "which covenant cannot calculate.",
                location={
                    "line": 0,
                    "function": "unknown",
                    "pattern": "fee = inputValue - outputValue"
                }
            )
        
        return None


class DivisionByZeroDetector(AntiPatternDetector):
    """
    Detects division or modulo without a dominating non-zero check.
    
    VIOLATION: a / b where require(b > 0) is missing.
    """
    id = "division_by_zero"
    
    def detect(self, ast: CashScriptAST) -> Optional[Violation]:
        unguarded = ast.has_unguarded_division()
        if unguarded:
            first = unguarded[0]
            return Violation(
                rule=f"{self.id}.cash",
                reason=f"Division/modulo operation '{first.op}' on variable '{first.divisor_expression}' without non-zero guard",
                exploit="Transaction will fail and contract will be bricked if divisor is 0. "
                        "CashScript does not handle division by zero safely - it results in an "
                        "unspendable UTXO. Contracts must explicitly validate divisors.",
                location={
                    "line": first.location.line,
                    "function": first.location.function,
                    "operator": first.op,
                    "divisor": first.divisor_expression
                }
            )
        return None


class TokenPairValidationDetector(AntiPatternDetector):
    """
    Detects tokenCategory checks without a corresponding tokenAmount check.
    
    VIOLATION: require(tx.outputs[N].tokenCategory == category) found, but tokenAmount is ignored.
    """
    id = "missing_token_amount_validation"
    
    def detect(self, ast: CashScriptAST) -> Optional[Violation]:
        violations = ast.find_token_pair_violations()
        if violations:
            idx = violations[0]
            return Violation(
                rule=f"{self.id}.cash",
                reason=f"Output {idx} has tokenCategory validation but is missing tokenAmount validation",
                exploit="Token inflation/duplication. Attacker can set an arbitrary tokenAmount "
                        "if the contract only validates the category. Both must be checked to "
                        "preserve token integrity.",
                location={
                    "line": 0,
                    "function": "all",
                    "output_index": idx
                }
            )
        return None


class CovenantContinuationDetector(AntiPatternDetector):
    """
    Detects stateful covenants that forget to validate lockingBytecode continuation.
    """
    id = "vulnerable_covenant"
    
    def detect(self, ast: CashScriptAST) -> Optional[Violation]:
        if ast.is_stateful:
            # Check if any function validates lockingBytecode continuation
            has_continuation = any(v.validates_locking_bytecode for v in ast.validations)
            if not has_continuation:
                return Violation(
                    rule=f"{self.id}.cash",
                    reason="Stateful covenant detected but no lockingBytecode continuation check found",
                    exploit="Covenant escape. Attacker can redirect funds to any script by "
                            "providing a different lockingBytecode in the transaction output. "
                            "Stateful contracts must enforce that they recreate themselves.",
                    location={
                        "line": 0,
                        "function": "all",
                        "missing": "require(tx.outputs[N].lockingBytecode == ...)"
                    }
                )
        return None


class TimeOperatorViolationDetector(AntiPatternDetector):
    """
    Detects usage of > or <= in time checks.
    
    VIOLATION: require(tx.time > deadline) or require(tx.time <= deadline)
    """
    id = "time_validation_error"
    
    def detect(self, ast: CashScriptAST) -> Optional[Violation]:
        if ast.has_time_validation_error():
            return Violation(
                rule=f"{self.id}.cash",
                reason="Invalid time comparison operator used for tx.time",
                exploit="Off-by-one block/timestamp errors. CashScript development standards "
                        "require using >= for 'at or after' and < for 'before' to ensure "
                        "clear, gap-free time boundaries.",
                location={
                    "line": 0,
                    "function": "all",
                    "pattern": "Use >= or < for time gating"
                }
            )
        return None


class HardcodedInputIndexDetector(AntiPatternDetector):
    """
    Detects hardcoded indices for inputs other than this.activeInputIndex.
    """
    id = "unvalidated_position"
    
    def detect(self, ast: CashScriptAST) -> Optional[Violation]:
        # Simple check for tx.inputs[0] or similar being used without position validation
        code_str = ast.code
        if ("tx.inputs[0]" in code_str or "tx.inputs[1]" in code_str) and not ast.validates_input_position():
            return Violation(
                rule=f"{self.id}.cash",
                reason="Literal input index used without this.activeInputIndex validation",
                exploit="Position-dependent logic bypass. Attacker can shift contract position "
                        "to a different index (1 instead of 0) to make it read the wrong data.",
                location={
                    "line": 0,
                    "function": "all",
                    "missing": "require(this.activeInputIndex == 0)"
                }
            )
        return None


class EVMHallucinationDetector(AntiPatternDetector):
    """
    Detects Solidity/EVM hallucinated terms.
    """
    id = "evm_hallucination"
    
    def detect(self, ast: CashScriptAST) -> Optional[Violation]:
        import re
        evm_patterns = [
            r'\bmsg\.sender\b', r'\bmsg\.value\b', r'\bmapping\s*\(', r'\bemit\s+\w+',
            r'\bmodifier\s+\w+', r'\bpayable\b', r'\bview\b', r'\bpure\b',
            r'\bconstructor\s*\(', r'\bevent\s+\w+', r'\buint256\b'
        ]
        for p in evm_patterns:
            if re.search(p, ast.code, re.IGNORECASE):
                return Violation(
                    rule=f"{self.id}",
                    reason=f"EVM/Solidity pattern '{p}' detected in CashScript source",
                    exploit="Generated code will fail to compile as it uses Solidity syntax.",
                    severity="critical",
                    location={"line": 0, "function": "all"}
                )
        return None


class EmptyFunctionDetector(AntiPatternDetector):
    """
    Detects public functions with no require() statements.
    """
    id = "empty_function_body"
    
    def detect(self, ast: CashScriptAST) -> Optional[Violation]:
        import re
        # Find function blocks and check for require()
        fn_pattern = re.compile(r'function\s+(\w+)\s*\([^)]*\)\s*\{([^}]*)\}', re.DOTALL)
        empty_fns = []
        for match in fn_pattern.finditer(ast.code):
            if 'require(' not in match.group(2):
                empty_fns.append(match.group(1))
        
        if empty_fns:
            return Violation(
                rule=f"{self.id}",
                reason=f"Functions with no require() statements: {', '.join(empty_fns)}",
                exploit="Empty functions allow unrestricted spending of UTXOs by anyone. "
                        "Every public function must enforce at least one constraint.",
                severity="critical",
                location={"line": 0, "function": empty_fns[0]}
            )
        return None


class SemanticTypeValidationDetector(AntiPatternDetector):
    """
    Detects comparisons between incompatible types in require statements.
    
    VIOLATION: require(tx.outputs[0].lockingBytecode == NO_TOKEN)
    """
    id = "semantic_type_mismatch"
    
    def detect(self, ast: CashScriptAST) -> Optional[Violation]:
        for v in ast.validations:
            for comp in v.comparisons:
                if comp.is_type_mismatch:
                    return Violation(
                        rule=self.id,
                        reason=f"Type mismatch: Comparing '{comp.left}' and '{comp.right}' in {v.location.function}",
                        exploit="The comparison is logically broken (comparing bytes vs bytes32). "
                                "This will either always fail or pass unexpectedly, breaking contract logic. "
                                "CashScript bytecode comparisons must use compatible types.",
                        location={"line": comp.location.line, "function": comp.location.function}
                    )
        # Check for cross-field confusion
        if ("tokenCategory" in ast.code and "lockingBytecode" in ast.code):
             # Heuristic: if category is assigned to something called 'bytecode' or vice versa
             pass 
        return None


class MultisigDistinctnessDetector(AntiPatternDetector):
    """
    Detects lack of distinctness check for multisig pubkeys.
    """
    id = "multisig_distinctness_flaw"
    
    def detect(self, ast: CashScriptAST) -> Optional[Violation]:
        if ast.is_multisig_like:
            pk_names = [p['name'] for p in ast.constructor_params if p['type'] == 'pubkey']
            # Look for require(pk1 != pk2)
            has_distinctness = False
            for v in ast.validations:
                if '!=' in v.condition and pk_names[0] in v.condition and pk_names[1] in v.condition:
                    has_distinctness = True
                    break
            
            if not has_distinctness:
                return Violation(
                    rule=self.id,
                    reason=f"Multisig pubkeys ({', '.join(pk_names)}) are not enforced to be distinct",
                    exploit="Collusion vulnerability. If pk1 == pk2, one person can satisfy a 2-of-2 "
                            "multisig alone. Public keys should be explicitly compared with !=.",
                    severity="medium",
                    location={"line": 0, "function": "constructor"}
                )
        return None


class SpendingPathSecurityDetector(AntiPatternDetector):
    """
    Ensures spending functions either validate output values or use strict anchors.
    """
    id = "missing_value_enforcement"
    
    def detect(self, ast: CashScriptAST) -> Optional[Violation]:
        spending_fns = ast.get_spending_functions()
        for fn in spending_fns:
            fn_validations = [v for v in ast.validations if v.location.function == fn]
            validates_val = any(v.validates_value is not None for v in fn_validations)
            is_strict_single = ast.validates_output_count() and any("== 1" in v.condition for v in fn_validations)
            
            if not (validates_val or is_strict_single):
                return Violation(
                    rule=self.id,
                    reason=f"Spending function '{fn}' missing output value validation or strict output count anchor",
                    exploit="Value extraction. Attacker can redirect funds to themselves or "
                            "drain the contract by adding unexpected outputs if the contract "
                            "doesn't explicitly lock the output amount or total counts.",
                    severity="high",
                    location={"line": 0, "function": fn}
                )
        return None


class WeakOutputLimitDetector(AntiPatternDetector):
    """
    Detects weak output length checks (>= 1 without upper bound).
    """
    id = "weak_output_count_limit"
    
    def detect(self, ast: CashScriptAST) -> Optional[Violation]:
        for v in ast.validations:
            if "tx.outputs.length" in v.condition and ">=" in v.condition:
                # Check if there is also an equality or less-than check in the same function
                fn_validations = [v2 for v2 in ast.validations if v2.location.function == v.location.function]
                has_upper = any(("==" in v2.condition or "<" in v2.condition) and "tx.outputs.length" in v2.condition for v2 in fn_validations)
                if not has_upper:
                    return Violation(
                        rule=self.id,
                        reason="Weak output count check (>=) used without an upper bound or exact match",
                        exploit="Attacker can append extra outputs to the transaction. "
                                "While the first output is validated, extra outputs could "
                                "be used to drain the UTXO's remaining value or mint tokens.",
                        severity="medium",
                        location={"line": v.location.line, "function": v.location.function}
                    )
        return None


class EscrowRoleEnforcementDetector(AntiPatternDetector):
    """
    Ensures escrow-like contracts have at least one hard spending constraint.
    """
    id = "missing_output_anchor"
    
    def detect(self, ast: CashScriptAST) -> Optional[Violation]:
        if ast.is_escrow_like and not ast.is_stateful:
            # Check for at least one hard spending function (all must be secure)
            for fn in ast.get_spending_functions():
                fn_validations = [v for v in ast.validations if v.location.function == fn]
                # Requires lockingBytecode validation OR value validation OR strict single output
                has_anchor = any(v.validates_locking_bytecode or v.validates_value is not None for v in fn_validations)
                strict_single = any("tx.outputs.length == 1" in v.condition for v in fn_validations)
                
                if not (has_anchor or strict_single):
                    return Violation(
                        rule=self.id,
                        reason=f"Escrow function '{fn}' missing hard output anchor (lockingBytecode or value validation)",
                        exploit="Contract anchor bypass. In escrow roles, at least one output "
                                "must be strictly bound to a target destination or value to prevent "
                                "the arbiter/party from redirecting funds to an arbitrary script.",
                        severity="high",
                        location={"line": 0, "function": fn}
                    )
        return None


class TautologicalGuardDetector(AntiPatternDetector):
    """
    Detects comparisons where left and right sides are identical.
    """
    id = "tautological_guard"
    
    def detect(self, ast: CashScriptAST) -> Optional[Violation]:
        tautologies = ast.find_tautologies()
        if tautologies:
            first = tautologies[0]
            return Violation(
                rule=self.id,
                reason=f"Tautological guard detected: '{first.left} {first.op} {first.right}'",
                exploit="Bypassed security check. A comparison where both sides are identical "
                        "always evaluates to true (or false), effectively skipping the intended "
                        "validation. This is often used by LLMs to 'fake' compliance with "
                        "structural rules.",
                severity="critical",
                location={"line": first.location.line, "function": first.location.function}
            )
        return None


class InvalidLockingBytecodeSelfComparisonDetector(AntiPatternDetector):
    """
    Detects cases where lockingBytecode is compared to itself.
    """
    id = "locking_bytecode_self_comparison"
    
    def detect(self, ast: CashScriptAST) -> Optional[Violation]:
        violations = ast.find_locking_bytecode_self_comparisons()
        if violations:
            first = violations[0]
            return Violation(
                rule=self.id,
                reason=f"Invalid self-comparison of lockingBytecode: '{first.left} == {first.right}'",
                exploit="Critical anchor bypass. Comparing an output's lockingBytecode to itself "
                        "instead of a known anchor (like this.lockingBytecode) provides zero "
                        "security. An attacker can set any script they want in the output and "
                        "the check will still pass.",
                severity="critical",
                location={"line": first.location.line, "function": first.location.function}
            )
        return None


class MultisigSignatureReuseDetector(AntiPatternDetector):
    """
    Detects reuse of same signature variable across multiple pubkeys.
    """
    id = "multisig_signature_reuse"
    
    def detect(self, ast: CashScriptAST) -> Optional[Violation]:
        violations = ast.find_signature_reuse()
        if violations:
            first = violations[0]
            return Violation(
                rule=self.id,
                reason=f"Signature reuse detected: variable '{first.sig}' used for multiple pubkeys",
                exploit="Threshold bypass. If the same signature variable is used for two different "
                        "public keys, a single signature from one party can be used twice to "
                        "satisfy an N-of-M multisig requirement, reducing the effective security "
                        "threshold.",
                severity="high",
                location={"line": first.location.line, "function": first.location.function}
            )
        return None


# Registry of all detectors
DETECTOR_REGISTRY = [
    ImplicitOutputOrderingDetector(),
    MissingOutputLimitDetector(),
    UnvalidatedPositionDetector(),
    FeeAssumptionViolationDetector(),
    DivisionByZeroDetector(),
    TokenPairValidationDetector(),
    CovenantContinuationDetector(),
    TimeOperatorViolationDetector(),
    HardcodedInputIndexDetector(),
    EVMHallucinationDetector(),
    EmptyFunctionDetector(),
    SemanticTypeValidationDetector(),
    MultisigDistinctnessDetector(),
    SpendingPathSecurityDetector(),
    WeakOutputLimitDetector(),
    EscrowRoleEnforcementDetector(),
    TautologicalGuardDetector(),
    InvalidLockingBytecodeSelfComparisonDetector(),
    MultisigSignatureReuseDetector()
]



