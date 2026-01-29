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


# Registry of all detectors
DETECTOR_REGISTRY = [
    ImplicitOutputOrderingDetector(),
    MissingOutputLimitDetector(),
    UnvalidatedPositionDetector(),
    FeeAssumptionViolationDetector(),
]
