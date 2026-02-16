"""
CashScript AST Parser for Anti-Pattern Detection

This module provides a simplified AST representation for CashScript code
to enable semantic anti-pattern detection.

NOTE: This is a simplified parser for MVP. In production, this would use
the actual CashScript compiler's AST or a full parser like tree-sitter.
"""

from typing import List, Optional, Dict, Any
from dataclasses import dataclass
import re


@dataclass
class Location:
    """Source code location"""
    line: int
    column: int
    function: Optional[str] = None


@dataclass
class OutputReference:
    """Represents a reference to tx.outputs[N]"""
    index: int  # Which output index (0, 1, 2, ...)
    location: Location
    property_accessed: str  # "value", "lockingBytecode", "tokenCategory", etc.
    
    def uses_index_only(self) -> bool:
        """True if this reference uses positional index without semantic validation"""
        # This will be determined by the AST analyzer
        return True  # Placeholder


@dataclass
class Comparison:
    """Represents a comparison in a require statement"""
    left: str
    op: str  # "==", "!=", ">", etc.
    right: str
    location: Location
    
    @property
    def is_type_mismatch(self) -> bool:
        """Simple heuristic for type mismatches"""
        bytes_fields = {'lockingBytecode'}
        bytes32_fields = {'tokenCategory', 'hash256', 'sha256'}
        
        # Check if one is bytes and other is bytes32 constant
        if any(f in self.left or f in self.right for f in bytes_fields):
            if 'NO_TOKEN' in self.left or 'NO_TOKEN' in self.right:
                return True
            if '0x' in self.left or '0x' in self.right:
                # Check if it's 32 bytes (66 chars with 0x)
                literal = self.left if '0x' in self.left else self.right
                if len(literal) == 66:
                    return True
        return False


@dataclass
class ValidationCheck:
    """Represents a require() statement"""
    location: Location
    condition: str
    validates_locking_bytecode: bool = False
    validates_output_count: bool = False
    validates_position: bool = False
    validates_token_category: Optional[int] = None
    validates_token_amount: Optional[int] = None
    validates_value: Optional[int] = None
    is_time_check: bool = False
    comparisons: List[Comparison] = None


@dataclass
class ArithmeticOp:
    """Represents an arithmetic operation"""
    op: str  # "/", "%", "+", "*"
    location: Location
    divisor_expression: Optional[str] = None


class CashScriptAST:
    """
    Simplified AST representation for CashScript code.
    
    This provides semantic analysis capabilities for anti-pattern detection.
    """
    
    def __init__(self, code: str):
        self.code = code
        self.lines = code.split('\n')
        
        # Parsed elements
        self.output_references: List[OutputReference] = []
        self.validations: List[ValidationCheck] = []
        self.arithmetic_ops: List[ArithmeticOp] = []
        self.functions: List[str] = []
        self.constructor_params: List[Dict[str, str]] = []
        self.is_stateful = False
        
        # Parse the code
        self._parse()
    
    def _parse(self):
        """Parse code into AST elements"""
        current_function = None
        
        for line_num, line in enumerate(self.lines, start=1):
            stripped = line.strip()
            
            # Detect constructor parameters
            if re.match(r'contract\s+\w+\s*\(', stripped):
                params_block = re.search(r'\((.*?)\)', stripped)
                if params_block:
                    param_strs = params_block.group(1).split(',')
                    for p in param_strs:
                        parts = p.strip().split()
                        if len(parts) >= 2:
                            self.constructor_params.append({'type': parts[0], 'name': parts[1]})

            # Detect function definitions
            if 'function ' in stripped:
                func_match = re.search(r'function\s+(\w+)', stripped)
                if func_match:
                    current_function = func_match.group(1)
                    self.functions.append(current_function)
            
            # Detect stateful patterns (hash256 of state)
            if 'hash256(' in stripped and 'state' in stripped.lower():
                self.is_stateful = True
            
            # Detect output references
            output_refs = re.findall(r'tx\.outputs\[(\d+)\]\.(\w+)', stripped)
            for index_str, property_name in output_refs:
                self.output_references.append(OutputReference(
                    index=int(index_str),
                    location=Location(line=line_num, column=0, function=current_function),
                    property_accessed=property_name
                ))
            
            # Detect division/modulo operations
            div_matches = re.findall(r'(\w+)\s*([/%])\s*(\w+)', stripped)
            for left, op, right in div_matches:
                self.arithmetic_ops.append(ArithmeticOp(
                    op=op,
                    location=Location(line=line_num, column=0, function=current_function),
                    divisor_expression=right
                ))
            
            # Detect validation checks
            if 'require(' in stripped:
                validation = ValidationCheck(
                    location=Location(line=line_num, column=0, function=current_function),
                    condition=stripped,
                    comparisons=[]
                )
                
                # Parse comparisons
                comp_matches = re.findall(r'([^=!><\s]+)\s*([=!><]+)\s*([^&|)\s]+)', stripped)
                for left, op, right in comp_matches:
                    validation.comparisons.append(Comparison(
                        left=left, op=op, right=right,
                        location=validation.location
                    ))

                # Check what this validation validates
                if 'lockingBytecode' in stripped and '==' in stripped:
                    validation.validates_locking_bytecode = True
                
                if 'tx.outputs.length' in stripped:
                    validation.validates_output_count = True
                
                if 'this.activeInputIndex' in stripped and '==' in stripped:
                    validation.validates_position = True
                
                # Value and Token checks
                val_match = re.search(r'tx\.outputs\[(\d+)\]\.value', stripped)
                if val_match:
                    validation.validates_value = int(val_match.group(1))

                token_cat_match = re.search(r'tx\.outputs\[(\d+)\]\.tokenCategory', stripped)
                if token_cat_match:
                    validation.validates_token_category = int(token_cat_match.group(1))
                
                token_amt_match = re.search(r'tx\.outputs\[(\d+)\]\.tokenAmount', stripped)
                if token_amt_match:
                    validation.validates_token_amount = int(token_amt_match.group(1))
                
                # Time checks
                if 'tx.time' in stripped or 'tx.age' in stripped or 'tx.blockHeight' in stripped:
                    validation.is_time_check = True
                
                self.validations.append(validation)
    
    @property
    def is_multisig_like(self) -> bool:
        """True if contract has multiple pubkeys in constructor"""
        pubkeys = [p for p in self.constructor_params if p['type'] == 'pubkey']
        return len(pubkeys) >= 2

    @property
    def is_escrow_like(self) -> bool:
        """True if contract seems designed for escrow/multisig roles"""
        return self.is_multisig_like or "escrow" in self.code.lower()

    def get_spending_functions(self) -> List[str]:
        """Identify functions that likely spend or release funds"""
        spending_keywords = {'release', 'spend', 'reclaim', 'withdraw', 'payout'}
        return [f for f in self.functions if any(k in f.lower() for k in spending_keywords)]

    def validates_locking_bytecode_for(self, output_ref: OutputReference) -> bool:
        """
        Check if lockingBytecode is validated for a specific output index.
        """
        for validation in self.validations:
            if validation.location.function == output_ref.location.function:
                if validation.validates_locking_bytecode:
                    if f'tx.outputs[{output_ref.index}].lockingBytecode' in validation.condition:
                        return True
        return False
    
    def validates_output_count(self) -> bool:
        """Check if code validates tx.outputs.length"""
        return any(v.validates_output_count for v in self.validations)
    
    def validates_input_position(self) -> bool:
        """Check if code validates this.activeInputIndex"""
        return any(v.validates_position for v in self.validations)
    
    def has_fee_calculation(self) -> bool:
        """Check if code calculates fee as input - output"""
        for line in self.lines:
            if re.search(r'\bfee\s*=.*-', line): return True
            if re.search(r'assumedFee\s*=.*-', line): return True
        return False
    
    def has_unguarded_division(self) -> List[ArithmeticOp]:
        """Find division operations without dominating require(divisor > 0)"""
        unguarded = []
        for op in self.arithmetic_ops:
            if op.op in ('/', '%'):
                # Check for dominating require in same function
                guarded = False
                for v in self.validations:
                    if v.location.function == op.location.function and v.location.line < op.location.line:
                        if op.divisor_expression in v.condition and ('> 0' in v.condition or '!= 0' in v.condition):
                            guarded = True
                            break
                if not guarded:
                    unguarded.append(op)
        return unguarded
    
    def find_token_pair_violations(self) -> List[int]:
        """Find output indices with tokenCategory check but no tokenAmount check"""
        cats = {v.validates_token_category for v in self.validations if v.validates_token_category is not None}
        amts = {v.validates_token_amount for v in self.validations if v.validates_token_amount is not None}
        return list(cats - amts)
    
    def has_time_validation_error(self) -> bool:
        """Detect using > or <= instead of >= and < for time checks"""
        for v in self.validations:
            if v.is_time_check:
                if '>' in v.condition and '>=' not in v.condition: return True
                if '<=' in v.condition: return True
        return False

    def references_output_by_index_without_semantic_validation(self) -> List[OutputReference]:
        """Find output references that use index without validating semantic role."""
        violations = []
        for output_ref in self.output_references:
            if output_ref.property_accessed == 'lockingBytecode': continue
            if not self.validates_locking_bytecode_for(output_ref):
                violations.append(output_ref)
        return violations
    
    def to_dict(self) -> Dict[str, Any]:
        """Serialize AST to dict for debugging"""
        return {
            "functions": self.functions,
            "output_references": len(self.output_references),
            "validations": len(self.validations),
            "validates_output_count": self.validates_output_count(),
            "is_stateful": self.is_stateful,
            "is_escrow_like": self.is_escrow_like
        }

