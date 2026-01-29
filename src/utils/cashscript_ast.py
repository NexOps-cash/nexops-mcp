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
class ValidationCheck:
    """Represents a require() statement"""
    location: Location
    condition: str
    validates_locking_bytecode: bool = False
    validates_output_count: bool = False
    validates_position: bool = False


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
        self.functions: List[str] = []
        
        # Parse the code
        self._parse()
    
    def _parse(self):
        """Parse code into AST elements"""
        current_function = None
        
        for line_num, line in enumerate(self.lines, start=1):
            stripped = line.strip()
            
            # Detect function definitions
            if 'function ' in stripped:
                func_match = re.search(r'function\s+(\w+)', stripped)
                if func_match:
                    current_function = func_match.group(1)
                    self.functions.append(current_function)
            
            # Detect output references
            output_refs = re.findall(r'tx\.outputs\[(\d+)\]\.(\w+)', stripped)
            for index_str, property_name in output_refs:
                self.output_references.append(OutputReference(
                    index=int(index_str),
                    location=Location(line=line_num, column=0, function=current_function),
                    property_accessed=property_name
                ))
            
            # Detect validation checks
            if 'require(' in stripped:
                validation = ValidationCheck(
                    location=Location(line=line_num, column=0, function=current_function),
                    condition=stripped
                )
                
                # Check what this validation validates
                if 'lockingBytecode' in stripped and '==' in stripped:
                    validation.validates_locking_bytecode = True
                
                if 'tx.outputs.length' in stripped:
                    validation.validates_output_count = True
                
                if 'this.activeInputIndex' in stripped and '==' in stripped:
                    validation.validates_position = True
                
                self.validations.append(validation)
    
    def find_output_references(self) -> List[OutputReference]:
        """Return all tx.outputs[N] references"""
        return self.output_references
    
    def validates_locking_bytecode_for(self, output_ref: OutputReference) -> bool:
        """
        Check if lockingBytecode is validated for a specific output index.
        
        This is a semantic check: does the code verify that the output at this
        index has the expected script (covenant continuation, recipient address, etc.)?
        """
        # Look for validations in the same function
        for validation in self.validations:
            if validation.location.function == output_ref.location.function:
                if validation.validates_locking_bytecode:
                    # Check if it validates the same output index
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
            # Look for patterns like: int fee = ... - ...
            if re.search(r'\bfee\s*=.*-', line):
                return True
            if re.search(r'assumedFee\s*=.*-', line):
                return True
        return False
    
    def references_output_by_index_without_semantic_validation(self) -> List[OutputReference]:
        """
        Find output references that use index without validating semantic role.
        
        This is the core check for implicit output ordering anti-pattern.
        """
        violations = []
        
        for output_ref in self.output_references:
            # Skip if this is a lockingBytecode access (that's the validation itself)
            if output_ref.property_accessed == 'lockingBytecode':
                continue
            
            # Check if lockingBytecode is validated for this output
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
            "validates_input_position": self.validates_input_position()
        }
