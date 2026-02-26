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
    def is_tautology(self) -> bool:
        """True if left and right operands are identical after normalization"""
        def normalize(s: str) -> str:
            return re.sub(r'\s+', '', s).strip('()')
        return normalize(self.left) == normalize(self.right)

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
class CheckSigCall:
    """Represents a checkSig() or checkMultiSig() call"""
    sig: str
    pubkey: str
    location: Location


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
        self.check_sig_calls: List[CheckSigCall] = []
        self.functions: List[str] = []
        self.constructor_params: List[Dict[str, str]] = []
        self.is_stateful = False
        
        # Parse the code
        self._parse()
    
    def _parse(self):
        """Parse code into AST elements"""
        # Pre-process code to handle multi-line statements
        # 1. Remove comments
        clean_code = re.sub(r'//.*', '', self.code)
        clean_code = re.sub(r'/\*.*?\*/', '', clean_code, flags=re.DOTALL)
        
        # 2. Extract content and structure
        current_function = None
        
        # Split into statements based on semicolons and braces
        # This is a heuristic parser for structural analysis
        
        # Find constructor parameters
        contract_match = re.search(r'contract\s+\w+\s*\((.*?)\)', clean_code, re.DOTALL)
        if contract_match:
            param_block = contract_match.group(1)
            for p in param_block.split(','):
                parts = p.strip().split()
                if len(parts) >= 2:
                    self.constructor_params.append({'type': parts[0], 'name': parts[1]})

        # Detect stateful patterns
        if 'hash256(' in clean_code and 'state' in clean_code.lower():
            self.is_stateful = True

        # Find function blocks
        function_blocks = re.finditer(r'function\s+(\w+)\s*\([^)]*\)\s*\{(.*?)\}', clean_code, re.DOTALL)
        for func_match in function_blocks:
            func_name = func_match.group(1)
            func_body = func_match.group(2)
            self.functions.append(func_name)
            
            # Process function body statements
            statements = func_body.split(';')
            for stmt in statements:
                stmt = stmt.strip()
                if not stmt: continue
                
                # Mock line number as 0 for multi-line statements in this simple parser
                loc = Location(line=0, column=0, function=func_name)

                # Detect output references
                output_refs = re.findall(r'tx\.outputs\[(\d+)\]\.(\w+)', stmt)
                for index_str, property_name in output_refs:
                    self.output_references.append(OutputReference(
                        index=int(index_str),
                        location=loc,
                        property_accessed=property_name
                    ))

                # Detect checkSig calls
                sig_matches = re.findall(r'checkSig\s*\(\s*(\w+)\s*,\s*(\w+)\s*\)', stmt)
                for sig, pk in sig_matches:
                    self.check_sig_calls.append(CheckSigCall(sig=sig, pubkey=pk, location=loc))

                # Detect division/modulo
                div_matches = re.findall(r'(\w+)\s*([/%])\s*(\w+)', stmt)
                for left, op, right in div_matches:
                    self.arithmetic_ops.append(ArithmeticOp(op=op, location=loc, divisor_expression=right))

                # Detect require()
                if 'require(' in stmt:
                    # Extract the condition inside require(...)
                    # Handle nested parentheses simple case
                    req_match = re.search(r'require\s*\((.*)\)', stmt, re.DOTALL)
                    if req_match:
                        condition = req_match.group(1).strip()
                        validation = ValidationCheck(
                            location=loc,
                            condition=condition,
                            comparisons=[]
                        )
                        
                        # Parse comparisons
                        comp_matches = re.findall(r'([^=!><&|()]+)\s*([=!><]+)\s*([^&|)\s,;]+)', condition)
                        for left, op, right in comp_matches:
                            validation.comparisons.append(Comparison(
                                left=left.strip(), op=op.strip(), right=right.strip(),
                                location=loc
                            ))

                        # Semantic labeling
                        if 'lockingBytecode' in condition and '==' in condition:
                            validation.validates_locking_bytecode = True
                        if 'tx.outputs.length' in condition:
                            validation.validates_output_count = True
                        if 'this.activeInputIndex' in condition and '==' in condition:
                            validation.validates_position = True
                        
                        val_match = re.search(r'tx\.outputs\[(\d+)\]\.value', condition)
                        if val_match:
                            validation.validates_value = int(val_match.group(1))

                        token_cat_match = re.search(r'tx\.outputs\[(\d+)\]\.tokenCategory', condition)
                        if token_cat_match:
                            validation.validates_token_category = int(token_cat_match.group(1))
                        
                        token_amt_match = re.search(r'tx\.outputs\[(\d+)\]\.tokenAmount', condition)
                        if token_amt_match:
                            validation.validates_token_amount = int(token_amt_match.group(1))

                        if any(x in condition for x in ['tx.time', 'tx.age', 'tx.blockHeight']):
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

    @property
    def is_covenant_like(self) -> bool:
        """True if contract uses specific covenant/token keywords"""
        covenant_keywords = {
            'tx.outputs', 'tx.inputs', 'this.activeBytecode', 
            'this.activeInputIndex', 'tokenCategory', 'tokenAmount'
        }
        return any(k in self.code for k in covenant_keywords)

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
    
    def find_tautologies(self) -> List[Comparison]:
        """Find comparisons where left and right are identical"""
        tautologies = []
        for v in self.validations:
            for comp in v.comparisons:
                if comp.is_tautology:
                    tautologies.append(comp)
        return tautologies

    def find_locking_bytecode_self_comparisons(self) -> List[Comparison]:
        """Find cases where lockingBytecode is compared to itself"""
        violations = []
        for v in self.validations:
            for comp in v.comparisons:
                if 'lockingBytecode' in comp.left and comp.left == comp.right:
                    violations.append(comp)
        return violations

    def find_signature_reuse(self) -> List[CheckSigCall]:
        """Find reuse of same signature variable for different pubkeys in same function"""
        violations = []
        for func in self.functions:
            func_calls = [c for c in self.check_sig_calls if c.location.function == func]
            sig_map = {} # signature -> set of pubkeys
            for call in func_calls:
                if call.sig not in sig_map:
                    sig_map[call.sig] = set()
                sig_map[call.sig].add(call.pubkey)
            
            for sig, pubkeys in sig_map.items():
                if len(pubkeys) > 1:
                    # Find first call with this sig to report
                    violations.append([c for c in func_calls if c.sig == sig][0])
        return violations

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
            "is_escrow_like": self.is_escrow_like,
            "signature_reuse_count": len(self.find_signature_reuse())
        }

