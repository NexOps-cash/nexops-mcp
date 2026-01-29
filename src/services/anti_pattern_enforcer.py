"""
Anti-Pattern Enforcement System for NexOps MCP

This module implements the authoritative anti-pattern validation system.
Anti-patterns are absolute constraints - if any are violated, the contract is INVALID.

Key Principles:
1. Dynamic loading - scans knowledge/anti_pattern/ directory for documentation
2. Hard rejection - no fixes, no partial acceptance
3. Semantic detection - uses AST analysis, not string matching
4. Future-proof - automatically enforces new anti-patterns via detector registry

IMPORTANT: Anti-pattern .cash files are DOCUMENTATION ONLY.
Detection logic is in anti_pattern_detectors.py using semantic analysis.
"""

import os
import logging
from pathlib import Path
from typing import List, Dict, Any, Optional

from src.utils.cashscript_ast import CashScriptAST
from src.services.anti_pattern_detectors import DETECTOR_REGISTRY, Violation

logger = logging.getLogger(__name__)


class AntiPattern:
    """Represents a single anti-pattern loaded from a .cash file (documentation)"""
    
    def __init__(self, filename: str, content: str):
        self.id = filename  # e.g., "fee_assumption_violation.cash"
        self.filename = filename
        self.content = content
        self.type = "anti_pattern"
        self.severity = "critical"  # All anti-patterns are critical
        
        # Extract metadata from file content
        self._parse_metadata()
    
    def _parse_metadata(self):
        """Extract vulnerability description and attack vectors from file"""
        lines = self.content.split('\n')
        
        self.vulnerability = ""
        self.attack_vector = ""
        
        for line in lines[:20]:  # Check first 20 lines for metadata
            if line.startswith("// VULNERABILITY:"):
                self.vulnerability = line.replace("// VULNERABILITY:", "").strip()
            elif line.startswith("// ATTACK VECTOR:"):
                self.attack_vector = line.replace("// ATTACK VECTOR:", "").strip()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return {
            "id": self.id,
            "type": self.type,
            "severity": self.severity,
            "vulnerability": self.vulnerability,
            "attack_vector": self.attack_vector,
            "filename": self.filename
        }


class AntiPatternEnforcer:
    """
    Enforces anti-pattern constraints on generated/audited code.
    
    This is the negative type system of NexOps - it defines what must NEVER appear.
    
    Architecture:
    - Loads .cash files for documentation/context
    - Uses semantic detectors for actual enforcement
    - Separates detection (audit) from repair (future)
    """
    
    def __init__(self, kb_path: str = "knowledge"):
        self.kb_path = kb_path
        self.anti_patterns: List[AntiPattern] = []  # Documentation
        self.detectors = DETECTOR_REGISTRY  # Enforcement
        
        self._load_anti_pattern_docs()
    
    def _load_anti_pattern_docs(self):
        """
        Dynamically load ALL anti-pattern files from knowledge/anti_pattern/
        
        These files are DOCUMENTATION ONLY - they explain vulnerabilities.
        Actual detection is done by semantic detectors in anti_pattern_detectors.py
        """
        anti_pattern_dir = Path(self.kb_path) / "anti_pattern"
        
        if not anti_pattern_dir.exists():
            logger.warning(f"Anti-pattern directory not found: {anti_pattern_dir}")
            return
        
        # Scan for all .cash files
        pattern_files = list(anti_pattern_dir.glob("*.cash"))
        
        if not pattern_files:
            logger.warning(f"No anti-pattern files found in {anti_pattern_dir}")
            return
        
        logger.info(f"Loading {len(pattern_files)} anti-pattern documentation files...")
        
        for filepath in pattern_files:
            try:
                with open(filepath, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                anti_pattern = AntiPattern(
                    filename=filepath.name,
                    content=content
                )
                
                self.anti_patterns.append(anti_pattern)
                logger.info(f"Loaded anti-pattern docs: {anti_pattern.id}")
                
            except Exception as e:
                logger.error(f"Failed to load anti-pattern {filepath}: {e}")
        
        logger.info(f"Successfully loaded {len(self.anti_patterns)} anti-pattern docs")
        logger.info(f"Active detectors: {len(self.detectors)}")
    
    def get_all_anti_patterns(self) -> List[AntiPattern]:
        """Return all loaded anti-pattern documentation"""
        return self.anti_patterns
    
    def get_anti_pattern_context(self) -> str:
        """
        Generate context string for LLM prompts.
        
        This injects anti-pattern awareness into the LLM without embedding
        the full vulnerable code (which would be wasteful and dangerous).
        """
        if not self.anti_patterns:
            return ""
        
        context = "# CRITICAL ANTI-PATTERNS (ABSOLUTE CONSTRAINTS)\n\n"
        context += "The following patterns are FORBIDDEN and will cause HARD REJECTION:\n\n"
        
        for ap in self.anti_patterns:
            context += f"## {ap.id}\n"
            if ap.vulnerability:
                context += f"**Vulnerability:** {ap.vulnerability}\n"
            if ap.attack_vector:
                context += f"**Attack Vector:** {ap.attack_vector}\n"
            context += "\n"
        
        context += "\n**ENFORCEMENT RULE:**\n"
        context += "If generated code matches ANY anti-pattern, it will be REJECTED.\n"
        context += "No fixes, no partial acceptance, no pattern override.\n\n"
        
        return context
    
    def validate_code(self, code: str, stage: str = "generation") -> Dict[str, Any]:
        """
        Validate code against ALL anti-patterns using semantic detection.
        
        This is AUDIT mode - detection only, no fixes.
        
        Args:
            code: The CashScript code to validate
            stage: "generation" or "audit"
        
        Returns:
            {
                "valid": bool,
                "violated_rules": List[str],  # List of anti-pattern IDs
                "violations": List[Dict],     # Detailed violation info
                "stage": str
            }
        """
        violations = []
        
        # Parse code into AST for semantic analysis
        try:
            ast = CashScriptAST(code)
        except Exception as e:
            logger.error(f"Failed to parse code: {e}")
            return {
                "valid": False,
                "violated_rules": ["parse_error"],
                "violations": [{
                    "rule": "parse_error",
                    "reason": f"Failed to parse code: {e}",
                    "exploit": "Cannot validate unparseable code",
                    "location": {},
                    "severity": "critical"
                }],
                "stage": stage
            }
        
        # Run all semantic detectors
        for detector in self.detectors:
            try:
                violation = detector.detect(ast)
                if violation:
                    violations.append(violation.to_dict())
                    logger.warning(f"Anti-pattern detected: {violation.rule}")
            except Exception as e:
                logger.error(f"Detector {detector.id} failed: {e}")
        
        return {
            "valid": len(violations) == 0,
            "violated_rules": [v["rule"] for v in violations],
            "violations": violations,
            "stage": stage
        }


# Singleton instance
_enforcer_instance: Optional[AntiPatternEnforcer] = None


def get_anti_pattern_enforcer() -> AntiPatternEnforcer:
    """Get singleton instance of anti-pattern enforcer"""
    global _enforcer_instance
    if _enforcer_instance is None:
        _enforcer_instance = AntiPatternEnforcer()
    return _enforcer_instance
