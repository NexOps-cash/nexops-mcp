import json
import os
from typing import List, Dict, Any, Optional
import logging
from pathlib import Path

logger = logging.getLogger("nexops.knowledge")

class KnowledgeRetriever:
    """
    Authoritative Knowledge Retrieval Layer for NexOps MCP.
    
    Dynamically loads and serves:
    - Security Rules (JSON)
    - Anti-Patterns (Documentation)
    - Code Patterns (Secure snippets)
    - Contract Templates (Reference implementations)
    - Mistake Patterns (Known pitfalls)
    - Multi-Contract Patterns (Interaction models)
    """
    
    def __init__(self, kb_path: str = "knowledge"):
        self.kb_path = Path(kb_path)
        self.security_rules: List[Dict[str, Any]] = []
        self.categories: Dict[str, Dict[str, str]] = {
            "patterns": {},       # core/patterns
            "primitives": {},     # core/primitives
            "templates": {},      # core/templates
            "anti_pattern": {},   # core/anti_pattern
            "mistakes": {},       # core/mistakes
            "multi_contract": {}  # core/multi_contract
        }
        self._load_knowledge()
    
    def _load_knowledge(self):
        """Load security rules and all categorized patterns from disk."""
        # 1. Load security rules
        rules_file = self.kb_path / "security_rules.json"
        if rules_file.exists():
            try:
                with open(rules_file, 'r', encoding='utf-8') as f:
                    self.security_rules = json.load(f)
                logger.info(f"Loaded {len(self.security_rules)} security rules")
            except Exception as e:
                logger.warning(f"Failed to load security rules: {e}")
        
        # 2. Load patterns from all known subdirectories
        for category in self.categories.keys():
            category_dir = self.kb_path / category
            if category_dir.exists():
                count = 0
                for filepath in category_dir.glob("*"):
                    if filepath.suffix in ('.cash', '.md'):
                        try:
                            with open(filepath, 'r', encoding='utf-8') as f:
                                name = filepath.stem
                                self.categories[category][name] = f.read()
                                count += 1
                        except Exception as e:
                            logger.warning(f"Failed to load {category} {filepath.name}: {e}")
                logger.info(f"Loaded {count} items for category: {category}")
    
    def get_security_rules(self, categories: Optional[List[str]] = None, severity: Optional[str] = None) -> str:
        """
        Retrieve security rules filtered by categories and/or severity.
        """
        filtered_rules = self.security_rules
        
        if categories:
            filtered_rules = [r for r in filtered_rules if r.get('category') in categories]
        
        if severity:
            filtered_rules = [r for r in filtered_rules if r.get('severity') == severity]
        
        if not filtered_rules:
            return ""
        
        # Format rules for prompt injection
        formatted = "# SECURITY CONSTRAINTS\n\n"
        for rule in filtered_rules:
            formatted += f"### [{rule['id']}] {rule['rule']}\n"
            formatted += f"  ↳ Severity: {rule['severity'].upper()}\n"
            formatted += f"  ↳ {rule['description']}\n\n"
        
        return formatted
    
    def get_category_content(self, category: str, keywords: Optional[List[str]] = None) -> str:
        """
        Retrieve content from a specific category, optionally filtered by keywords.
        """
        if category not in self.categories:
            return ""
        
        items = self.categories[category]
        if not items:
            return ""
        
        matched_items = {}
        if not keywords:
            matched_items = items
        else:
            for name, content in items.items():
                if any(kw.lower() in name.lower() or kw.lower() in content.lower() for kw in keywords):
                    matched_items[name] = content
        
        if not matched_items:
            return ""
        
        header = category.replace('_', ' ').upper()
        formatted = f"# {header}\n\n"
        for name, content in matched_items.items():
            formatted += f"## {name}\n"
            # Detect if it's CashScript or MD
            if "//" in content or "pragma" in content:
                formatted += f"```cashscript\n{content}\n```\n\n"
            else:
                formatted += f"{content}\n\n"
        
        return formatted

    def get_context(self, categories: Optional[List[str]] = None, keywords: Optional[List[str]] = None) -> str:
        """
        Aggregate ALL relevant context for LLM code generation.
        
        Filters security rules, patterns, templates, and anti-patterns 
        to provide a focused context for the current task.
        """
        context_parts = []
        
        # 1. Add relevant security rules
        rules = self.get_security_rules(categories=categories)
        if rules:
            context_parts.append(rules)
        
        # 2. Add relevant Anti-Patterns (CRITICAL - ALWAYS INJECT MINIMAL CONTEXT)
        # We don't inject the full code to save tokens, just descriptions if keywords match
        anti_patterns = self.get_category_content("anti_pattern", keywords=keywords)
        if anti_patterns:
            context_parts.append(anti_patterns)
        
        # 3. Add relevant code patterns
        patterns = self.get_category_content("patterns", keywords=keywords)
        if patterns:
            context_parts.append(patterns)
            
        # 4. Add relevant templates
        templates = self.get_category_content("templates", keywords=keywords)
        if templates:
            context_parts.append(templates)
            
        # 5. Add common mistakes
        mistakes = self.get_category_content("mistakes", keywords=keywords)
        if mistakes:
            context_parts.append(mistakes)

        return "\n\n".join(context_parts) if context_parts else "No specific context available."

# Singleton
_retriever_instance = None

def get_knowledge_retriever() -> KnowledgeRetriever:
    """Get the singleton KnowledgeRetriever instance."""
    global _retriever_instance
    if _retriever_instance is None:
        _retriever_instance = KnowledgeRetriever()
    return _retriever_instance
