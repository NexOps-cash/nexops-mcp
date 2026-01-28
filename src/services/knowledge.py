import json
import os
from typing import List, Dict, Any
import logging

logger = logging.getLogger("nexops.knowledge")

class KnowledgeRetriever:
    def __init__(self, kb_path: str = "knowledge"):
        self.kb_path = kb_path
        self.security_rules = []
        self.patterns = {}
        self._load_knowledge()
    
    def _load_knowledge(self):
        """Load security rules and patterns from disk."""
        # Load security rules
        rules_file = os.path.join(self.kb_path, "security_rules.json")
        if os.path.exists(rules_file):
            try:
                with open(rules_file, 'r', encoding='utf-8') as f:
                    self.security_rules = json.load(f)
                logger.info(f"Loaded {len(self.security_rules)} security rules")
            except Exception as e:
                logger.warning(f"Failed to load security rules: {e}")
        
        # Load patterns
        patterns_dir = os.path.join(self.kb_path, "patterns")
        if os.path.exists(patterns_dir):
            for filename in os.listdir(patterns_dir):
                if filename.endswith(('.cash', '.md')):
                    pattern_path = os.path.join(patterns_dir, filename)
                    try:
                        with open(pattern_path, 'r', encoding='utf-8') as f:
                            pattern_name = filename.replace('.cash', '').replace('.md', '')
                            self.patterns[pattern_name] = f.read()
                    except Exception as e:
                        logger.warning(f"Failed to load pattern {filename}: {e}")
            logger.info(f"Loaded {len(self.patterns)} patterns")
    
    def get_security_rules(self, categories: List[str] = None, severity: str = None) -> str:
        """
        Retrieve security rules filtered by categories and/or severity.
        Returns formatted text suitable for injection into LLM prompts.
        """
        filtered_rules = self.security_rules
        
        if categories:
            filtered_rules = [r for r in filtered_rules if r.get('category') in categories]
        
        if severity:
            filtered_rules = [r for r in filtered_rules if r.get('severity') == severity]
        
        if not filtered_rules:
            return "No specific security rules found for this context."
        
        # Format rules for prompt injection
        formatted = "## Security Constraints\n\n"
        for rule in filtered_rules:
            formatted += f"**[{rule['id']}]** ({rule['severity'].upper()}): {rule['rule']}\n"
            formatted += f"  ↳ {rule['description']}\n\n"
        
        return formatted
    
    def get_patterns(self, keywords: List[str] = None) -> str:
        """
        Retrieve code patterns filtered by keywords.
        Returns formatted code snippets.
        """
        if not keywords:
            # Return all patterns if no filter
            all_patterns = "\n\n".join([f"### {name}\n```cashscript\n{code}\n```" 
                                       for name, code in self.patterns.items()])
            return f"## Code Patterns\n\n{all_patterns}" if all_patterns else ""
        
        # Simple keyword matching
        matched_patterns = {}
        for name, code in self.patterns.items():
            if any(kw.lower() in name.lower() or kw.lower() in code.lower() for kw in keywords):
                matched_patterns[name] = code
        
        if not matched_patterns:
            return ""
        
        formatted = "## Relevant Patterns\n\n"
        for name, code in matched_patterns.items():
            formatted += f"### {name}\n```cashscript\n{code}\n```\n\n"
        
        return formatted
    
    def get_context(self, categories: List[str] = None, keywords: List[str] = None) -> str:
        """
        Aggregate all relevant context (rules + patterns) for a given query.
        This is the primary method used by controllers.
        """
        context_parts = []
        
        # Add security rules
        rules = self.get_security_rules(categories=categories)
        if rules:
            context_parts.append(rules)
        
        # Add patterns
        patterns = self.get_patterns(keywords=keywords)
        if patterns:
            context_parts.append(patterns)
        
        return "\n\n".join(context_parts) if context_parts else "No additional context available."

# Singleton instance
_retriever_instance = None

def get_knowledge_retriever() -> KnowledgeRetriever:
    """Get or create the singleton KnowledgeRetriever instance."""
    global _retriever_instance
    if _retriever_instance is None:
        _retriever_instance = KnowledgeRetriever()
    return _retriever_instance
