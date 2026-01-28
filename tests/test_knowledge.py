import pytest
import json
import os
import tempfile
import shutil
from src.services.knowledge import KnowledgeRetriever

@pytest.fixture
def temp_kb():
    """Create a temporary knowledge base for testing."""
    temp_dir = tempfile.mkdtemp()
    
    # Create security rules
    rules = [
        {
            "id": "SEC-001",
            "category": "defi",
            "severity": "critical",
            "rule": "Always validate signatures",
            "description": "Prevents unauthorized access"
        },
        {
            "id": "SEC-002",
            "category": "general",
            "severity": "warning",
            "rule": "Check for reentrancy",
            "description": "Prevents reentrancy attacks"
        }
    ]
    
    with open(os.path.join(temp_dir, "security_rules.json"), 'w') as f:
        json.dump(rules, f)
    
    # Create patterns directory
    patterns_dir = os.path.join(temp_dir, "patterns")
    os.makedirs(patterns_dir)
    
    with open(os.path.join(patterns_dir, "auth_check.cash"), 'w') as f:
        f.write("require(checkSig(sig, pubkey));")
    
    yield temp_dir
    
    # Cleanup
    shutil.rmtree(temp_dir)

def test_load_security_rules(temp_kb):
    retriever = KnowledgeRetriever(kb_path=temp_kb)
    assert len(retriever.security_rules) == 2
    assert retriever.security_rules[0]['id'] == 'SEC-001'

def test_get_security_rules_by_category(temp_kb):
    retriever = KnowledgeRetriever(kb_path=temp_kb)
    rules = retriever.get_security_rules(categories=['defi'])
    assert 'SEC-001' in rules
    assert 'SEC-002' not in rules

def test_get_security_rules_by_severity(temp_kb):
    retriever = KnowledgeRetriever(kb_path=temp_kb)
    rules = retriever.get_security_rules(severity='critical')
    assert 'SEC-001' in rules
    assert 'SEC-002' not in rules

def test_get_patterns(temp_kb):
    retriever = KnowledgeRetriever(kb_path=temp_kb)
    patterns = retriever.get_patterns(keywords=['auth'])
    assert 'auth_check' in patterns
    assert 'checkSig' in patterns

def test_get_context(temp_kb):
    retriever = KnowledgeRetriever(kb_path=temp_kb)
    context = retriever.get_context(categories=['defi'], keywords=['auth'])
    assert 'SEC-001' in context
    assert 'auth_check' in context
