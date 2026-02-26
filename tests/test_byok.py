import pytest
import json
from unittest.mock import AsyncMock, patch, MagicMock
from src.controllers.generator import GenerationController
from src.models import MCPRequest, ContractIR, IntentModel, TollGateResult, AuditRequest, RepairRequest, AuditIssue, Severity
from src.services.llm.factory import LLMFactory
from src.services.audit_agent import get_audit_agent
from src.services.repair_agent import get_repair_agent

@pytest.fixture
def anyio_backend():
    return 'asyncio'

@pytest.mark.anyio
async def test_byok_propagation_generate():
    """Verify api_key propagation in generation pipeline."""
    mock_provider = MagicMock()
    mock_provider.complete = AsyncMock(return_value="contract Test() { function test() { require(true); } }")
    
    with patch("src.services.llm.factory.LLMFactory.get_provider", return_value=mock_provider) as mock_get_provider:
        req = MCPRequest(
            request_id="test-gen",
            action="generate",
            payload={"user_request": "test", "session_id": "s1"},
            context={"api_key": "key123", "provider": "groq"}
        )
        with patch("src.services.pipeline.Phase1.run", new_callable=AsyncMock) as p1, \
             patch("src.services.pipeline.Phase2.run", new_callable=AsyncMock) as p2, \
             patch("src.services.pipeline_engine.Phase3.validate") as p3, \
             patch("src.services.pipeline_engine.get_sanity_checker") as sc:
            
            p1.return_value = ContractIR()
            p1.return_value.metadata.intent_model = IntentModel(contract_type="test")
            p2.return_value = "code"
            p3.return_value = TollGateResult(passed=True)
            sc.return_value.validate.return_value = {"success": True}
            
            controller = GenerationController()
            controller.session_mgr = MagicMock()
            await controller.generate(req)
            
            p1.assert_called_with("test", "high", api_key="key123", provider="groq")
            p2.assert_called()
            assert p2.call_args.kwargs["api_key"] == "key123"

@pytest.mark.anyio
async def test_byok_propagation_audit():
    """Verify api_key propagation in audit agent."""
    mock_provider = MagicMock()
    mock_provider.complete = AsyncMock(return_value='{"category": "none", "explanation": "ok", "confidence": 1.0, "business_logic_score": 10}')
    
    with patch("src.services.llm.factory.LLMFactory.get_provider", return_value=mock_provider) as mock_get_provider:
        from src.services.audit_agent import AuditAgent
        with patch("src.services.audit_agent.get_compiler_service") as c, \
             patch("src.services.audit_agent.get_dsl_linter") as l, \
             patch("src.services.audit_agent.Phase3.validate") as p3:
            c.return_value.compile.return_value = {"success": True}
            l.return_value.lint.return_value = {"passed": True}
            p3.return_value = TollGateResult(passed=True, structural_score=1.0)
            
            await AuditAgent.audit(code="pragma cashscript ^0.13.0; contract T(){}", api_key="audit-key", provider="openai")
            
            calls = [str(c) for c in mock_get_provider.call_args_list]
            found = any("'audit'" in c and "'audit-key'" in c and "'openai'" in c for c in calls)
            assert found, f"Audit call with keys not found. Calls: {calls}"

@pytest.mark.anyio
async def test_byok_propagation_repair():
    """Verify api_key propagation in repair agent."""
    mock_provider = MagicMock()
    mock_provider.complete = AsyncMock(return_value="fixed code")
    
    with patch("src.services.llm.factory.LLMFactory.get_provider", return_value=mock_provider) as mock_get_provider:
        agent = get_repair_agent()
        issue = AuditIssue(title="T", severity=Severity.HIGH, line=1, description="D", recommendation="R", rule_id="rule")
        req = RepairRequest(original_code="orig", issue=issue, context={"api_key": "repair-key", "provider": "openrouter"})
        
        await agent.repair(req)
        mock_get_provider.assert_any_call("repair", api_key="repair-key", provider_type="openrouter")

@pytest.mark.anyio
async def test_byok_propagation_fix_loop():
    """Verify api_key propagation in pipeline fix loop."""
    from src.services.pipeline_engine import GuardedPipelineEngine
    engine = GuardedPipelineEngine()
    
    mock_provider = MagicMock()
    mock_provider.complete = AsyncMock(return_value="fixed")
    
    with patch("src.services.llm.factory.LLMFactory.get_provider", return_value=mock_provider) as mock_get_provider:
        ir = ContractIR()
        await engine._request_syntax_fix(code="err", error_obj={"type": "ParseError"}, ir=ir, api_key="fix-key", provider="groq")
        mock_get_provider.assert_called_with("fix", api_key="fix-key", provider_type="groq")
