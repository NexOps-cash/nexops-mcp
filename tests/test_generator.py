import pytest
from src.controllers.generator import generate_skeleton
from src.models import MCPRequest

@pytest.mark.asyncio
async def test_generate_skeleton_structure():
    req = MCPRequest(
        request_id="test-gen-1",
        action="generate",
        payload={"user_request": "Create a token contract"}
    )
    
    response = await generate_skeleton(req)
    
    assert response["request_id"] == "test-gen-1"
    assert response["type"] == "skeleton"
    data = response["data"]
    assert data["stage"] == "skeleton"
    assert "contract ExampleSkeleton" in data["code"]
    assert "Create a token contract" in data["code"]
