import pytest
from src.router import route_request
from src.models import MCPRequest

@pytest.mark.asyncio
async def test_route_generate_action():
    request = {
        "request_id": "test-1",
        "action": "generate",
        "payload": {"user_request": "Create a DAO"}
    }
    response = await route_request(request)
    
    assert response["request_id"] == "test-1"
    assert response["type"] == "skeleton"
    assert "code" in response["data"]

@pytest.mark.asyncio
async def test_route_unknown_action():
    request = {
        "request_id": "test-2",
        "action": "unknown_action",
        "payload": {}
    }
    response = await route_request(request)
    
    assert response["request_id"] == "test-2"
    assert response["type"] == "error"
    assert response["error"]["code"] == "UNKNOWN_ACTION"

@pytest.mark.asyncio
async def test_route_invalid_payload():
    # Missing 'action' field or other validation errors
    request = {
        "request_id": "test-3",
        # action missing
        "payload": {}
    }
    response = await route_request(request)
    
    assert response["type"] == "error"
    assert response["error"]["code"] == "INTERNAL_ERROR"
