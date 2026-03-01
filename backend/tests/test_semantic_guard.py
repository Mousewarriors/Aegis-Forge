import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from semantic_guard import SemanticGuard
from models import GuardrailMode

@pytest.mark.asyncio
async def test_evaluate_narrative_block():
    guard = SemanticGuard()
    # Mock Ollama response to simulate malicious intent
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "response": '{"risk_level": "BLOCKED", "categories": ["bypass"], "confidence": 0.9, "rationale": "Direct attempt to access /etc/shadow", "recommended_action": "terminate"}'
    }
    
    with patch('httpx.AsyncClient.post', return_value=mock_response):
        verdict = await guard.evaluate_narrative({"assistant_draft": "I will now read the shadow file"})
        assert verdict.risk_level == "BLOCKED"

@pytest.mark.asyncio
async def test_evaluate_tool_allowed():
    guard = SemanticGuard()
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "response": '{"risk_level": "ALLOWED", "categories": [], "confidence": 1.0, "rationale": "Safe probe", "recommended_action": "proceed"}'
    }
    
    with patch('httpx.AsyncClient.post', return_value=mock_response):
        verdict = await guard.evaluate_tool({"tool_call": {"name": "ls", "args": {"path": "/tmp"}}})
        assert verdict.risk_level == "ALLOWED"

@pytest.mark.asyncio
async def test_evaluate_narrative_fallback():
    guard = SemanticGuard()
    # Simulate malformed JSON or API error
    with patch('httpx.AsyncClient.post', side_effect=Exception("API Down")):
        verdict = await guard.evaluate_narrative({"assistant_draft": "harmless text"})
        # Should fallback to WARN
        assert verdict.risk_level == "WARN" 
        assert "error" in verdict.rationale.lower()
