import pytest

from agent_loop import AgentLoop
from models import AttackCampaign, GuardrailMode, SemanticVerdict
from policy_engine import SecurityProxy, policy_engine


@pytest.mark.asyncio
async def test_process_interaction_resets_stale_verdicts_and_records_compliance():
    proxy = SecurityProxy()
    proxy.set_context({"guardrail_mode": GuardrailMode.BLOCK})
    proxy.context["last_input_verdict"] = {"risk_level": "STALE"}
    proxy.context["last_narrative_verdict"] = {"risk_level": "STALE"}

    async def fake_input_policy(user_text, history):
        proxy.context["last_input_verdict"] = {"risk_level": "ALLOW", "rationale": "Fresh input"}
        return user_text, False, "OK"

    async def fake_llm(_history):
        return "safe draft", None

    async def fake_output_policy(draft_text, history):
        proxy.context["last_narrative_verdict"] = {"risk_level": "ALLOW", "rationale": "Fresh output"}
        return True, draft_text, "OK"

    async def fake_verify_compliance(_audit_packet):
        return SemanticVerdict.model_validate({
            "pass": False,
            "score": 1.0,
            "risk_level": "ALLOW",
            "categories": [],
            "confidence": 1.0,
            "rationale": "Compliant",
            "recommended_action": "allow",
        })

    proxy.enforce_input_policy_async = fake_input_policy
    proxy.enforce_output_policy = fake_output_policy
    proxy.verify_compliance = fake_verify_compliance

    response, tool_call, reason = await proxy.process_interaction(
        "hello",
        [{"role": "user", "content": "hello"}],
        fake_llm,
    )

    assert response == "safe draft"
    assert tool_call is None
    assert reason == "OK"
    assert proxy.context["last_input_verdict"]["rationale"] == "Fresh input"
    assert proxy.context["last_narrative_verdict"]["rationale"] == "Fresh output"
    assert proxy.context["last_compliance_verdict"]["rationale"] == "Compliant"


@pytest.mark.asyncio
async def test_process_interaction_compliance_block_uses_clean_refusal():
    proxy = SecurityProxy()
    proxy.set_context({"guardrail_mode": GuardrailMode.BLOCK})

    async def fake_input_policy(user_text, history):
        return user_text, False, "OK"

    async def fake_llm(_history):
        return "safe draft", None

    async def fake_output_policy(draft_text, history):
        return True, draft_text, "OK"

    async def fake_verify_compliance(_audit_packet):
        return SemanticVerdict.model_validate(
            {
                "pass": False,
                "score": 1.0,
                "risk_level": "CRITICAL",
                "categories": ["Political Content Request"],
                "confidence": 1.0,
                "rationale": "Potential policy violation.",
                "recommended_action": "refuse",
            }
        )

    proxy.enforce_input_policy_async = fake_input_policy
    proxy.enforce_output_policy = fake_output_policy
    proxy.verify_compliance = fake_verify_compliance

    response, tool_call, reason = await proxy.process_interaction(
        "hello",
        [{"role": "user", "content": "hello"}],
        fake_llm,
    )

    assert response == "I cannot fulfill this request due to security protocols."
    assert tool_call is None
    assert reason == "Audit Block: Political persuasion request detected."


@pytest.mark.asyncio
async def test_agent_loop_surfaces_all_semantic_guard_verdicts(monkeypatch):
    async def fake_process_interaction(user_input, history, llm_caller_func):
        policy_engine.context["last_input_verdict"] = {"risk_level": "WARN", "rationale": "Input flagged"}
        policy_engine.context["last_narrative_verdict"] = {"risk_level": "ALLOW", "rationale": "Narrative safe"}
        policy_engine.context["last_role_verdict"] = {"risk_level": "ALLOW", "rationale": "Role safe"}
        policy_engine.context["last_compliance_verdict"] = {"risk_level": "ALLOW", "rationale": "Audited"}
        return "Refused safely.", None, "OK"

    monkeypatch.setattr(policy_engine, "process_interaction", fake_process_interaction)

    loop = AgentLoop()
    evidence, tool_call = await loop.run_iteration(
        "test prompt",
        campaign=AttackCampaign(guardrail_mode=GuardrailMode.BLOCK),
    )

    assert tool_call is None
    assert evidence.stdout == "Refused safely."
    assert [verdict["rationale"] for verdict in evidence.semantic_verdicts] == [
        "Input flagged",
        "Narrative safe",
        "Role safe",
        "Audited",
    ]


@pytest.mark.asyncio
async def test_agent_loop_can_bypass_proxy(monkeypatch):
    async def fail_if_called(user_input, history, llm_caller_func):
        raise AssertionError("Proxy should be bypassed when proxy_enabled is false")

    class FakeResponse:
        status_code = 200

        @staticmethod
        def json():
            return {"response": "Direct model output"}

    class FakeClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        async def post(self, *args, **kwargs):
            return FakeResponse()

    monkeypatch.setattr(policy_engine, "process_interaction", fail_if_called)
    monkeypatch.setattr("agent_loop.httpx.AsyncClient", lambda timeout=30.0: FakeClient())

    loop = AgentLoop()
    evidence, tool_call = await loop.run_iteration(
        "test prompt",
        campaign=AttackCampaign(proxy_enabled=False),
    )

    assert tool_call is None
    assert evidence.stdout == "Direct model output"
    assert evidence.semantic_verdicts == []
