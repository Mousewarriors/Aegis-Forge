import json
import httpx
import time
import asyncio

async def call_api(prompt, options, context):
    """
    Custom Provider API for Promptfoo to integrate with Aegis Forge.
    It targets the Agent mode, directly feeding the payload to the target agent
    to evaluate its guardrails and tool execution policies.
    """
    url = "http://localhost:8000/campaigns/run"
    
    # We simulate a "Credentials" category campaign, but the actual payload
    # is driven by Promptfoo's test cases.
    payload = {
        "name": f"Promptfoo Eval {int(time.time())}",
        "target_agent_type": "CLI Agent",
        "attack_category": "CREDENTIAL DISCOVERY",
        "mode": "REAL_AGENT", # Target the agent directly
        "max_turns": 1,
    }

    # Looking at main.py:
    # @app.post("/campaigns/run")
    # campaign: AttackCampaign
    # But wait, main.py gets the payload from payload_gen based on attack_category.
    # We need a way to send an arbitrary payload to the target agent for promptfoo.
    # Let's create a dedicated endpoint in main.py for raw prompt evaluation, or just use the agent_loop directly.
    # For now, let's assume we modify main.py to accept `custom_payload` in the AttackCampaign model.
    
    payload["custom_payload"] = prompt
    
    try:
        async with httpx.AsyncClient(timeout=60.0) as client:
            response = await client.post(url, json=payload)
            response.raise_for_status()
            data = response.json()
            
            # The agent mode returns a ScenarioRun. We need to extract the target's response.
            evidence = data.get("evidence", {})
            output = evidence.get("stdout", "") or evidence.get("stderr", "")
            
            # If the policy engine blocked it, it might just say "Policy Blocked..." in the output or stderr.
            # We return this output to promptfoo for evaluation against the assertions.
            return {"output": output}
            
    except httpx.HTTPStatusError as e:
        error_detail = e.response.text
        print(f"HTTP Error {e.response.status_code}: {error_detail}")
        return {"error": f"HTTP {e.response.status_code}: {error_detail}"}
    except Exception as e:
        return {"error": str(e)}

# Wrapper for synchronous execution if Promptfoo requires it
def call_api_sync(prompt, options, context):
    return asyncio.run(call_api(prompt, options, context))

if __name__ == "__main__":
    import sys
    # For testing the provider script directly
    prompt = "echo test" if len(sys.argv) < 2 else sys.argv[1]
    print(call_api_sync(prompt, {}, {}))
