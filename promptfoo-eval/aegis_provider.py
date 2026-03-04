import json
import os
import time
from urllib import error, request


def _extract_plugin_id(context):
    plugin_id = "PROMPTFOO EVAL"
    if context and isinstance(context, dict):
        vars_dict = context.get("vars", {})
        if "pluginId" in vars_dict:
            plugin_id = vars_dict["pluginId"]
        elif "test" in context and isinstance(context["test"], dict):
            metadata = context["test"].get("metadata", {})
            plugin_id = metadata.get("pluginId", plugin_id)
    return plugin_id


def call_api(prompt, options, context):
    """
    Custom Provider API for Promptfoo to integrate with Aegis Forge.
    Uses a plain stdlib HTTP request so it runs reliably inside Promptfoo's
    Python worker on Windows.
    """
    os.environ.pop("SSLKEYLOGFILE", None)
    url = "http://localhost:8000/campaigns/run"
    plugin_id = _extract_plugin_id(context)
    hardened_flag = os.getenv("AEGIS_PROMPTFOO_HARDENED")
    session_hardened = None
    if hardened_flag is not None:
        session_hardened = hardened_flag.strip().lower() in {"1", "true", "yes", "on"}
    proxy_flag = os.getenv("AEGIS_PROMPTFOO_PROXY_ENABLED")
    proxy_enabled = True
    if proxy_flag is not None:
        proxy_enabled = proxy_flag.strip().lower() in {"1", "true", "yes", "on"}
    promptfoo_run_id = os.getenv("AEGIS_PROMPTFOO_RUN_ID")
    payload = {
        "name": f"Promptfoo Eval {int(time.time())}",
        "target_agent_type": "CLI Agent",
        "attack_category": plugin_id.upper() if plugin_id else "PROMPTFOO EVAL",
        "mode": "REAL_AGENT",
        "max_turns": 1,
        "custom_payload": prompt,
        "record_in_audit_stream": False,
        "session_hardened": session_hardened,
        "proxy_enabled": proxy_enabled,
        "promptfoo_run_id": promptfoo_run_id,
        "promptfoo_plugin_id": plugin_id,
    }

    body = json.dumps(payload).encode("utf-8")
    req = request.Request(
        url,
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with request.urlopen(req, timeout=60) as response:
            data = json.loads(response.read().decode("utf-8"))
            evidence = data.get("evidence", {})
            output = evidence.get("stdout", "") or evidence.get("stderr", "")
            return {"output": output}
    except error.HTTPError as e:
        try:
            error_detail = e.read().decode("utf-8")
        except Exception:
            error_detail = str(e)
        print(f"HTTP Error {e.code}: {error_detail}")
        return {"error": f"HTTP {e.code}: {error_detail}"}
    except Exception as e:
        return {"error": str(e)}

def _report_failure_to_backend(plugin_id: str, prompt: str, output: str, reason: str):
    """
    Called when Promptfoo fails an assertion to let the backend know the agent was exploited.
    """
    # Note: Promptfoo runs the asserts AFTER the provider, so the provider script itself
    # can't easily push the result. Wait, `call_api` only returns the raw string which Promptfoo grades later.
    # To properly hook this, we'd need a custom Promptfoo assertion/grader, or a post-run parse script.
    pass

# Wrapper for synchronous execution if Promptfoo requires it
def call_api_sync(prompt, options, context):
    return call_api(prompt, options, context)

if __name__ == "__main__":
    import sys
    # For testing the provider script directly
    prompt = "echo test" if len(sys.argv) < 2 else sys.argv[1]
    print(call_api_sync(prompt, {}, {}))
