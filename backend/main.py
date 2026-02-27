from fastapi import FastAPI, HTTPException, Body
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
import uuid
import time
import os
from typing import List, Optional, Dict, Any

from docker_manager import orchestrator
from payload_gen import payload_gen
from monitor import monitor
from policy_engine import policy_engine
from agent_loop import agent_loop
from report_gen import report_gen
from models import AttackCampaign, ScenarioRun, Evidence, Outcome, Mode, FullReport

app = FastAPI(title="Aegis Forge: Red Teaming Harness")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/health")
async def health():
    return {"status": "healthy", "timestamp": time.time()}

@app.get("/categories")
async def get_categories():
    return payload_gen.get_all_categories()

@app.get("/payloads/preview/{category}")
async def get_payload_preview(category: str):
    payload = payload_gen.get_random_payload(category)
    if not payload or payload.get("id") == "NONE":
        raise HTTPException(status_code=404, detail="Category not found")
    return payload

@app.post("/campaigns/run")
async def run_campaign(campaign: AttackCampaign = Body(...)):
    """
    Run a single campaign test against the sandbox.
    Mode A: Uses the shell_cmd from payloads.json directly.
    Mode B: Sends payload to a real Ollama agent and executes whatever it decides.
    """
    # 1. Get Payload - uses shell_cmd field for reliable execution
    payload_info = payload_gen.get_random_payload(campaign.attack_category)
    if not payload_info or payload_info.get("id") == "NONE":
        raise HTTPException(status_code=404, detail=f"No payloads for category: {campaign.attack_category}")

    # 2. Setup Container with workspace mounted (read-only)
    workspace_abs = os.path.abspath("../workspace")
    container = orchestrator.create_vulnerable_agent_container(workspace_path=workspace_abs)
    if not container:
        raise HTTPException(status_code=500, detail="Failed to create sandbox container")

    evidence = Evidence(input_prompt=payload_info["payload"])
    outcome = Outcome.WARNING
    tool_denied = False

    try:
        if campaign.mode == Mode.A:
            # Mode A: Direct Simulation — use the shell_cmd from payloads.json
            shell_cmd = payload_info.get("shell_cmd", "whoami")
            tool_name = "run_command"
            args = {"cmd": shell_cmd}
            evidence.tool_calls_attempted.append({"tool": tool_name, "args": args})

            # Policy Check
            is_allowed, reason = policy_engine.validate_tool_call(tool_name, args)
            if is_allowed:
                exec_result = orchestrator.execute_payload(container.id, shell_cmd)
                evidence.stdout = exec_result.get("output", "")
                evidence.stderr = exec_result.get("error", "")
            else:
                evidence.sensitive_events.append(f"Policy Blocked: {reason}")
                tool_denied = True

        else:
            # Mode B: Real Agent (Ollama)
            agent_evidence, tool_call = await agent_loop.run_iteration(payload_info["payload"])
            evidence = agent_evidence

            if tool_call:
                tool_name = tool_call.get("tool")
                args = tool_call.get("args", {})

                is_allowed, reason = policy_engine.validate_tool_call(tool_name, args)
                if is_allowed:
                    payload_cmd = args.get("cmd") or args.get("path") or args.get("content")
                    exec_result = orchestrator.execute_payload(container.id, payload_cmd)
                    evidence.stdout = exec_result.get("output", "")
                    evidence.tool_calls_results.append({"tool": tool_name, "result": exec_result})
                else:
                    evidence.sensitive_events.append(f"Policy Blocked: {reason}")
                    tool_denied = True

        # 3. Evaluate Outcome
        outcome = monitor.evaluate_outcome(
            campaign.attack_category,
            {"output": evidence.stdout, "exit_code": 0},
            payload_info,
            tool_denied
        )

        run = ScenarioRun(
            id=str(uuid.uuid4()),
            mode=campaign.mode,
            category=campaign.attack_category,
            payload_id=payload_info["id"],
            container_id=container.id,
            outcome=outcome,
            evidence=evidence
        )

        monitor.record_scenario(run)
        return run

    finally:
        orchestrator.cleanup_container(container.id)


@app.get("/reports/summary")
async def get_summary():
    stats = monitor.get_summary()
    report = report_gen.generate_full_report(stats["campaign_history"])
    return report


@app.get("/stats")
async def get_stats():
    stats = monitor.get_summary()
    return {
        "total_attacks": stats["total_runs"],
        "successful_exploits": stats["fail_count"],
        "failed_attempts": stats["pass_count"],
        "campaign_history": [
            {
                "timestamp": r["timestamp"],
                "campaign": f"{r['mode']} - {r['payload_id']}",
                "category": r["category"],
                "success": r["outcome"] == Outcome.FAIL,
                "input_payload": r["evidence"].get("input_prompt", ""),
                "output_snippet": (
                    r["evidence"]["stdout"][:200]
                    if r["evidence"].get("stdout")
                    else (r["evidence"].get("sensitive_events") or [""])[0][:200]
                ),
                "full_run": r
            } for r in stats["campaign_history"]
        ]
    }


@app.get("/scans/available")
async def get_available_scans():
    return [
        {"id": "full-sweep", "name": "Full Library Sweep (All Vectors)", "engine": "internal"},
        {"id": "quick-sweep", "name": "Quick Sweep (1 per category)", "engine": "internal"},
    ]


@app.post("/scans/run")
async def run_automated_scan(scan_type: str = Body(..., embed=True)):
    """
    Automated sweep of the attack library.
    Every payload gets its own isolated container, real policy check, and real sandbox execution.
    Results are piped live into the Audit Stream.
    """
    all_categories = payload_gen.get_all_categories()
    results = []
    workspace_abs = os.path.abspath("../workspace")

    if scan_type == "quick-sweep":
        # One random payload per category
        payloads_to_run = []
        for cat in all_categories:
            p = payload_gen.get_random_payload(cat)
            if p and p.get("id") != "NONE":
                payloads_to_run.append((cat, p))
    else:
        # Full scan: every single payload in the library
        payloads_to_run = []
        for cat in all_categories:
            for p in payload_gen.get_all_payloads_for_category(cat):
                payloads_to_run.append((cat, p))

    for cat, payload_info in payloads_to_run:
        container = orchestrator.create_vulnerable_agent_container(workspace_path=workspace_abs)
        if not container:
            continue
        try:
            shell_cmd = payload_info.get("shell_cmd", "whoami")
            tool_name = "run_command"
            args = {"cmd": shell_cmd}

            evidence = Evidence(input_prompt=payload_info["payload"])
            evidence.tool_calls_attempted.append({"tool": tool_name, "args": args})

            is_allowed, reason = policy_engine.validate_tool_call(tool_name, args)
            if is_allowed:
                exec_result = orchestrator.execute_payload(container.id, shell_cmd)
                evidence.stdout = exec_result.get("output", "")
                evidence.stderr = exec_result.get("error", "")
                tool_denied = False
            else:
                evidence.sensitive_events.append(f"Policy Blocked: {reason}")
                tool_denied = True

            outcome = monitor.evaluate_outcome(
                cat,
                {"output": evidence.stdout, "exit_code": 0},
                payload_info,
                tool_denied
            )

            run = ScenarioRun(
                id=str(uuid.uuid4()),
                mode=Mode.A,
                category=cat,
                payload_id=payload_info["id"],
                container_id=container.id,
                outcome=outcome,
                evidence=evidence
            )
            monitor.record_scenario(run)
            if outcome == Outcome.FAIL:
                results.append(run)

            # Brief delay so containers are visible in docker ps during scan
            time.sleep(1)

        finally:
            orchestrator.cleanup_container(container.id)

    return {
        "status": "success",
        "message": f"Scan complete. {len(payloads_to_run)} payloads run across isolated sandboxes.",
        "results_summary": {
            "total_prompts": len(payloads_to_run),
            "vulnerabilities_found": len(results),
            "risk_score": "Critical" if len(results) > 5 else "High" if len(results) > 0 else "Low"
        }
    }


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
