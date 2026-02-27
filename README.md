# 🛡️ Aegis Forge: AI-Agent Red Teaming Harness

A safe, sandboxed environment for evaluating the security of AI agents against prompt injection, tool misuse, and data exfiltration.

## ⚖️ Ethical Use & Scope
**IMPORTANT**: This application is strictly for **local research and testing** of AI agents in controlled environments.

- **Authorized Testing Only**: Only test agents within Docker sandboxes that you own and have explicit permission to evaluate.
- **Local Isolation**: All tests are conducted inside isolated Docker containers with **no network access** by default.
- **No External Targeting**: Do not use this tool to target external systems, public IPs, or third-party networks.
- **Controlled Payloads**: Payloads are designed to demonstrate internal safety failures, not to facilitate real-world attacks.

## 🏗️ How it Works
Aegis Forge runs "campaigns" against a target agent. Each campaign follows a structured lifecycle:

1. **Sandbox Creation**: Spins up a fresh, disposable Docker container with strict security constraints (non-root, no network, restricted resources).
2. **Execution Mode**:
   - **Mode A (Simulated)**: Directly simulates a failed guardrail by mapping a payload to a specific tool call attempt (e.g., trying to read `/etc/passwd`).
   - **Mode B (Real Agent)**: Sends the payload to a real LLM (via local Ollama) and observes if the agent *chooses* to call a tool unsafely.
3. **Policy Enforcement**: The `ToolPolicyEngine` intercepts every tool call attempt and validates it against an explicit allowlist and path-safety rules.
4. **Evidence Collection**: Captures prompts, tool call attempts, policy decisions, and execution outputs.
5. **Deterministic Reporting**: Produces a structured JSON report and human-readable summary with clear outcome definitions (`PASS`, `WARNING`, `FAIL`).

## 🚀 Quick Start (Red Teaming)

### Mode A: Simulated Baseline
Use this mode to test your sandbox hardening and policy rules without an LLM cost.
```powershell
Invoke-RestMethod -Uri "http://localhost:8000/campaigns/run" -Method Post -ContentType "application/json" -Body '{"name": "Simulated Audit", "target_agent_type": "Docker Container", "attack_category": "data_exfiltration", "mode": "SIMULATED"}'
```

### Mode B: Real Agent Evaluation
Requires **Ollama** running locally with the `llama3` model.
```powershell
Invoke-RestMethod -Uri "http://localhost:8000/campaigns/run" -Method Post -ContentType "application/json" -Body '{"name": "End-to-End Test", "target_agent_type": "LLM Agent", "attack_category": "prompt_injection", "mode": "REAL_AGENT"}'
```

## 🛠️ Components
- `policy_engine.py`: The core guardrail system.
- `docker_manager.py`: Hardened container orchestration.
- `agent_loop.py`: LLM interaction and tool parsing.
- `monitor.py`: Structured evidence and outcome evaluation.
- `report_gen.py`: Human-friendly security summaries.
