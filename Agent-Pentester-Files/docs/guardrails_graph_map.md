# Aegis Forge: Guardrails & Graph Map

This document maps the architectural hook points for the Semantic Guardrails and Attack Graph Visualizer.

## 1. Trace Interaction Loops

### Narrative Generation Loop
- **File**: `backend/agent_loop.py`
- **Method**: `AgentLoop.run_iteration_with_history(self, history)`
- **Entrance**: Ollama API `httpx.post` returns response text.
- **Hook Point**: After `json_str = match.group(0)` and before returning.
- **Purpose**: Intercept assistant reasoning before it is processed or returned.

### Tool Execution Flow
- **File**: `backend/policy_engine.py`
- **Method**: `ToolPolicyEngine.validate_tool_call(self, tool_name, args)`
- **Entrance**: Called from `main.py` or `inquisitor.py`.
- **Hook Point**: After syntactic validation and path/canary checks, but before returning `True`.
- **Purpose**: Verify tool intent using semantic judging.

## 2. Telemetry & Audit Stream

### Audit Emission
- **File**: `backend/monitor.py`
- **Class**: `CampaignMonitor`
- **Emit Points**: `record_scenario` and `record_inquisitor_session`.
- **Consumption**: `main.py` exposes `GET /stats`, which mirrors `monitor.campaign_history`.

### Frontend Consumption
- **File**: `frontend/src/app/page.tsx`
- **Method**: `fetchStats()` (Interval polling every 5s).
- **Data Shape**: Array of `campaign_history` objects.

## 3. Configuration & State

### Campaign Configuration
- **File**: `backend/models.py`
- **Classes**: `AttackCampaign`, `ScenarioRun`.
- **State**: `WorkspaceMode`, `Outcome`, `Evidence`.

### Kernel Telemetry (SysWatch)
- **File**: `backend/ebpf_monitor.py`
- **Class**: `SysWatchMonitor`
- **Hook**: `stop_and_collect` returns `KernelEvent` objects.

## 4. Proposed Call Flow (Semantic Gating)

1. **User Request** -> `Inquisitor` or `Main API`
2. **Target Agent** -> Calls Ollama -> Returns Draft
3. **Narrative Gate** -> `SemanticGuard.evaluate_narrative` -> Result (ALLOW/WARN/BLOCK)
4. **Tool Proposal** (if any) -> `PolicyEngine.validate_tool_call`
5. **Tool Gate** -> `SemanticGuard.evaluate_tool` -> Result (ALLOW/WARN/BLOCK)
6. **Execution** (if allowed) -> `DockerOrchestrator`
7. **Telemetry** -> `Monitor.record_event` (verdicts, "would-have" nodes)
8. **Frontend** -> Polls `/stats` -> Rebuilds Attack Graph
