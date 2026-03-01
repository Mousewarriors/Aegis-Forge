## 🚀 Aegis Forge: Quick Start Guide

This is the **authoritative** guide for starting the Aegis Forge environment. Follow these steps in order.

## 1. Prerequisites
- **Docker Desktop** must be running (**WSL2 backend** required for SysWatch eBPF monitoring).
- `quay.io/iovisor/bpftrace:latest` must be pulled:
  ```powershell
  docker pull quay.io/iovisor/bpftrace:latest
  ```
- **Ollama** must be running locally with `llama3.1:8b` pulled.
- **Node.js 20+** installed on the host.

## 2. Start the Backend (Terminal 1)
```powershell
cd d:\Agent-Container-Pentester\ai-pentest-researcher\aegis-forge\backend
# Ensure virtualenv is active
.\venv\Scripts\activate
python main.py
```
> [!NOTE]
> The backend automatically detects if it's running in Windows or Linux (WSL2) to coordinate SysWatch containerized probes.

## 3. Start the Frontend (Terminal 2)
```powershell
cd d:\Agent-Container-Pentester\ai-pentest-researcher\aegis-forge\frontend
npx next dev -p 3000 --hostname 0.0.0.0
```

## 4. Run Red Team Evaluations (Promptfoo)
Once the servers are running, you can trigger advanced algorithmic scans:
1. Navigate to the **Eval Matrix** page in the UI.
2. Click **Launch Eval**.
3. The backend will invoke `npx promptfoo redteam run` locally using your Ollama instance.
4. **Agent Hardening:** You can toggle the "Agent Hardening" switch mid-scan to instantly update the agent's system prompt and watch the live execution block incoming adversarial payloads.

## 5. Access Summary
- **Main Dashboard**: [http://localhost:3000](http://localhost:3000)
- **Red Team Eval Matrix**: [http://localhost:3000/eval](http://localhost:3000/eval)
- **API Documentation**: [http://localhost:8000/docs](http://localhost:8000/docs)

---

## 🧠 Current Project State (2026-03-01)

### Core Integration — Promptfoo
Integrated Promptfoo as a native bencharking suite. The backend (FastAPI) manages `promptfoo` subprocesses, while the frontend provides a real-time vulnerability matrix visualization.

### SysWatch — Kernel Monitoring
Enabled eBPF-based syscall monitoring for agent containers. When running on Windows, the system automatically falls back to a **containerized bpftrace probe** inside Docker (WSL2) to maintain visibility into the sandboxed kernel.

### Semantic Guardrails
Layered defense using a "Guard" LLM to intercept and block adversarial intent in real-time.
- `BLOCK` mode is now the default for high-security scenarios.

