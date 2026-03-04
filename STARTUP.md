## Aegis Forge: Quick Start Guide

This is the authoritative guide for starting the Aegis Forge environment.

### Automated Startup (Recommended)
From the repo root:

```powershell
.\startup.ps1
```

From inside `ai-pentest-researcher\aegis-forge`:

```powershell
.\startup.ps1
```

## Manual Startup

### 1. Prerequisites
- Docker Desktop must be running. WSL2 is required for SysWatch eBPF monitoring.
- Pull the bpftrace image once:

```powershell
docker pull quay.io/iovisor/bpftrace:latest
```

- Ollama must be running locally with `llama3.1:8b` available.
- Node.js 20+ must be installed on the host.

### 2. Start the Backend

```powershell
cd d:\Agent-Container-Pentester\ai-pentest-researcher\aegis-forge\backend
.\venv\Scripts\python.exe main.py
```

The backend auto-detects whether it is running on Windows or Linux and adjusts SysWatch monitoring accordingly.

### 3. Start the Frontend

```powershell
cd d:\Agent-Container-Pentester\ai-pentest-researcher\aegis-forge\frontend
npm run dev
```

### 4. Promptfoo Red Team Evaluations
Once the backend and frontend are running:

1. Open the Eval Matrix page in the UI.
2. Click `Launch Eval`.
3. The backend runs `promptfoo redteam run` locally against your Ollama instance.
4. You can toggle Agent Hardening mid-scan to update the agent system prompt during the run.

### 5. Service URLs
- App: `http://localhost:3000`
- Backend API: `http://localhost:8000`
- Ollama: `http://localhost:11434`
- Promptfoo UI: `http://localhost:15500`
- API docs: `http://localhost:8000/docs`
