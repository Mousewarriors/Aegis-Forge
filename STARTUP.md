# 🚀 Aegis Forge: Quick Start Guide

> **Note for Antigravity (future session):** Read the "Current Project State" section below before doing anything else to restore full context.

## 1. Prerequisites
- **Docker Desktop** must be running (WSL2 backend — confirmed working).
- `quay.io/iovisor/bpftrace:latest` must be pulled (already done: `docker pull quay.io/iovisor/bpftrace:latest`).

## 2. Start the Backend (Terminal 1)
```powershell
cd d:\Agent-Container-Pentester\ai-pentest-researcher\aegis-forge\backend
.\venv\Scripts\activate
python main.py
```

## 3. Start the Frontend (Terminal 2)
```powershell
cd d:\Agent-Container-Pentester\ai-pentest-researcher\aegis-forge\frontend
npm run dev
```

## 4. Access the App
- **Dashboard**: [http://localhost:3000](http://localhost:3000)
- **API Docs**: [http://localhost:8000/docs](http://localhost:8000/docs)

---

## 🧠 Current Project State (as of 2026-02-28)

### New Features Built This Session

#### 🕵️ Feature 1 — The Inquisitor (Multi-Turn Adversarial Agent)
A second LLM ("The Inquisitor") autonomously drives multi-turn prompt injection attacks, adapting strategy based on the target's responses.

**New files:**
- `backend/inquisitor.py` — The Inquisitor adversarial loop
- **Modified:** `backend/agent_loop.py` — added `run_iteration_with_history()`
- **Modified:** `backend/models.py` — `Mode.C (INQUISITOR)`, `InquisitorSession`, `InquisitorTurn`, `EscalationDecision`
- **Modified:** `backend/main.py` — new `POST /campaigns/inquisitor` endpoint
- **Modified:** `frontend/src/app/page.tsx` — INQUISITOR mode button + turn-log panel

**Requires:** Ollama running locally with `mistral:latest` for real LLM attacks.

#### 🔍 Feature 2 — SysWatch (eBPF Kernel Monitoring)
A bpftrace probe runs in a privileged container on the WSL2 kernel and watches every syscall from sandbox containers. Suspicious events (file access, shell exec, network) auto-trigger `FAIL`.

**New files:**
- `backend/ebpf_monitor.py` — SysWatchMonitor (auto-selects native/containerised/skip)
- `backend/probes/aegis.bt` — bpftrace probe script (supports `openat2` for WSL2)
- `backend/probes/smoke_test.bt` — verified smoke test script
- **Modified:** `backend/models.py` — `KernelEvent`, `SysWatchSession`, `evidence.kernel_events/kernel_alerts`
- **Modified:** `backend/monitor.py` — kernel-level FAIL override in `evaluate_outcome()`
- **Modified:** `backend/main.py` — SysWatch wraps every `/campaigns/run`
- **Modified:** `frontend/src/app/page.tsx` — amber SysWatch panel in campaign results

**SysWatch runs automatically on every campaign.** On Windows (Docker WSL2), it auto-uses the containerised mode (`quay.io/iovisor/bpftrace`). Mounting `/sys/kernel/debug` is required — this is done automatically in `ebpf_monitor.py`.

### What Still Needs Work / Next Steps
- **Test Inquisitor end-to-end** (requires Ollama + `mistral:latest` locally)
- **See real SysWatch kernel events** — needs a campaign where a command actually executes (not policy-blocked). Try `identity_verification` category which runs `whoami`.
- **Display SysWatch events in the scan/sweep results** (currently only shows in single campaign runs)
- **Add Inquisitor to the Audit Stream history** (currently only `ScenarioRun` appears in history, not `InquisitorSession`)

---
**Tip**: If starting a new session, tell Antigravity: **"Start the Aegis Forge project"** and it will use this file to restore full context.

## ⚙️ Current Defaults (updated 2026-02-28)
- **Inquisitor attacker model**: `llama3.1:8b` (switched from `mistral:latest`)
- **Target agent model**: `llama3.1:8b` (switched from `mistral:latest`)
- **Ollama must be running** with `llama3.1:8b` pulled.

## 🐛 Bug Fixes Applied This Session
- **Blocked tool calls now count as EXPLOIT_FOUND** (behavioral bypass, firewall just stopped it). Severity: HIGH.
- **Fuzzy signal parsing**: Inquisitor narrating around EXPLOIT_FOUND/FAILED now handled correctly.
- **Exploit severity scoring**: CRITICAL (allowed) / HIGH (blocked) / LOW (LLM-declared). Shown in UI.
- **Log truncation removed**: Full target responses now shown in the Inquisitor turn log.
- **Attack playbook expanded**: 20+ research-backed strategies (DAN, authority escalation, encoding, tool-call exploitation, multi-hop).
