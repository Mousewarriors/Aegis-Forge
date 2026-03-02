# 🛡️ Aegis Forge: The Ultimate AI Security Research Sandbox

Aegis Forge is a hyper-secure, locally-hosted environment designed exclusively for **testing, breaking, and hardening AI agents**. By executing adversarial payloads inside isolated Docker containers, security researchers can safely evaluate Large Language Model (LLM) behavior against Prompt Injection, RBAC bypasses, and Data Exfiltration techniques without risking host system integrity.

---

## ⚡ Key Features

### 🎯 Automated Red Team Evaluation
Aegis Forge integrates **Promptfoo** headlessly as its core benchmarking engine. 
- **Dynamic Scans**: Trigger hundreds of adversarial permutations across categories like Shell Injection, Jailbreaking (Pliny), and Hijacking.
- **Premium Dashboard**: Visualize results in a real-time **Vulnerability Matrix** with shimmering progress bars and active evaluation HUDs.
- **Selective Attack Vectors**: Generate custom `promptfooconfig.yaml` profiles on-the-fly directly from the UI.

### 🛡️ Active Agent Hardening
Implement a **Defense-in-Depth** strategy using our contextual **Semantic Guard**.
- **Real-time Interception**: A "Guard" LLM analyzes incoming tool calls (e.g., `run_command`) and blocks them if they exhibit malicious intent.
- **Hot-swappable Policies**: Toggle hardening modes instantly and watch the agent's refusal rate spike as defenses come online.

### 📡 SysWatch: Kernel-Level Telemetry
Traditional logging is easily bypassed. Aegis Forge monitors the **Raw Syscall Stream** using eBPF (`bpftrace`).
- **Deep Visibility**: Track `execve`, `openat2`, and network socket calls directly at the kernel tracepoint.
- **Windows/WSL2 Support**: Automatically fall back to containerized probes inside Docker to maintain visibility on Windows hosts.

### 📦 Isolated Execution Environment
- Every campaign run spawns an **ephemeral, non-root Docker container**.
- **Ephemeral Volumes**: Sandbox file-system modifications using isolated named volumes that are purged upon completion.
- **No Network Access**: Containers are strictly isolated from the external internet by default.

---

## 🛠️ Tech Stack
- **Backend**: FastAPI (Python 3.10+)
- **Frontend**: Next.js 16 (React 19 + Framer Motion)
- **Engine**: Ollama (Llama 3.1 8B recommended)
- **Benchmarks**: Promptfoo CLI
- **Monitoring**: eBPF (bpftrace) + Docker API

---

## 🚀 Getting Started

### 1. Prerequisites
- **Docker Desktop** (with WSL2 backend if on Windows).
- **Ollama** installed and running locally.
- **Node.js 20+** installed.

### 2. Automated Setup (Recommended)
We've unified the environment initialization into a single script. Simply run:
```powershell
./startup.ps1
```
This script will:
1. Verify Docker and Ollama availability.
2. Pull required models (`llama3.1:8b`).
3. Spawn the Backend, Frontend, and Promptfoo viewer in the background.

### 3. Access the Dashboard
- **Main UI**: [http://localhost:3000](http://localhost:3000)
- **Red Team Matrix**: [http://localhost:3000/eval](http://localhost:3000/eval)
- **API Docs**: [http://localhost:8000/docs](http://localhost:8000/docs)
- **Promptfoo Viewer**: [http://localhost:15500](http://localhost:15500)

---

## 📂 Project Structure
- `backend/`: FastAPI source, policy engines, and Docker orchestrators.
- `frontend/`: Next.js dashboard and Red Team visualization.
- `promptfoo-eval/`: Evaluator configurations and adversarial providers.
- `workspace/`: The designated sandbox directory for agent file operations.
- `contracts/`: (Coming Soon) Formal definitions for agent tool permissions.

---

## ⚖️ Ethical Use & Scope
**Aegis Forge is unintended for malicious use.** It is a defensive tool meant to expose vulnerabilities in AI agent orchestration frameworks. 
- Only test systems you have explicit authorization to audit.
- Keep experimental payloads within the sandboxed `workspace/`.

---

## 👥 Contributors
- **Mousewarriors Team**

*This project is built for the future of secure AI agent orchestration.*
