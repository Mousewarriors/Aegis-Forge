# 🛡️ Aegis Forge: The Ultimate AI Security Research Sandbox

Aegis Forge is a hyper-secure, locally-hosted environment designed exclusively for testing, breaking, and hardening AI agents. By executing adversarial payloads inside isolated Docker containers, security researchers can safely evaluate Large Language Model (LLM) decision-making protocols against Prompt Injection, RBAC bypasses, and Data Exfiltration techniques without risking host system integrity.

## ✨ Core Capabilities

*   **Promptfoo Red Teaming Native Integration:** Run sophisticated, automated Red Team campaigns powered by local language models (Ollama). Aegis Forge invokes Promptfoo headlessly in the background, churning through thousands of payload permutations and returning the results to a beautiful Vulnerability Matrix on the frontend.
*   **Active Agent Hardening:** Intercept adversarial payloads dynamically with a contextual Semantic Guard LLM that sits in front of your tools. Toggle restrictions mid-flight and watch your agent refuse unsafe instructions before they reach the execution engine.
*   **eBPF SysWatch Kernel Telemetry:** True security cannot rely merely on Python-layer logging. Aegis Forge leverages `bpftrace` to monitor raw syscalls (like `execve` and `openat2`) exactly as they happen inside the container sandbox. It seamlessly degrades gracefully to containerized probes for WSL2/Windows hosts.
*   **Isolated Ephemeral Containers:** Every execution spawns an isolated, non-root Docker container stripped of network access (unless explicitly required). Once the payload concludes, the container is destroyed, leaving zero persistence footprint behind.

## ⚖️ Ethical Use & Scope
**IMPORTANT**: This application is strictly for **local research and testing** of AI agents in controlled environments.

- **Authorized Testing Only**: Only test agents within Docker sandboxes that you own and have explicit permission to evaluate.
- **Local Isolation**: All tests are conducted inside isolated Docker containers with **no network access** by default.
- **No External Targeting**: Do not use this tool to target external systems, public IPs, or third-party networks.
- **Controlled Payloads**: Payloads are designed to demonstrate internal safety failures, not to facilitate real-world attacks.

## 🚀 Quick Start
Please see the authoritative **[STARTUP.md](STARTUP.md)** for detailed instructions on launching the Backend FastAPI, the Next.js Frontend, Docker daemon requirements, and local Ollama setup.

## 🛠️ Architecture
- `main.py` & `models.py`: The FastAPI orchestration backbone.
- `policy_engine.py`: The deterministic tool-call guardrail system.
- `docker_manager.py`: Hardened container lifecycle management.
- `ebpf_monitor.py`: The SysWatch kernel tracepoint scanner.
- `promptfooconfig.yaml`: Customized local Red Team attack configurations.
