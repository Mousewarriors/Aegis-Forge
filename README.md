# Aegis Forge

Aegis Forge is a local AI red-teaming and hardening workbench for testing agentic systems behind a defended execution boundary.

It combines:

- a FastAPI backend that runs campaigns, enforces guardrails, and orchestrates sandboxes
- a Next.js frontend for live audit, eval control, and reporting
- multiple evaluator paths:
  - Promptfoo for regression-style red teaming and policy checks
  - Garak for broad probe-based vulnerability scanning
  - PyRIT for orchestrated attack mutation and refusal testing

The project is built for iterative security work: launch a scan, see exactly what ran, review blocked or vulnerable responses, tighten defenses, and run again.

## What It Does

Aegis Forge gives you one place to:

- run adversarial campaigns against a defended local agent
- compare Promptfoo, Garak, and PyRIT in the same dashboard
- inspect live attack attempts, transcripts, and evaluator events
- retain reports and logs after completion or stop
- harden the target agent and immediately re-test it
- observe execution behavior through audit history and kernel-oriented telemetry

## Current Evaluator Model

### Promptfoo

Best for:

- policy and regression checks
- curated red-team vectors
- structured pass or fail reporting

### Garak

Best for:

- breadth scanning across concrete probe classes
- probe-family expansion and quick smoke runs
- fast feedback on blocked versus vulnerable responses

### PyRIT

Best for:

- mutated or transformed attack execution
- scenario-based refusal testing
- richer orchestration as the integration expands

The current PyRIT integration already supports transformed preview samples, retained logs, and official report generation. The broader roadmap for full PyRIT exposure is documented in [docs/pyrit_full_integration_spec.md](docs/pyrit_full_integration_spec.md).

## Architecture

### Backend

Path: `backend/`

Responsibilities:

- campaign execution
- evaluator orchestration
- Docker sandbox management
- semantic and policy enforcement
- audit feed aggregation
- report and log retention

Core stack:

- Python
- FastAPI
- Docker SDK
- local Ollama integration

### Frontend

Path: `frontend/`

Responsibilities:

- evaluator control surfaces
- live audit stream
- vulnerability matrix
- flagged findings view
- evaluator-specific preview and reporting UX

Core stack:

- Next.js 16
- React 19
- Framer Motion

### Evaluator Runtimes

- `promptfoo-eval/`
- `garak-eval/`
- `pyrit-eval/`

These directories hold evaluator-specific assets, generated configs, and runtime wrappers.

## Key Capabilities

- Local defended target execution through the Aegis backend
- Promptfoo, Garak, and PyRIT launch paths under a unified `/eval` model
- Full retained logs for completed and stopped eval runs
- Live attack preview and provisional reporting during execution
- Vulnerability matrix plus consolidated flagged findings
- PyRIT transformed prompt preview and richer event stream
- Garak concrete probe selection and prompt caps for quick scans
- Agent hardening toggle for fix-and-retest workflows
- Docker-isolated execution for agent actions

## Prerequisites

- Docker Desktop
- Ollama with `llama3.1:8b` available locally
- Node.js 20+
- Windows PowerShell for the current startup workflow

Notes:

- The repo is currently optimized around local Windows development with Docker Desktop and Ollama.
- Some monitoring features depend on environment support and may degrade gracefully.

## Quick Start

From the repo root:

```powershell
.\startup.ps1
```

The startup script will:

1. verify Docker
2. verify Ollama and pull `llama3.1:8b` if needed
3. stop old Aegis service instances
4. start backend, frontend, and Promptfoo viewer
5. wait for the services to become ready

### Service URLs

- App: `http://localhost:3000`
- Eval dashboard: `http://localhost:3000/eval`
- Garak shortcut: `http://localhost:3000/garak`
- PyRIT shortcut: `http://localhost:3000/pyrit`
- Backend API: `http://localhost:8000`
- FastAPI docs: `http://localhost:8000/docs`
- Promptfoo viewer: `http://localhost:15500`
- Ollama: `http://localhost:11434`

## Manual Startup

### Backend

```powershell
cd backend
.\venv\Scripts\python.exe main.py
```

### Frontend

```powershell
cd frontend
npm run dev
```

### Promptfoo Viewer

Use the startup script unless you specifically need to run components manually.

## Evaluator Workflows

### Promptfoo Workflow

- choose vectors in the eval dashboard
- preflight the run
- launch against the defended local target
- review matrix, flagged findings, and final report

### Garak Workflow

- choose concrete probes or family-expanded probe sets
- cap prompts per probe for quick scans
- watch probe-level progress in the eval dashboard
- review provisional and official Garak reports

### PyRIT Workflow

- choose curated scenarios in the eval dashboard
- review raw objective plus transformed preview samples before launch
- watch live plan, objective, transformation, score, and completion events
- inspect retained transcripts and official reports after completion

## Development

### Frontend build

```powershell
cd frontend
npm run build
```

### Backend compile check

```powershell
backend\venv\Scripts\python.exe -m compileall backend pyrit-eval
```

### Focused backend tests

```powershell
backend\venv\Scripts\python.exe -m pytest backend\tests\test_promptfoo_eval_integration.py -q -p no:cacheprovider
```

## Repository Layout

```text
aegis-forge/
|-- backend/            FastAPI app, models, policies, monitors, tests
|-- frontend/           Next.js dashboard
|-- promptfoo-eval/     Promptfoo assets and generated eval outputs
|-- garak-eval/         Garak image assets and reports
|-- pyrit-eval/         PyRIT image assets and runtime wrapper
|-- docs/               Design and implementation specs
|-- startup.ps1         One-command local startup
|-- STARTUP.md          Startup reference
```

## Important Docs

- Startup guide: [STARTUP.md](STARTUP.md)
- PyRIT expansion spec: [docs/pyrit_full_integration_spec.md](docs/pyrit_full_integration_spec.md)
- Guardrail graph map: [docs/guardrails_graph_map.md](docs/guardrails_graph_map.md)

## Safety and Scope

Aegis Forge is for defensive research, validation, and hardening.

Use it only against systems and agents you are authorized to test.

The project is intentionally built around:

- local execution
- sandboxed action paths
- explicit evaluator launch control
- visible retained evidence

It is a security workbench, not a production deployment platform.
