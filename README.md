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

These directories hold evaluator-specific wrappers and local runtime assets. Generated evaluator reports and configs are ignored from git.

## Support Tiers

- Windows: full local stack support, including `startup.ps1`, Docker Desktop, Ollama, backend runtime, frontend runtime, and evaluator flows.
- Linux/macOS: supported for backend dependency bootstrap, backend tests, frontend install/build/lint, and GitHub Actions style validation. Full interactive local stack startup is currently best-effort rather than first-class.

## Key Capabilities

- local defended target execution through the Aegis backend
- Promptfoo, Garak, and PyRIT launch paths under a unified `/eval` model
- full retained logs for completed and stopped eval runs
- live attack preview and provisional reporting during execution
- vulnerability matrix plus consolidated flagged findings
- PyRIT transformed prompt preview and richer event stream
- Garak concrete probe selection and prompt caps for quick scans
- agent hardening toggle for fix-and-retest workflows
- Docker-isolated execution for agent actions

## Prerequisites

- Python 3.13 for the validated backend path
- Node.js `22.13.1` and npm `10.9.2`
- Docker Desktop or Docker Engine
- Ollama with `llama3.1:8b` available locally for full runtime use

Runtime policy:

- `.nvmrc` pins the supported Node runtime for local shells and CI
- `frontend/package.json` declares matching `engines` and `packageManager`
- `backend/requirements.txt` is UTF-8 encoded runtime-only dependencies
- `backend/requirements-dev.txt` layers test tooling on top of runtime dependencies

## Quick Start

### Windows

From the repo root:

```powershell
.\startup.ps1
```

If the backend virtual environment does not exist yet:

```powershell
py -3.13 -m venv backend\venv
backend\venv\Scripts\python.exe -m pip install --upgrade pip
backend\venv\Scripts\python.exe -m pip install -r backend\requirements-dev.txt
cd frontend
cmd /c npm ci
cd ..
.\startup.ps1
```

### Linux/macOS

The validated Linux/macOS path is for local validation and CI-style workflows:

```bash
python3.13 -m venv backend/venv
backend/venv/bin/python -m pip install --upgrade pip
backend/venv/bin/python -m pip install -r backend/requirements-dev.txt
cd frontend
npm ci
cd ..
make test-backend
make build-frontend
make lint-frontend
```

For full runtime use on Linux/macOS, start services manually instead of relying on `startup.ps1`.

## Service URLs

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

Windows:

```powershell
cd backend
.\venv\Scripts\python.exe main.py
```

Linux/macOS:

```bash
cd backend
venv/bin/python main.py
```

### Frontend

```bash
cd frontend
npm run dev
```

### Promptfoo Viewer

Use the startup script on Windows unless you specifically need to run components manually. On Linux/macOS, run the viewer manually after frontend dependencies are installed.

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

### Backend bootstrap

Cross-platform:

```bash
python -m venv backend/venv
backend/venv/bin/python -m pip install --upgrade pip
backend/venv/bin/python -m pip install -r backend/requirements-dev.txt
```

Windows equivalent:

```powershell
py -3.13 -m venv backend\venv
backend\venv\Scripts\python.exe -m pip install --upgrade pip
backend\venv\Scripts\python.exe -m pip install -r backend\requirements-dev.txt
```

### Standard developer commands

From the repo root:

```bash
make test-backend
make frontend-install
make build-frontend
make lint-frontend
make ci
```

Notes:

- `make test-backend` creates `backend/venv` if needed and runs `pytest -q` from `backend/`
- backend pytest uses `backend/pytest.ini` to keep temp files repo-local and avoid cache permission issues in containers
- Docker integration tests skip automatically when the Docker daemon is unavailable

### Direct commands

Focused backend tests:

```powershell
cd backend
.\venv\Scripts\python.exe -m pytest tests\test_promptfoo_eval_integration.py -q
```

Frontend build:

```powershell
cd frontend
cmd /c npm run build
```

Frontend lint:

```powershell
cd frontend
cmd /c npm run lint
```

## Continuous Integration

GitHub Actions runs:

- backend bootstrap plus `make test-backend` on Ubuntu
- frontend install, build, and lint on Ubuntu

Workflow path: `.github/workflows/ci.yml`

## Repository Layout

```text
aegis-forge/
|-- backend/            FastAPI app, models, policies, monitors, tests
|-- frontend/           Next.js dashboard
|-- promptfoo-eval/     Promptfoo assets and generated eval outputs
|-- garak-eval/         Garak runtime wrapper and local reports
|-- pyrit-eval/         PyRIT runtime wrapper and local reports
|-- docs/               Design and implementation specs
|-- Makefile            Linux/macOS and CI developer workflows
|-- startup.ps1         Windows-first local startup
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
