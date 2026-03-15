## Aegis Forge Startup Guide

This is the reference guide for bootstrapping and starting Aegis Forge.

## Support Summary

- Windows: full local stack support through `startup.ps1`
- Linux/macOS: supported for backend bootstrap, backend tests, frontend build/lint, and CI-style validation

## Windows Startup

From the repo root:

```powershell
.\startup.ps1
```

If `backend\venv` does not exist yet:

```powershell
py -3.13 -m venv backend\venv
backend\venv\Scripts\python.exe -m pip install --upgrade pip
backend\venv\Scripts\python.exe -m pip install -r backend\requirements-dev.txt
cd frontend
cmd /c npm ci
cd ..
.\startup.ps1
```

## Linux/macOS Bootstrap

This path is intended for local validation and CI-style workflows.

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

## Manual Service Startup

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

Windows automated startup is still the easiest path. On Linux/macOS, run the viewer manually after frontend dependencies are installed.

## Service URLs

- App: `http://localhost:3000`
- Backend API: `http://localhost:8000`
- Promptfoo UI: `http://localhost:15500`
- Ollama: `http://localhost:11434`
- API docs: `http://localhost:8000/docs`

## Validation Commands

From the repo root:

```bash
make test-backend
make frontend-install
make build-frontend
make lint-frontend
```

Direct backend test command:

```bash
cd backend
venv/bin/python -m pytest -q
```

Direct frontend build command:

```bash
cd frontend
npm run build
```
