PYTHON ?= python3
NPM ?= npm

BACKEND_VENV := backend/venv
BACKEND_PYTHON := $(BACKEND_VENV)/bin/python
BACKEND_PIP := $(BACKEND_VENV)/bin/pip
BACKEND_REQUIREMENTS := backend/requirements.txt backend/requirements-dev.txt

.PHONY: backend-venv frontend-install test-backend build-frontend lint-frontend ci

$(BACKEND_PYTHON):
	$(PYTHON) -m venv $(BACKEND_VENV)

$(BACKEND_VENV)/.deps-installed: $(BACKEND_REQUIREMENTS) | $(BACKEND_PYTHON)
	$(BACKEND_PYTHON) -m pip install --upgrade pip
	$(BACKEND_PIP) install -r backend/requirements-dev.txt
	touch $(BACKEND_VENV)/.deps-installed

backend-venv: $(BACKEND_VENV)/.deps-installed

frontend-install:
	cd frontend && $(NPM) ci

test-backend: $(BACKEND_VENV)/.deps-installed
	cd backend && venv/bin/python -m pytest -q

build-frontend:
	cd frontend && $(NPM) run build

lint-frontend:
	cd frontend && $(NPM) run lint

ci: test-backend build-frontend lint-frontend
