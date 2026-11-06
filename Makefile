PY ?= python
COMPOSE_LAB = docker compose --env-file .env.lab -f docker-compose.lab.yml
ATTACK_URL = https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json

.PHONY: help install test lint server agent env mitre-update lab-env lab-up lab-purple lab-purple-live lab-down verify-ledger

help:
	@echo "install          Install everything into the current environment"
	@echo "test             Run the test suite"
	@echo "lint             Run ruff"
	@echo "env              Generate server secrets in .env (refuses to overwrite)"
	@echo "server           Run the server"
	@echo "agent            Run the agent"
	@echo "verify-ledger    Verify the action ledger's hash chain"
	@echo "mitre-update     Download the latest ATT&CK dataset"
	@echo "lab-env          Generate lab secrets in .env.lab"
	@echo "lab-up           Start the isolated lab"
	@echo "lab-purple       Run synthetic purple scenarios in the lab"
	@echo "lab-purple-live  Run live purple scenarios on the lab victim"
	@echo "lab-down         Stop the lab and delete its data"

install:
	$(PY) -m pip install -e ".[server,agent-full,dev]"

test:
	$(PY) -m pytest

lint:
	$(PY) -m ruff check .

env:
	@test ! -e .env || (echo ".env already exists, not overwriting" && exit 1)
	$(PY) -m carylle.cli init-env > .env
	@echo "Wrote .env"

server:
	$(PY) -m carylle.main

agent:
	$(PY) -m carylle_agent.main

verify-ledger:
	$(PY) -m carylle.cli verify-ledger

mitre-update:
	curl -fsSL -o data/mitre/enterprise-attack.json.tmp $(ATTACK_URL)
	$(PY) -c "import json; json.load(open('data/mitre/enterprise-attack.json.tmp', encoding='utf-8'))"
	mv data/mitre/enterprise-attack.json.tmp data/mitre/enterprise-attack.json
	$(PY) -m pytest tests/test_mitre.py

lab-env:
	@test ! -e .env.lab || (echo ".env.lab already exists, not overwriting" && exit 1)
	$(PY) -m carylle.cli init-env --lab > .env.lab
	@echo "Wrote .env.lab"

lab-up:
	$(COMPOSE_LAB) up -d --build

lab-purple:
	$(COMPOSE_LAB) run --rm purple

lab-purple-live:
	$(COMPOSE_LAB) exec victim python -m purple.runner --mode live --server http://server:8443 --report /tmp/purple-live

lab-down:
	$(COMPOSE_LAB) down -v
