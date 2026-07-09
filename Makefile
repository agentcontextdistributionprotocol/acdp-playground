.PHONY: dev dev-local build-sdk run test test-live cov smoke smoke-live docker up down up-full down-full fmt lint clean

PYTHON ?= python
UV ?= uv
ACDP_RS ?= ../acdp-rs
COMPOSE_FULL = docker compose -f docker-compose.yml -f docker-compose.full.yml

# Default install: `acdp` resolves as a prebuilt wheel from PyPI. No sibling
# acdp-rs checkout and no Rust toolchain required.
dev:
	$(UV) sync --extra llm --extra dev

# Local SDK development: install deps, then overlay a `maturin develop` build
# of a sibling acdp-rs checkout (override the location with ACDP_RS=...). Use
# this only when hacking on the SDK itself. `build-sdk` re-overlays after
# pulling acdp-rs changes; the next plain `uv sync` restores the PyPI wheel.
dev-local: dev build-sdk

# The acdp SDK is a compiled (maturin/pyo3) extension. `maturin develop`
# builds the sibling checkout straight into this venv, overriding the PyPI
# wheel until the next `uv sync`. Requires a Rust toolchain + the acdp-rs repo.
build-sdk:
	$(UV) run --with maturin maturin develop --release \
		--manifest-path $(ACDP_RS)/bindings/acdp-py/Cargo.toml

run:
	$(UV) run uvicorn playground.main:app --reload --port 8000

test:
	$(UV) run pytest -q

# Offline suite with the same coverage gate CI enforces.
cov:
	$(UV) run pytest -q --cov --cov-report=term-missing --cov-fail-under=80

# Live conformance against a running full stack. Bring it up first
# (`make up-full` in another shell, or `$(COMPOSE_FULL) up -d --wait`).
test-live:
	ACDP_LIVE_STACK=1 $(UV) run pytest -m live -q

smoke:
	$(UV) run python scripts/smoke_test.py

smoke-live:
	$(UV) run python scripts/smoke_test.py --live

docker:
	docker compose build

up:
	docker compose up

down:
	docker compose down -v

# Full stack incl. the control plane (see docker-compose.full.yml).
up-full:
	$(COMPOSE_FULL) up

down-full:
	$(COMPOSE_FULL) down -v

fmt:
	$(UV) run ruff format .

lint:
	$(UV) run ruff check .

clean:
	rm -rf .venv .pytest_cache __pycache__ */__pycache__ */*/__pycache__
