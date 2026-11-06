.PHONY: sidecar dev up demo test lint fmt down clean

UV ?= uv
COMPOSE = docker compose -p acdp-a2a

sidecar:  ## build the Rust bridge to acdp-rs's acdp-a2a
	cd sidecar && cargo build --release --locked

dev: sidecar  ## install the demo project (a2a-sdk, acdp, acdp-verifier)
	$(UV) sync

up:  ## local registry-a + throwaway Postgres on :8100 (skip if `make up` runs at the repo root)
	$(COMPOSE) up -d --wait

demo:  ## the three runs: pass, tamper, retraction
	$(UV) run python -m acdp_a2a_demo.demo

test:  ## offline unit checks
	$(UV) run pytest -q

lint:
	$(UV) run ruff check .
	$(UV) run ruff format --check .
	cd sidecar && cargo fmt --check && cargo clippy --release -- -D warnings

fmt:
	$(UV) run ruff format .
	cd sidecar && cargo fmt

down:
	$(COMPOSE) down -v

clean: down
	rm -rf .venv sidecar/target
