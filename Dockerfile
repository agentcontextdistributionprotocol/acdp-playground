# Builds the playground image. The `acdp` SDK now resolves from PyPI as a
# prebuilt wheel, so the build context is just this repo — no sibling
# acdp-rs checkout and no Rust/maturin toolchain (see docker-compose.yml).
FROM python:3.12-slim AS base

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN curl -LsSf https://astral.sh/uv/install.sh | sh \
    && mv /root/.local/bin/uv /usr/local/bin/uv

WORKDIR /workspace/acdp-playground

# Sync dependencies first (cached layer) — acdp + its transitive deps come
# from PyPI, no build toolchain required.
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --extra llm --no-install-project

# Then the application source.
COPY . .
RUN uv sync --frozen --extra llm

EXPOSE 8000
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

# Bind PORT/HOST from the environment so the same image runs locally (defaults
# 0.0.0.0:8000) and on a PaaS like Railway, which injects a dynamic $PORT and
# requires binding IPv6 `::` for private-network service-to-service traffic.
# `sh -c` expands the vars; `--no-sync` skips a redundant re-resolve on every
# cold start (the env is already built above); `exec` hands signals to the
# server for graceful shutdown. Set HOST=:: on Railway.
CMD ["sh", "-c", "exec uv run --no-sync uvicorn playground.main:app --host \"${HOST:-0.0.0.0}\" --port \"${PORT:-8000}\""]
