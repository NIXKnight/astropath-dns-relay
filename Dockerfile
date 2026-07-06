# syntax=docker/dockerfile:1
# SPDX-License-Identifier: GPL-3.0-or-later
#
# AstropathDNSRelay — multi-stage production image (SPEC §15.2, T-M0-07).
#
#   1. frontend  (node)   — build the Vite/React SPA to dist/  (guarded until M4)
#   2. builder   (uv)     — `uv sync --frozen` → /app/.venv    (deps only)
#   3. runtime   (python) — minimal, NON-ROOT, HEALTHCHECK → /healthz
#
# Entrypoint: `python -m astropath.main`. main.py is a stub until M1; no
# application logic is baked in here.

# ---------------------------------------------------------------------------
# Stage 1 — frontend: build the SPA bundle to /frontend/dist
# ---------------------------------------------------------------------------
# TODO(T-M4-01): the Vite/React/TS SPA and its package-lock.json land at M4.
# Until frontend/package.json exists this stage emits an EMPTY dist/ so
# `docker build` succeeds today. When the SPA is scaffolded, restructure to
# `COPY frontend/package*.json ./` + `npm ci` (cached deps layer) BEFORE
# `COPY frontend/ .` + `npm run build`, for optimal layer caching.
FROM node:22-alpine AS frontend
WORKDIR /frontend
COPY frontend/ ./
RUN if [ -f package.json ]; then \
        npm ci && npm run build; \
    else \
        mkdir -p dist && \
        printf '<!doctype html><title>AstropathDNSRelay</title><!-- SPA builds at M4 (T-M4-01) -->\n' > dist/index.html; \
    fi

# ---------------------------------------------------------------------------
# Stage 2 — builder: resolve the frozen dependency set into /app/.venv
# ---------------------------------------------------------------------------
# uv is pinned by digest-free version tag; the base is shared with the runtime
# stage so the copied venv's interpreter symlinks resolve identically.
FROM python:3.12-slim-bookworm AS builder
COPY --from=ghcr.io/astral-sh/uv:0.8.17 /uv /uvx /bin/
ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=0 \
    UV_PROJECT_ENVIRONMENT=/app/.venv
WORKDIR /app
# Only the lockfile + manifest are needed for the deps layer; `--no-install-project`
# skips building astropath itself (its source is copied into the runtime stage and
# placed on PYTHONPATH), keeping this layer cached until the pins actually change.
COPY pyproject.toml uv.lock ./
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-install-project --no-dev

# ---------------------------------------------------------------------------
# Stage 3 — runtime: minimal non-root image
# ---------------------------------------------------------------------------
FROM python:3.12-slim-bookworm AS runtime

# Dedicated, fixed-uid non-root account (SPEC §15.2). No login shell, no home write.
RUN groupadd --system --gid 10001 astropath && \
    useradd --system --uid 10001 --gid astropath --home-dir /app --no-create-home astropath

WORKDIR /app

ENV PATH="/app/.venv/bin:${PATH}" \
    PYTHONPATH="/app/src" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# Dependency virtualenv (built in the builder stage), the application source, and
# the built SPA. SPEC §9.3 serves the SPA from ./static (StaticFiles + FileResponse);
# TODO(T-M4-05): that mount/serving wiring is finalized at M4.
COPY --from=builder --chown=astropath:astropath /app/.venv ./.venv
COPY --chown=astropath:astropath src/ ./src/
COPY --from=frontend --chown=astropath:astropath /frontend/dist ./static

USER astropath

# RFC2136 DNS listener (UDP + TCP) and the FastAPI management/admin HTTP plane.
EXPOSE 53/udp
EXPOSE 53/tcp
EXPOSE 8080/tcp

# /healthz lands at M1/M3; the directive presence is the M0 acceptance criterion.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import sys, urllib.request as u; sys.exit(0 if u.urlopen('http://127.0.0.1:8080/healthz', timeout=3).status == 200 else 1)" || exit 1

ENTRYPOINT ["python", "-m", "astropath.main"]
