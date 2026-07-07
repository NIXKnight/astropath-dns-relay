# syntax=docker/dockerfile:1
# SPDX-License-Identifier: GPL-3.0-or-later
#
# AstropathDNSRelay — multi-stage production image (SPEC §15.2, T-M0-07).
#
#   1. frontend  (node)   — build the Vite/React SPA to dist/
#   2. builder   (uv)     — `uv sync --frozen` → /app/.venv    (deps only)
#   3. runtime   (python) — minimal, NON-ROOT, HEALTHCHECK → /healthz
#
# Entrypoint: `python -m astropath.main`.

# ---------------------------------------------------------------------------
# Stage 1 — frontend: build the Vite/React/TS SPA to /frontend/dist
# ---------------------------------------------------------------------------
# node:24-slim matches the toolchain the committed package-lock.json resolved
# against (glibc), so `npm ci` installs the recorded native build binaries
# (rolldown/oxc) deterministically. This stage is a throwaway builder — only
# /frontend/dist (static HTML/JS/CSS) is copied into the runtime image, so the
# builder base never reaches the shipped image.
FROM node:24-slim AS frontend
WORKDIR /frontend
# Lockfile-first: the deps layer is cached until the pinned deps actually change,
# so source-only edits skip `npm ci` on rebuild (SPEC §15.2).
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci
# SPA sources + production build (`tsc -b && vite build`) → dist/ (index.html + assets/).
COPY frontend/ ./
RUN npm run build

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
    PYTHONDONTWRITEBYTECODE=1 \
    ASTROPATH_SPA_DIR="/app/static"

# Dependency virtualenv (built in the builder stage), the application source, and
# the built SPA. The app serves the SPA from /app/static behind an explicit
# catch-all (SPEC §9.3, T-M4-04); ASTROPATH_SPA_DIR points the app at it so a
# deep link resolves to index.html while /api and ops routes stay authoritative.
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
