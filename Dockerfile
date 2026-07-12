# syntax=docker/dockerfile:1
# SPDX-License-Identifier: GPL-3.0-or-later
#
# astropath-dns-relay — multi-stage production image (SPEC §15.2, T-M0-07, T-M6-07).
#
#   1. frontend  (node)   — build the Vite/React SPA to dist/
#   2. builder   (uv)     — `uv sync --frozen` → /app/.venv    (deps only)
#   3. runtime   (python) — minimal, NON-ROOT, HEALTHCHECK → /healthz
#
# Entrypoint: `python -m astropath.main`.
#
# Hardening (SPEC §15.2, T-M6-07):
#   * Every base is pinned by immutable digest (the human tag is kept in a
#     comment); take base security updates by bumping the digest. Digests are the
#     multi-arch *index* digest so the amd64 + arm64 (T-M6-06) legs both resolve.
#   * `uv sync --frozen` / `npm ci` install only the committed lockfiles — a drift
#     fails the build rather than silently resolving new versions.
#   * OCI image labels (incl. licenses=GPL-3.0-or-later) are set on the runtime.
#   * No init/tini is bundled — the app owns its signals and reaps no children
#     (see the ENTRYPOINT note). The image runs read-only-fs clean.

# ---------------------------------------------------------------------------
# Stage 1 — frontend: build the Vite/React/TS SPA to /frontend/dist
# ---------------------------------------------------------------------------
# node:24-slim matches the toolchain the committed package-lock.json resolved
# against (glibc), so `npm ci` installs the recorded native build binaries
# (rolldown/oxc) deterministically. This stage is a throwaway builder — only
# /frontend/dist (static HTML/JS/CSS) is copied into the runtime image, so the
# builder base never reaches the shipped image.
# Pinned by multi-arch index digest; tag node:24-slim kept for readability.
# `--platform=$BUILDPLATFORM` pins this stage to the builder's native arch: the
# SPA output (static HTML/JS/CSS) is architecture-independent, so on a multi-arch
# build (T-M6-06: amd64 + arm64) it is built ONCE natively instead of re-running
# `npm ci`/`npm run build` under slow arm64 emulation. Only the arch-specific
# Python `builder` stage below fans out per target platform.
FROM --platform=$BUILDPLATFORM node:24-slim@sha256:b31e7a42fdf8b8aa5f5ed477c72d694301273f1069c5a2f71d53c6482e99a2fc AS frontend
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
# The base is shared with the runtime stage (same digest) so the copied venv's
# interpreter symlinks resolve identically. Pinned by multi-arch index digest;
# tag python:3.12-slim-bookworm kept for readability.
FROM python:3.12-slim-bookworm@sha256:8a7e7cc04fd3e2bd787f7f24e22d5d119aa590d429b50c95dfe12b3abe52f48b AS builder
# uv is copied from its published image, pinned by digest (tag 0.8.17 in comment);
# the index digest carries amd64 + arm64 so the builder stage resolves on both.
COPY --from=ghcr.io/astral-sh/uv:0.8.17@sha256:e4644cb5bd56fdc2c5ea3ee0525d9d21eed1603bccd6a21f887a938be7e85be1 /uv /uvx /bin/
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
# Same pinned digest as the builder so the copied venv's interpreter matches.
FROM python:3.12-slim-bookworm@sha256:8a7e7cc04fd3e2bd787f7f24e22d5d119aa590d429b50c95dfe12b3abe52f48b AS runtime

# --- OCI image metadata (SPEC §15.2, T-M6-07) ------------------------------- #
# Static descriptive labels + build-arg-driven provenance (version/revision/
# created). CI passes --build-arg for the dynamic three; a bare `docker build`
# still succeeds with the defaults below. `licenses` is the SPDX identifier for
# the project license (GPL-3.0-or-later, SPEC §1.5).
ARG VERSION=0.1.1
ARG VCS_REF=unknown
ARG BUILD_DATE=unknown
LABEL org.opencontainers.image.title="astropath-dns-relay" \
      org.opencontainers.image.description="Self-hosted ACME DNS-01 solver gateway (RFC2136/TSIG front end for cert-manager)." \
      org.opencontainers.image.licenses="GPL-3.0-or-later" \
      org.opencontainers.image.source="https://github.com/NIXKnight/Astropath-DNS-Relay" \
      org.opencontainers.image.url="https://github.com/NIXKnight/Astropath-DNS-Relay" \
      org.opencontainers.image.documentation="https://github.com/NIXKnight/Astropath-DNS-Relay" \
      org.opencontainers.image.authors="Saad Ali <engr.saadali786@gmail.com>" \
      org.opencontainers.image.vendor="Saad Ali" \
      org.opencontainers.image.base.name="docker.io/library/python:3.12-slim-bookworm" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.created="${BUILD_DATE}"

# Dedicated, fixed-uid non-root account (SPEC §15.2). No login shell, no home write.
RUN groupadd --system --gid 10001 astropath && \
    useradd --system --uid 10001 --gid astropath --home-dir /app --no-create-home astropath

WORKDIR /app

ENV PATH="/app/.venv/bin:${PATH}" \
    PYTHONPATH="/app/src" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    ASTROPATH_SPA_DIR="/app/static"

# Dependency virtualenv (built in the builder stage), the application source, the
# Alembic config + migrations, and the built SPA. The app serves the SPA from
# /app/static behind an explicit catch-all (SPEC §9.3, T-M4-04); ASTROPATH_SPA_DIR
# points the app at it so a deep link resolves to index.html while /api and ops
# routes stay authoritative.
#
# alembic.ini + alembic/ MUST ship in the image: DB-mode startup validation
# (astropath.startup.validate_db_startup -> _alembic_head) resolves the migration
# head from them before binding readiness, and operators run `alembic upgrade head`
# from /app (WORKDIR) — script_location is `%(here)s/alembic`, anchored to the ini.
# Without them the boot aborts (SPEC §11.3, T-M6-10). Copied before the SPA so a
# frontend-only change does not bust this layer.
COPY --from=builder --chown=astropath:astropath /app/.venv ./.venv
COPY --chown=astropath:astropath src/ ./src/
COPY --chown=astropath:astropath alembic.ini ./alembic.ini
COPY --chown=astropath:astropath alembic/ ./alembic/
COPY --from=frontend --chown=astropath:astropath /frontend/dist ./static

# Read-only root filesystem compatible: nothing is written to the image FS at
# runtime. PYTHONDONTWRITEBYTECODE (+ UV_COMPILE_BYTECODE in the builder) means no
# .pyc writes, logs go to stdout, and config/secrets arrive as read-only mounts.
# Deploy with `--read-only` (add `--tmpfs /tmp` only if a future dependency needs
# scratch space). The account owns /app but never writes there at runtime.
USER astropath

# RFC2136 DNS listener (UDP + TCP) and the FastAPI management/admin HTTP plane.
EXPOSE 53/udp
EXPOSE 53/tcp
EXPOSE 8080/tcp

# /healthz lands at M1/M3; the directive presence is the M0 acceptance criterion.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import sys, urllib.request as u; sys.exit(0 if u.urlopen('http://127.0.0.1:8080/healthz', timeout=3).status == 200 else 1)" || exit 1

# No init/tini bundled (SPEC §15.2 does not mandate one): astropath.main installs
# its own SIGTERM/SIGINT handlers (they set the shared shutdown event so both
# planes drain) and spawns no persistent child processes to reap, so it is safe as
# PID 1. Operators wanting universal zombie reaping can run `docker run --init` or
# rely on the Kubernetes pod sandbox — no image change required.
ENTRYPOINT ["python", "-m", "astropath.main"]
