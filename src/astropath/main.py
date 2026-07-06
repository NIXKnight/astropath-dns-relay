"""Process entrypoint and per-plane supervision (SPEC §2).

``main()`` owns the single asyncio process. It starts the data plane
(RFC2136/TSIG listener) and the management plane (uvicorn/FastAPI) under
*independent* per-plane supervisors — deliberately not ``asyncio.gather`` and
not a top-level ``TaskGroup`` (SPEC §2.1) — owns all shared-resource
startup/teardown, and coordinates graceful shutdown via a shared event.

Implemented in T-M1-23 / T-M1-24.
"""
