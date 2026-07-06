"""FastAPI application factory and router wiring (SPEC §2.2, §9.3).

The app runs embedded under uvicorn with ``lifespan="off"`` — ``main()`` is the
single owner of startup/teardown. Routers and static-asset mounts are registered
before the explicit SPA catch-all.

Implemented in T-M3-01.
"""
