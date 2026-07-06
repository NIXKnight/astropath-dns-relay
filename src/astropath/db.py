"""Async database engine, session factory, and dependency (SPEC §12.2).

``create_async_engine(postgresql+asyncpg://…)`` plus an ``async_sessionmaker``
with ``expire_on_commit=False`` and an async ``get_session()`` generator. The
sync ``with Session(engine)`` tutorial pattern is intentionally not used.

Implemented in T-M2-02.
"""
