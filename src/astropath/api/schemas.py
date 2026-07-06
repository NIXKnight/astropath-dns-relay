"""Request/response schemas for the management API (SPEC §9.2).

Pydantic models for the ``/api/v1`` surface. Secrets are write-only: accepted on
create/update, never returned on read (redacted to ``***`` / ``<REDACTED>``).

Implemented in T-M3-09 / T-M3-10.
"""
