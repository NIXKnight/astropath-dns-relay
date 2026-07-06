"""Backends CRUD routes (SPEC §9.1).

``POST``/``GET``/``PATCH``/``DELETE`` ``/api/v1/backends``; ``type`` validated
against ``REGISTRY``, config validated by the provider ``config_schema()`` and
re-encrypted on write, secrets redacted on read.

Implemented in T-M3-09.
"""
