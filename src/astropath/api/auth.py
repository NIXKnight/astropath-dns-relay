"""Management-plane authentication (SPEC §8).

``require_admin`` accepts either a signed session cookie or an ``X-API-Key``
header (both extractors use ``auto_error=False``) and raises
``HTTPException(401)`` itself when neither is valid. argon2 verification is
offloaded via ``asyncio.to_thread``.

Implemented in T-M3-02 / T-M3-04.
"""
