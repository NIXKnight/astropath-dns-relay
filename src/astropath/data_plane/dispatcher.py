"""Challenge dispatcher: zone → backend → provider (SPEC §3.13, §4, §5).

Resolves the zone from the UPDATE ZONE section, enforces the
``_acme-challenge`` write-surface allowlist, serializes pushes per FQDN, and
calls ``provider.present`` / ``provider.cleanup``. Provider failure maps to
SERVFAIL; success maps to NOERROR.

Implemented in T-M1-25.
"""
