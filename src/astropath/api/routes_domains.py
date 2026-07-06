"""Domains CRUD routes (SPEC §9.1).

``POST``/``GET``/``DELETE`` ``/api/v1/domains`` maps a zone to a backend plus a
provider record handle and the HE per-record ``secret_encrypted``; the secret is
redacted on read.

Implemented in T-M3-10.
"""
