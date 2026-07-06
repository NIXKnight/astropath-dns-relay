"""KEK / direct key encryption for credentials at rest (SPEC §7).

Fernet + ``MultiFernet`` for KEK rotation: encrypt with the primary key, decrypt
across the keylist, ``rotate()`` for lazy re-encryption, and at-rest decrypt with
no ``ttl``. This is *direct* key encryption, deliberately not called "envelope"
encryption (SPEC §7.2). The optional AES-256-GCM path is per SPEC §7.2.

Implemented in T-M1-20.
"""
