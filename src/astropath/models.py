"""SQLModel persistence models (SPEC §6).

``table=True`` models: ``Backend``, ``Domain`` (holds the HE per-record key in
``secret_encrypted``), ``TsigKey``, ``ApiToken``, the append-only
``ChallengeEvent`` audit table, and ``AdminCredential``. ``SQLModel.metadata``
is the Alembic ``target_metadata``.

Implemented in T-M2-01.
"""
