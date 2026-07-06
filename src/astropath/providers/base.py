"""Provider ABC and the module-level registry (SPEC §5.1, §5.2).

The ``Provider`` abstract base class defines ``config_schema()``,
``from_config()``, async ``present``/``cleanup``/``validate``, and the
``supports_multivalue`` / ``supports_delete`` class flags. ``REGISTRY`` maps a
provider ``type`` string to its ``Provider`` subclass.

Implemented in T-M1-17.
"""
