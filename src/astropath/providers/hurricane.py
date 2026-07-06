"""Hurricane Electric dynamic-DNS provider (SPEC §5.7).

Fixed endpoint ``POST https://dyn.dns.he.net/nic/update``; ``good``/``nochg`` are
success, ``badauth``/``nohost`` are hard errors. HE holds one value per dynamic
record (``supports_multivalue=False``) and cannot delete
(``supports_delete=False``; ``cleanup()`` overwrites a placeholder). The
per-record dynamic key is domain-scoped.

Implemented in T-M1-18.
"""
