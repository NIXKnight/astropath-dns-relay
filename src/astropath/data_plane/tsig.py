"""Algorithm-bound TSIG keyring construction (SPEC §3.1).

The keyring maps ``dns.name`` → explicit ``dns.tsig.Key`` objects (never raw
bytes), so the bound HMAC algorithm is enforced rather than read from the
attacker-influenced inbound wire.

Implemented in T-M1-01.
"""
