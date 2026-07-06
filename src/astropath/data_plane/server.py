"""RFC2136 UDP + TCP listener (SPEC §3.11).

The ``asyncio.DatagramProtocol`` UDP callback is synchronous and must not await:
it hands each packet off via ``asyncio.create_task``. TCP is mandatory (signed
UPDATEs can exceed 512 bytes) with 2-byte big-endian length framing.

Implemented in T-M1-11 / T-M1-12 / T-M1-13.
"""
