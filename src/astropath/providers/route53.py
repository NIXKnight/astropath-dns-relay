"""AWS Route 53 provider via aiobotocore (SPEC §5.8).

Async-native ``aiobotocore`` client used as an async context manager.
``present()`` issues ``Action='UPSERT'``; ``cleanup()`` reads the exact current
record then issues ``Action='DELETE'`` with the identical ``ResourceRecordSet``.
``supports_multivalue=True``.

Implemented in T-M5-01.
"""
