"""Shared pytest fixtures and configuration for the AstropathDNSRelay test suite.

Kept intentionally minimal at M0; fixtures (settings factories, ephemeral
Postgres via testcontainers, dnspython clients) are added by the tasks that need
them.
"""
