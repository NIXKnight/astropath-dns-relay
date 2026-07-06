"""Observability: liveness, per-plane readiness, and metrics (SPEC §11).

``/healthz`` (process up), ``/readyz`` (per-plane readiness), and the
prometheus-client Counters/Histograms/Gauges (challenge outcomes, TSIG failure
reasons, BADTIME, provider latency, plane restarts).

Implemented in T-M1-27 / T-M6-01 / T-M6-04.
"""
