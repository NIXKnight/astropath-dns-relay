"""AstropathDNSRelay — self-hosted ACME DNS-01 solver gateway.

Import root for the ``astropath`` package (SPEC §1.4). This initializer performs
no heavy imports so that ``import astropath`` stays cheap and side-effect free;
callers import submodules (``astropath.settings``, ``astropath.data_plane`` …)
explicitly.
"""

__version__ = "0.1.0"

__all__ = ["__version__"]
