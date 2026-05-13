"""Backward-compat shim — re-exports ReconNgAdapter under the legacy name."""
from raven.tools.recon_ng import ReconNgAdapter as ReconNgClient

__all__ = ["ReconNgClient"]
