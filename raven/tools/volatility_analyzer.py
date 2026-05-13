"""Backward-compat shim — re-exports VolatilityAdapter under the legacy name."""
from raven.tools.volatility import VolatilityAdapter as VolatilityAnalyzer

__all__ = ["VolatilityAnalyzer"]
